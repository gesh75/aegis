"""AEGIS community server — standalone, self-contained, sim-tier.

This is the open-source "demo" entry point: `python -m aegis.serve` (or `docker compose up`)
serves the PreFlight UI and the pipeline in SIMULATOR mode — no LLM, no containerlab, no
external anything. It proves the whole loop (intent/config-import -> verdict -> sealed,
framework-mapped, examiner-ready evidence bundle) on any machine, fully offline.

Live mode (real Qwen3 + containerlab twin) lives in the integrated deployment
(DCN_Network_Tool / the air-gapped product), not in the community core.

    python -m aegis.serve            # then open http://localhost:8088/preflight
    AEGIS_PORT=9000 python -m aegis.serve
"""
from __future__ import annotations
import base64
import hmac as hmaclib
import os
import re
import threading
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request

from aegis.core.orchestrator.pipeline import run_preflight, PreflightError
from aegis.core.backends.simulator import SimulatorBackend
from aegis.evidence.pdf import render_pdf
from aegis.evidence.bundler import verify as bundler_verify
from aegis.evidence.oscal import to_oscal
from aegis.evidence.cab import to_cab
from aegis.core.seal import Ed25519Signer, Ed25519Verifier, seal_response, verify_seal
from aegis.core.promote.promote import promote, PromoteDenied
from aegis.core.promote.connectors import get_connector
from aegis.core.promote.tokens import (
    TokenError, hmac_configured, mint_token, mint_token_for_bundle,
    digests_from_bundle, load_approve_key,
)
from aegis.core.promote import approvers
from aegis.core import runtime
from aegis.evidence.ledger import Ledger, sink_from_env
from aegis.core.intents import IntentSpecError, load_intents, parse_intents
from aegis.core.risk.authority import peer_as_policy
from aegis.core.integrations import IntegrationError
from aegis.core.integrations import netbox, servicenow
from aegis.core.postchange import verify_postchange
from aegis.evidence.secrets import reversible_policy

_UI = os.path.join(os.path.dirname(__file__), "ui", "preflight_screen.html")
_UI_JS = os.path.join(os.path.dirname(__file__), "ui", "preflight.js")

# Content-Security-Policy shared by the response header and the UI <meta> tag.
# default-src 'self' locks origins down. Scripts: 'self' only — the UI script is served
# from /preflight.js and every handler is wired with addEventListener, so injected markup
# cannot execute (A10). Styles keep 'unsafe-inline' (inline style attributes; far lower
# risk than script). connect-src allows the same-origin API plus the localhost fallback
# the UI uses when opened over http on a dev box.
_CSP = ("default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' http://localhost:5757; "
        "img-src 'self' data:; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'")

app = Flask(__name__)
# Reject oversized request bodies before they are parsed (sim tier has no auth).
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB


def _api_key() -> str:
    return (os.environ.get("AEGIS_API_KEY") or "").strip()


def _request_identity() -> str | None:
    """The person behind THIS request, from their own credential in X-Aegis-Approver-Key
    (the same registry that identifies approvers). Never the request body and never the
    shared API key, which identifies nobody. None = nobody authenticated (dgV9dC6J)."""
    return approvers.resolve(request.headers.get("X-Aegis-Approver-Key"))


def _guard_api():
    """T1 #10: when AEGIS_API_KEY is set, mutating routes require X-Aegis-Key.

    A custom header (not a cookie) also breaks trivial cross-site POSTs. Comparison
    is constant-time. Unset key = community/sim stays open, matching existing tests.
    """
    expected = _api_key()
    if not expected:
        return None
    got = request.headers.get("X-Aegis-Key") or ""
    if not hmaclib.compare_digest(got, expected):
        return jsonify({"error": "unauthorized — send X-Aegis-Key"}), 401
    return None


def _load_signer() -> Ed25519Signer:
    """Seal signing key. AEGIS_SEAL_KEY = 64 hex chars (an Ed25519 private seed) pins a
    stable key whose receipts verify across restarts; otherwise an EPHEMERAL demo key is
    used. Production swaps this for a YubiKey-PIV signer (same Signer protocol).

    T1 #10: a pinned seal key without API auth is refused — unauthenticated deployments
    must never mint pinned-key seals.
    """
    raw = (os.environ.get("AEGIS_SEAL_KEY") or "").strip()
    if raw and not _api_key():
        raise SystemExit(
            "[aegis.auth] AEGIS_SEAL_KEY is pinned but AEGIS_API_KEY is unset; "
            "refusing to mint pinned-key seals on an unauthenticated server"
        )
    if raw:
        try:
            return Ed25519Signer.from_private_bytes(bytes.fromhex(raw))
        except Exception as exc:  # noqa: BLE001
            # fail closed: an explicitly-pinned key that cannot load must be fatal —
            # silently degrading to an ephemeral key would mint seals nobody can verify
            raise SystemExit(f"[aegis.seal] AEGIS_SEAL_KEY invalid ({exc}); refusing to start") from exc
    print("[aegis.seal] no AEGIS_SEAL_KEY set - EPHEMERAL demo signing key "
          "(production uses a YubiKey-PIV key; receipts will not persist across restarts)")
    return Ed25519Signer.generate()


runtime.assert_startup_ok()  # production refuses to start with any control unset
_SIGNER = _load_signer()
_VERIFIER: Ed25519Verifier = _SIGNER.verifier()
load_approve_key()  # SystemExit if AEGIS_APPROVE_KEY is set but unusable


def _require_api_key_for_hmac() -> None:
    """Same rule as the pinned seal key: an unauthenticated server must never mint
    HMAC approvals, or anyone who can reach it could approve their own change."""
    if hmac_configured() and not _api_key():
        raise SystemExit(
            "[aegis.auth] AEGIS_APPROVE_KEY is set but AEGIS_API_KEY is unset; "
            "refusing to mint HMAC approvals on an unauthenticated server"
        )


_require_api_key_for_hmac()
approvers.load_registry()  # SystemExit if AEGIS_APPROVER_KEYS is malformed
for _policy in (peer_as_policy, reversible_policy):  # D1 / D2 switches: a typo is fatal
    try:
        _policy()
    except ValueError as _exc:
        raise SystemExit(f"[aegis.policy] {_exc}") from _exc
_LEDGER = Ledger(os.environ.get("AEGIS_LEDGER_PATH") or None, sink=sink_from_env())


def _load_baseline_intents() -> list[dict]:
    """Org-wide intents (e.g. 'guest never reaches the CDE') applied to EVERY run.
    A set-but-invalid file is fatal — a typo must never silently drop a security intent."""
    path = (os.environ.get("AEGIS_INTENTS_PATH") or "").strip()
    if not path:
        return []
    try:
        return load_intents(path)
    except (OSError, IntentSpecError) as exc:
        raise SystemExit(f"[aegis.intents] AEGIS_INTENTS_PATH invalid ({exc}); refusing to start")


_BASELINE_INTENTS = _load_baseline_intents()

# Prometheus counters (text exposition, no client library — air-gap friendly).
_METRICS: dict[tuple[str, tuple], int] = {}
_METRICS_LOCK = threading.Lock()


def _inc(name: str, **labels) -> None:
    key = (name, tuple(sorted(labels.items())))
    with _METRICS_LOCK:
        _METRICS[key] = _METRICS.get(key, 0) + 1


def _client_error(exc: Exception) -> str:
    """Community shows the exception for debuggability; production never leaks internals."""
    if runtime.is_production():
        app.logger.exception("pipeline error")
        return "internal error (see server log)"
    return f"{type(exc).__name__}: {exc}"


def _authenticity(bundle: dict) -> tuple[bool, str]:
    """Seal verdict for an export. (ok, human-readable authenticity line).

    present + valid   -> ok, "seal verified ..."
    present + invalid -> NOT ok (forged/tampered seal never renders)
    absent            -> community: ok but labelled UNSEALED; production: ok only for a
                         ``blocked`` verdict (blocked changes are never sealed by design,
                         and their evidence must stay exportable)
    """
    seal = bundle.get("seal")
    if isinstance(seal, dict):
        v = verify_seal(bundle, seal, _VERIFIER)
        _inc("aegis_seal_verify_total", result="valid" if v.valid else "invalid")
        if not v.valid:
            return False, f"seal verification failed at {v.gate}: {v.reason}"
        return True, (f"seal verified against pinned key {_VERIFIER.alg()}:"
                      f"{_VERIFIER.key_id()} (model identity + bounded authority + bundle "
                      f"sha256)")
    if seal is not None:
        return False, "seal is not an object"
    decision = (bundle.get("verdict") or {}).get("decision")
    if runtime.is_production() and decision != "blocked":
        return False, "unsealed bundle — production exports require a valid seal"
    return True, ("UNSEALED — integrity self-consistency only; origin NOT authenticated"
                  + (" (blocked change: seal withheld by design)" if decision == "blocked"
                     else ""))


@app.after_request
def _security_headers(resp: Response) -> Response:
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = _CSP
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.get("/")
def root():
    return Response('<meta http-equiv="refresh" content="0; url=/preflight">',
                    mimetype="text/html")


@app.get("/favicon.ico")
def favicon() -> Response:
    # the UI ships an inline data-URI icon; answer the browser's automatic
    # /favicon.ico probe so the console stays free of 404 noise
    return Response(status=204)


@app.get("/preflight")
def ui():
    with open(_UI, encoding="utf-8") as fh:
        return Response(fh.read(), mimetype="text/html")


@app.get("/preflight.js")
def ui_js():
    with open(_UI_JS, encoding="utf-8") as fh:
        return Response(fh.read(), mimetype="application/javascript")


@app.get("/api/status")
def status():
    """Public, no secrets: whether this process requires API auth / HMAC approvals."""
    return jsonify({
        "mode": runtime.mode(),
        "api_auth": "required" if _api_key() else "open",
        "approve_hmac": "required" if hmac_configured() else "unset-approvals-denied",
        "approver_identity": ("registry" if approvers.registry_configured()
                              else "unconfigured-approvals-denied"),
        "seal": "pinned" if (os.environ.get("AEGIS_SEAL_KEY") or "").strip() else "ephemeral",
        "ledger": _LEDGER.head()["storage"],
        "intents_engine": ("batfish" if (os.environ.get("AEGIS_BATFISH_HOST") or "").strip()
                           else "unconfigured"),
        "baseline_intents": len(_BASELINE_INTENTS),
        "egress": "none",  # the preflight run; integrations are separate, ledgered calls
        "integrations": {"servicenow": servicenow.configured(),
                         "netbox": netbox.configured()},
    })


@app.get("/healthz")
def healthz():
    """Liveness for container healthchecks. Public, constant body."""
    return jsonify({"ok": True})


@app.get("/metrics")
def metrics():
    """Prometheus text exposition. Counters only — no bundle content, no identities."""
    lines = [
        "# HELP aegis_info Static deployment facts (value is always 1).",
        "# TYPE aegis_info gauge",
        f'aegis_info{{mode="{runtime.mode()}",api_auth="{"required" if _api_key() else "open"}",'
        f'approve_hmac="{"required" if hmac_configured() else "unset"}",'
        f'ledger="{_LEDGER.head()["storage"]}"}} 1',
        "# HELP aegis_ledger_entries Entries in the hash-chained audit ledger.",
        "# TYPE aegis_ledger_entries gauge",
        f"aegis_ledger_entries {_LEDGER.head()['seq']}",
        "# HELP aegis_ledger_anchor_failures_total Ledger entries the SIEM sink failed to send.",
        "# TYPE aegis_ledger_anchor_failures_total counter",
        f"aegis_ledger_anchor_failures_total {_LEDGER.head()['anchor_failures']}",
    ]
    with _METRICS_LOCK:
        snap = dict(_METRICS)
    seen: set[str] = set()
    for (name, labels), val in sorted(snap.items()):
        if name not in seen:
            lines.append(f"# TYPE {name} counter")
            seen.add(name)
        lab = ",".join(f'{k}="{v}"' for k, v in labels)
        lines.append(f"{name}{{{lab}}} {val}" if lab else f"{name} {val}")
    return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")


@app.get("/api/ledger/verify")
def ledger_verify():
    """Re-walk the hash chain. Guarded: the head hash is an audit anchor."""
    denied = _guard_api()
    if denied:
        return denied
    ok, n, reason = _LEDGER.verify()
    return jsonify({"valid": ok, "entries_checked": n, "reason": reason,
                    **_LEDGER.head()}), (200 if ok else 409)


def _reject_run(body: dict, code: int):
    """Every rejected preflight attempt is a decision too: record it in the ledger (A5).
    Only the stage + reason are logged — never the submitted configs or intents."""
    data = request.get_json(silent=True)
    data = data if isinstance(data, dict) else {}
    _LEDGER.append("preflight_rejected", stage=body.get("stage", "guard"), http_status=code,
                   reason=str(body.get("error", ""))[:300],
                   operator=_request_identity(),
                   claimed_operator=str(data.get("operator") or "")[:128] or None,
                   change_ref=str(data.get("change_ref") or "")[:64] or None)
    return jsonify(body), code


@app.post("/api/preflight/run")
def preflight_run():
    denied = _guard_api()
    if denied:
        return denied
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _reject_run({"error": "request body must be a JSON object", "stage": "guard"}, 400)
    if (data.get("mode") or "sim") == "live":
        return _reject_run({"error": "live mode is not available in the community tier",
                        "stage": "guard", "mode": "live"}, 501)

    change_ref = (str(data.get("change_ref") or "")).strip() or None
    if change_ref and not runtime.valid_change_ref(change_ref):
        return _reject_run({"error": "change_ref does not match AEGIS_CHANGE_REF_PATTERN "
                                 "(e.g. CHG0012345)", "stage": "guard"}, 400)
    if runtime.is_production():
        if not change_ref:
            return _reject_run({"error": "production mode requires change_ref (ITSM change "
                                     "number) on every preflight run", "stage": "guard"}, 400)
        if data.get("approver"):
            return _reject_run({"error": "production mode: approval is granted at promotion "
                                     "with an HMAC token, not asserted at preflight",
                            "stage": "guard"}, 400)

    try:
        req_intents = parse_intents(data["intents"]) if data.get("intents") else []
        intents = parse_intents(_BASELINE_INTENTS + req_intents)  # re-validate: dup ids
    except IntentSpecError as e:
        return _reject_run({"error": f"intents: {e}", "stage": "guard"}, 400)

    source = (data.get("source") or "nl_intent").strip()
    imported = None
    if source == "config_import":
        if data.get("configs"):
            imported = data["configs"]
        elif (data.get("config") or "").strip():
            imported = [{"device": data.get("device") or "device-1",
                         "vendor": data.get("vendor") or "frr",
                         "config": data["config"]}]
        else:
            return _reject_run({"error": "config_import requires 'config' or 'configs'",
                            "stage": "guard"}, 400)
    try:
        bundle = run_preflight(
            (data.get("intent") or "").strip(), backend=SimulatorBackend(),
            lab=(data.get("lab") or "clos-evpn").strip(),
            frameworks=data.get("frameworks") or ["pci_dss_v4"],
            # authenticated identity only; the body's "operator" is a claim, ledgered below
            operator=_request_identity() or approvers.UNAUTHENTICATED,
            approver=data.get("approver") or None,
            source=source, imported_configs=imported, change_ref=change_ref,
            intents=intents or None,
            inventory_lookup=_netbox_lookup if netbox.configured() else None)
    except PreflightError as e:
        _inc("aegis_preflight_runs_total", decision="guard_rejected")
        return _reject_run({"error": str(e), "stage": "guard"}, 400)
    except Exception as e:  # noqa: BLE001
        _inc("aegis_preflight_runs_total", decision="pipeline_error")
        return _reject_run({"error": _client_error(e), "stage": "pipeline"}, 502)
    # CROSS-3: emit the bounded-autonomy seal in the same response (None if the change is
    # not within the autonomy ceiling -- see change.authority for why). Detached: the seal
    # rides under bundle["seal"] but is excluded from the bundle's own integrity hash.
    seal, _skipped = seal_response(bundle, _SIGNER, datetime.now(timezone.utc).isoformat())
    bundle["seal"] = seal
    decision = bundle["verdict"]["decision"]
    _inc("aegis_preflight_runs_total", decision=decision)
    for row in ((bundle["validation"].get("intents") or {}).get("results") or []):
        _inc("aegis_intent_results_total", status=row["status"])
    _LEDGER.append("preflight_run", run_id=bundle["run_id"],
                   bundle_sha256=bundle["integrity"]["sha256"], decision=decision,
                   risk_tier=bundle["change"]["risk_tier"],
                   authority=bundle["change"]["authority"]["effective"],
                   operator=bundle.get("operator"), change_ref=change_ref,
                   sealed=isinstance(seal, dict),
                   **({"claimed_operator": str(data.get("operator"))[:128]}
                      if data.get("operator") else {}),
                   # a run-time approver is never an approval (mbDZXhDK): keep what was
                   # claimed, clearly marked unverified
                   **({"claimed_approver": str(data.get("approver"))[:128],
                       "claimed_approver_verified": False} if data.get("approver") else {}),
                   intents_failed=(bundle["validation"].get("intents") or {}).get("failed"),
                   intents_errors=(bundle["validation"].get("intents") or {}).get("errors"))
    return jsonify(bundle)


def _verified_bundle():
    """Shared gate for PDF / OSCAL / CAB: API key + sha present + bundler.verify + seal.

    Returns (error_response, bundle, authenticity_line). A present-but-invalid seal is a
    422 — a forged seal must never be rendered as an "offline-verifiable receipt"."""
    denied = _guard_api()
    if denied:
        return denied, None, None
    bundle = request.get_json(silent=True) or {}
    if not isinstance(bundle, dict) or not (bundle.get("integrity") or {}).get("sha256"):
        return (jsonify({"error": "valid evidence bundle required"}), 400), None, None
    if not bundler_verify(bundle):
        return (jsonify({"error": "bundle integrity verification failed "
                                 "(content does not match integrity.sha256)"}), 422), None, None
    ok, authenticity = _authenticity(bundle)
    if not ok:
        return (jsonify({"error": authenticity}), 422), None, None
    return None, bundle, authenticity


def _run_slug(bundle: dict) -> str:
    # run_id is client-supplied; legit ids are uuid4().hex, so [a-f0-9] is lossless and
    # blocks quote/breakout header injection in Content-Disposition.
    return re.sub(r"[^a-f0-9]", "", str(bundle.get("run_id", "bundle")))[:12] or "bundle"


@app.post("/api/preflight/evidence/pdf")
def evidence_pdf():
    err, bundle, authenticity = _verified_bundle()
    if err:
        return err
    try:
        pdf = render_pdf(bundle, authenticity=authenticity)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": _client_error(e)}), 500
    _inc("aegis_evidence_exports_total", format="pdf")
    return Response(pdf, mimetype="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="aegis-evidence-{_run_slug(bundle)}.pdf"'})


@app.post("/api/preflight/evidence/oscal")
def evidence_oscal():
    """OSCAL-shaped Assessment Results. Not a FedRAMP package. Integrity must verify."""
    err, bundle, authenticity = _verified_bundle()
    if err:
        return err
    body = to_oscal(bundle, authenticity=authenticity)
    _inc("aegis_evidence_exports_total", format="oscal")
    return jsonify(body), 200, {
        "Content-Disposition": f'attachment; filename="aegis-oscal-{_run_slug(bundle)}.json"',
    }


@app.post("/api/preflight/evidence/cab")
def evidence_cab():
    """One-page CAB packet. Rollback is a plan, not a verified execution."""
    err, bundle, authenticity = _verified_bundle()
    if err:
        return err
    body = to_cab(bundle, authenticity=authenticity)
    _inc("aegis_evidence_exports_total", format="cab")
    return jsonify(body), 200, {
        "Content-Disposition": f'attachment; filename="aegis-cab-{_run_slug(bundle)}.json"',
    }


@app.post("/api/approve/mint")
def approve_mint():
    """Mint an HMAC approval token. A ``bundle`` body emits v2; hash-only stays v1."""
    denied = _guard_api()
    if denied:
        return denied
    if not hmac_configured():
        return jsonify({"error": "AEGIS_APPROVE_KEY is unset — HMAC minting refused "
                                 "(no approval can be verified until it is set)"}), 503
    if not _api_key():  # env changed after startup — still never mint unauthenticated
        return jsonify({"error": "AEGIS_APPROVE_KEY is set but AEGIS_API_KEY is unset — "
                                 "refusing to mint HMAC approvals on an unauthenticated "
                                 "server"}), 503
    data = request.get_json(silent=True) or {}
    bundle = data.get("bundle")
    who = data.get("approver") if isinstance(data.get("approver"), str) else ""
    if approvers.registry_configured():
        # A2: the approver identity comes from the approver's OWN credential, never from
        # the request body and never from the shared operator API key.
        resolved = approvers.resolve(request.headers.get("X-Aegis-Approver-Key"))
        if resolved is None:
            _inc("aegis_approval_mint_total", result="unauthorized")
            _LEDGER.append("approval_mint_denied", reason="missing or unknown approver credential")
            return jsonify({"error": "approver credential required — send "
                                     "X-Aegis-Approver-Key"}), 401
        if who and who.strip() != resolved:
            return jsonify({"error": "approver in body does not match the presented "
                                     "approver credential"}), 403
        who = resolved
    elif runtime.is_production():
        return jsonify({"error": "production mode requires AEGIS_APPROVER_KEYS"}), 503
    if runtime.is_production() and not isinstance(bundle, dict):
        return jsonify({"error": "production mode mints v2 tokens only — send the sealed "
                                 "bundle (binds config + inventory, enables SoD check)"}), 400
    if isinstance(bundle, dict):
        op = str(bundle.get("operator") or "").strip().lower()
        if not approvers.identified(op):
            _inc("aegis_approval_mint_total", result="operator_unauthenticated")
            _LEDGER.append("approval_mint_denied", run_id=bundle.get("run_id"),
                           approver=str(who).strip(),
                           reason="bundle has no authenticated operator")
            return jsonify({"error": "separation of duties cannot be checked: the bundle has "
                                     "no authenticated operator identity — the author must "
                                     "re-run the preflight with their personal credential "
                                     "(X-Aegis-Approver-Key)"}), 403
        if op == str(who).strip().lower():
            _inc("aegis_approval_mint_total", result="sod_denied")
            _LEDGER.append("approval_mint_denied", run_id=bundle.get("run_id"),
                           approver=str(who).strip(), reason="separation of duties")
            return jsonify({"error": "separation of duties: the change's operator cannot "
                                     "approve it"}), 403
    try:
        ttl = int(data.get("ttl_sec") or 14400)
        if isinstance(bundle, dict):
            if not bundler_verify(bundle):
                return jsonify({"error": "bundle integrity verification failed "
                                         "(content does not match integrity.sha256)"}), 422
            token = mint_token_for_bundle(who, bundle, ttl_sec=ttl)
            digest, cfg, inv = digests_from_bundle(bundle)
            _inc("aegis_approval_mint_total", result="v2")
            _LEDGER.append("approval_minted", run_id=bundle.get("run_id"),
                           bundle_sha256=digest, approver=who.strip(), version=2, ttl_sec=ttl)
            return jsonify({
                "token": token,
                "alg": "hmac-sha256",
                "version": 2,
                "bound_to": digest,
                "config_sha256": cfg,
                "inventory_sha256": inv,
                "approver": who.strip(),
            })
        token = mint_token(
            approver=who,
            bundle_sha256=data.get("bundle_sha256") or "",
            ttl_sec=ttl,
            config_sha256=data.get("config_sha256") or None,
            inventory_sha256=data.get("inventory_sha256") or None,
        )
    except (TokenError, TypeError, ValueError) as e:
        return jsonify({"error": str(e)}), 400
    digest = (data.get("bundle_sha256") or "").strip().lower()
    _inc("aegis_approval_mint_total", result="hash_only")
    _LEDGER.append("approval_minted", bundle_sha256=digest, approver=str(who).strip(),
                   version=None, ttl_sec=ttl)
    cfg = (data.get("config_sha256") or "").strip().lower() or None
    inv = (data.get("inventory_sha256") or "").strip().lower() or None
    version = 2 if (cfg and inv) else 1
    body = {
        "token": token,
        "alg": "hmac-sha256",
        "version": version,
        "bound_to": digest,
        "approver": str(who).strip(),
    }
    if version == 2:
        body["config_sha256"] = cfg
        body["inventory_sha256"] = inv
    return jsonify(body)


@app.post("/api/preflight/promote")
def preflight_promote():
    denied = _guard_api()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    bundle = data.get("bundle")
    if not isinstance(bundle, dict):
        return jsonify({"error": "body must include bundle"}), 400
    try:
        conn = get_connector(data.get("connector") or "dry_run")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    allow_live = (os.environ.get("AEGIS_PROMOTE_ALLOW_LIVE") or "").strip() == "1"
    try:
        rec = promote(
            bundle, connector=conn,
            approver=data.get("approver"),
            approval_token=data.get("approval_token"),
            allow_live=allow_live,
            live_inventory_sha256=data.get("inventory_sha256"),
            # A1: the server ALWAYS authenticates the bundle with its pinned seal key —
            # a self-hashed forgery fails G0 before any other rule runs.
            seal=bundle.get("seal"), verifier=_VERIFIER, require_seal=True,
            require_verified_approval=runtime.is_production(),
            ledger=_LEDGER,
        )
    except PromoteDenied as e:
        _inc("aegis_promotions_total", status="denied")
        return jsonify({"error": str(e), "denied": True}), 403
    except Exception as e:  # noqa: BLE001
        _inc("aegis_promotions_total", status="error")
        return jsonify({"error": _client_error(e)}), 500
    _inc("aegis_promotions_total", status=rec["status"])
    return jsonify(rec)


def _netbox_lookup(devices: list[str]) -> dict:
    """Roles + sealed inventory rev from NetBox. Production fails closed (the run is
    rejected). The community tier records ``netbox:unavailable`` and falls back to the
    name heuristic, which can only be stricter, never looser."""
    try:
        client = netbox.NetBoxClient()
        try:
            inv = client.inventory(devices)
        finally:
            client.close()
        _inc("aegis_integration_calls_total", system="netbox", result="ok")
        return inv
    except IntegrationError as exc:
        _inc("aegis_integration_calls_total", system="netbox", result="error")
        if runtime.is_production():
            raise PreflightError(f"source of truth unavailable: {exc}") from exc
        return {"roles": {}, "inventory_rev": "netbox:unavailable", "missing": devices}


def _integration_guard():
    denied = _guard_api()
    if denied:
        return denied
    if not _api_key():
        return jsonify({"error": "integrations require AEGIS_API_KEY — an unauthenticated "
                                 "server must never write to ITSM"}), 503
    return None


@app.post("/api/integrations/servicenow/sync")
def servicenow_sync():
    """Attach the verdict + redacted PDF to the CHG the bundle was sealed against; a
    blocked verdict puts the CHG on hold. Explicit, operator-triggered, ledgered."""
    denied = _integration_guard()
    if denied:
        return denied
    if not servicenow.configured():
        return jsonify({"error": "AEGIS_SNOW_URL is not set"}), 503
    err, bundle, authenticity = _verified_bundle()
    if err:
        return err
    run_id = bundle.get("run_id")
    try:
        pdf = render_pdf(bundle, authenticity=authenticity)
        client = servicenow.ServiceNowClient()
        try:
            rec = client.sync(bundle, pdf)
        finally:
            client.close()
    except IntegrationError as exc:
        _inc("aegis_integration_calls_total", system="servicenow", result="error")
        _LEDGER.append("itsm_sync_failed", run_id=run_id, reason=str(exc)[:200])
        return jsonify({"error": str(exc)}), 502
    except Exception as e:  # noqa: BLE001
        _inc("aegis_integration_calls_total", system="servicenow", result="error")
        return jsonify({"error": _client_error(e)}), 500
    _inc("aegis_integration_calls_total", system="servicenow", result="ok")
    _LEDGER.append("itsm_synced", run_id=run_id, change_ref=rec["change_ref"],
                   decision=rec["decision"], on_hold=rec["on_hold"],
                   change_sys_id=rec["change_sys_id"])
    return jsonify(rec)


@app.post("/api/postchange/verify")
def postchange_verify():
    """Body {bundle, running_configs:[{device, vendor, config}], intents?}. Proves the sealed
    change landed (line presence) and re-checks intents on the running configs."""
    denied = _guard_api()
    if denied:
        return denied
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "body must be a JSON object"}), 400
    bundle = data.get("bundle")
    running = data.get("running_configs")
    if not isinstance(bundle, dict) or not (bundle.get("integrity") or {}).get("sha256"):
        return jsonify({"error": "body must include the sealed bundle"}), 400
    if not isinstance(running, list) or not running or len(running) > 200:
        return jsonify({"error": "running_configs must be a list of 1-200 devices"}), 400
    if sum(len(str((r or {}).get("config") or "")) for r in running
           if isinstance(r, dict)) > 5_000_000:
        return jsonify({"error": "running configs exceed 5 MB"}), 400
    if not bundler_verify(bundle):
        return jsonify({"error": "bundle integrity verification failed"}), 422
    seal = bundle.get("seal")
    if not isinstance(seal, dict) or not verify_seal(bundle, seal, _VERIFIER).valid:
        # only an approved, sealed change can have been pushed
        return jsonify({"error": "post-change verification needs a bundle sealed by this "
                                 "AEGIS (pinned key)"}), 422
    try:
        extra = parse_intents(data["intents"]) if data.get("intents") else []
        intents = parse_intents(_BASELINE_INTENTS + extra)  # re-validate: dup ids
    except IntentSpecError as e:
        return jsonify({"error": f"intents: {e}"}), 400
    try:
        rec = verify_postchange(bundle, running, intents or None)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": _client_error(e)}), 500
    _inc("aegis_postchange_total", status=rec["status"])
    _LEDGER.append("postchange_verified", run_id=rec["run_id"], change_ref=rec["change_ref"],
                   status=rec["status"], record_sha256=rec["record_sha256"])
    return jsonify(rec)


@app.get("/api/seal/pubkey")
def seal_pubkey():
    """The pinned public key a client uses to verify seals offline (no secret)."""
    return jsonify({"alg": _VERIFIER.alg(), "key_id": _VERIFIER.key_id(),
                    "public_key_b64": base64.b64encode(_SIGNER.public_key_bytes()).decode("ascii")})


@app.post("/api/seal/verify")
def seal_verify():
    """Offline verification of a {bundle, seal} pair against THIS server's pinned key."""
    data = request.get_json(silent=True) or {}
    bundle, seal = data.get("bundle"), data.get("seal")
    if not isinstance(bundle, dict) or not isinstance(seal, dict):
        return jsonify({"error": "body must be {bundle, seal}"}), 400
    v = verify_seal(bundle, seal, _VERIFIER)
    _inc("aegis_seal_verify_total", result="valid" if v.valid else "invalid")
    return jsonify({"valid": v.valid, "gate": v.gate, "reason": v.reason}), (200 if v.valid else 422)


def main():
    port = int(os.environ.get("AEGIS_PORT", "8088"))
    # Bind loopback by default; require an explicit AEGIS_HOST=0.0.0.0 to expose it.
    host = os.environ.get("AEGIS_HOST", "127.0.0.1")
    print(f"AEGIS community server (sim tier) — http://localhost:{port}/preflight")
    app.run(host=host, port=port)


if __name__ == "__main__":
    main()
