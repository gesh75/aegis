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
    TokenError, hmac_configured, mint_token, load_approve_key,
)

_UI = os.path.join(os.path.dirname(__file__), "ui", "preflight_screen.html")

# Content-Security-Policy shared by the response header and the UI <meta> tag.
# default-src 'self' locks origins down; 'unsafe-inline' is required because the
# PreFlight UI ships inline <style>, inline event handlers and one inline <script>
# (no external assets, no eval). connect-src allows the same-origin API plus the
# localhost fallback the UI uses when opened over http on a dev box.
_CSP = ("default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
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


_SIGNER = _load_signer()
_VERIFIER: Ed25519Verifier = _SIGNER.verifier()
load_approve_key()  # SystemExit if AEGIS_APPROVE_KEY is set but unusable


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


@app.get("/api/status")
def status():
    """Public, no secrets: whether this process requires API auth / HMAC approvals."""
    return jsonify({
        "api_auth": "required" if _api_key() else "open",
        "approve_hmac": "required" if hmac_configured() else "asserted-unverified",
        "seal": "pinned" if (os.environ.get("AEGIS_SEAL_KEY") or "").strip() else "ephemeral",
        "egress": "none",
    })


@app.post("/api/preflight/run")
def preflight_run():
    denied = _guard_api()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    if (data.get("mode") or "sim") == "live":
        return jsonify({"error": "live mode is not available in the community tier",
                        "stage": "guard", "mode": "live"}), 501

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
            return jsonify({"error": "config_import requires 'config' or 'configs'",
                            "stage": "guard"}), 400
    try:
        bundle = run_preflight(
            (data.get("intent") or "").strip(), backend=SimulatorBackend(),
            lab=(data.get("lab") or "clos-evpn").strip(),
            frameworks=data.get("frameworks") or ["pci_dss_v4"],
            operator=(data.get("operator") or "community").strip(),
            approver=data.get("approver") or None,
            source=source, imported_configs=imported)
    except PreflightError as e:
        return jsonify({"error": str(e), "stage": "guard"}), 400
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"{type(e).__name__}: {e}", "stage": "pipeline"}), 502
    # CROSS-3: emit the bounded-autonomy seal in the same response (None if the change is
    # not within the autonomy ceiling -- see change.authority for why). Detached: the seal
    # rides under bundle["seal"] but is excluded from the bundle's own integrity hash.
    seal, _skipped = seal_response(bundle, _SIGNER, datetime.now(timezone.utc).isoformat())
    bundle["seal"] = seal
    return jsonify(bundle)


@app.post("/api/preflight/evidence/pdf")
def evidence_pdf():
    denied = _guard_api()
    if denied:
        return denied
    bundle = request.get_json(silent=True) or {}
    if not bundle.get("integrity", {}).get("sha256"):
        return jsonify({"error": "valid evidence bundle required"}), 400
    # never render a tampered/forged bundle into an examiner-ready artifact:
    # the integrity hash must verify before ReportLab ever sees the content
    if not bundler_verify(bundle):
        return jsonify({"error": "bundle integrity verification failed "
                                 "(content does not match integrity.sha256)"}), 422
    try:
        pdf = render_pdf(bundle)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500
    # run_id is client-supplied; sanitize before it lands in the Content-Disposition
    # header. Legit run_ids are uuid4().hex (lowercase hex), so stripping to [a-f0-9]
    # is lossless for them while blocking quote/breakout header-injection abuse.
    run = re.sub(r"[^a-f0-9]", "", str(bundle.get("run_id", "bundle")))[:12] or "bundle"
    return Response(pdf, mimetype="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="aegis-evidence-{run}.pdf"'})


def _verified_bundle():
    """Shared gate for PDF / OSCAL / CAB: API key + sha present + bundler.verify."""
    denied = _guard_api()
    if denied:
        return denied, None
    bundle = request.get_json(silent=True) or {}
    if not bundle.get("integrity", {}).get("sha256"):
        return (jsonify({"error": "valid evidence bundle required"}), 400), None
    if not bundler_verify(bundle):
        return (jsonify({"error": "bundle integrity verification failed "
                                 "(content does not match integrity.sha256)"}), 422), None
    return None, bundle


@app.post("/api/preflight/evidence/oscal")
def evidence_oscal():
    """OSCAL-shaped Assessment Results. Not a FedRAMP package. Integrity must verify."""
    err, bundle = _verified_bundle()
    if err:
        return err
    body = to_oscal(bundle)
    run = re.sub(r"[^a-f0-9]", "", str(bundle.get("run_id", "bundle")))[:12] or "bundle"
    return jsonify(body), 200, {
        "Content-Disposition": f'attachment; filename="aegis-oscal-{run}.json"',
    }


@app.post("/api/preflight/evidence/cab")
def evidence_cab():
    """One-page CAB packet. Rollback is a plan, not a verified execution."""
    err, bundle = _verified_bundle()
    if err:
        return err
    body = to_cab(bundle)
    run = re.sub(r"[^a-f0-9]", "", str(bundle.get("run_id", "bundle")))[:12] or "bundle"
    return jsonify(body), 200, {
        "Content-Disposition": f'attachment; filename="aegis-cab-{run}.json"',
    }


@app.post("/api/approve/mint")
def approve_mint():
    """Mint an HMAC approval token bound to a bundle hash. Requires AEGIS_APPROVE_KEY."""
    denied = _guard_api()
    if denied:
        return denied
    if not hmac_configured():
        return jsonify({"error": "AEGIS_APPROVE_KEY is unset — HMAC minting refused "
                                 "(asserted-unverified mode)"}), 503
    data = request.get_json(silent=True) or {}
    try:
        token = mint_token(
            approver=data.get("approver") or "",
            bundle_sha256=data.get("bundle_sha256") or "",
            ttl_sec=int(data.get("ttl_sec") or 14400),
        )
    except (TokenError, TypeError, ValueError) as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({
        "token": token,
        "alg": "hmac-sha256",
        "bound_to": (data.get("bundle_sha256") or "").strip().lower(),
        "approver": (data.get("approver") or "").strip(),
    })


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
        )
    except PromoteDenied as e:
        return jsonify({"error": str(e), "denied": True}), 403
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500
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
    return jsonify({"valid": v.valid, "gate": v.gate, "reason": v.reason}), (200 if v.valid else 422)


def main():
    port = int(os.environ.get("AEGIS_PORT", "8088"))
    # Bind loopback by default; require an explicit AEGIS_HOST=0.0.0.0 to expose it.
    host = os.environ.get("AEGIS_HOST", "127.0.0.1")
    print(f"AEGIS community server (sim tier) — http://localhost:{port}/preflight")
    app.run(host=host, port=port)


if __name__ == "__main__":
    main()
