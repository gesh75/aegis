"""Hardening controls (2026-10 audit): authenticity, SoD, replay, ledger, production mode.

  H1  a self-hashed FORGERY (ship_ready/low, sha256 recomputed) is denied at G0 — with no
      seal, with a stolen seal from another bundle, and with a garbage seal
  H2  exports: a forged/garbage seal is 422; an unsealed bundle renders but is labelled
      UNSEALED; a genuine seal renders "seal verified"
  H3  separation of duties: approver == operator is denied at the gate AND at mint
  H4  HMAC approval tokens are single-use, including across a restart (file ledger)
  H5  ledger: chain verifies; editing / deleting a line is detected at that seq; a broken
      ledger refuses to load (never appends onto a broken chain)
  H6  production mode: refuses to start with any control unset; asserted-unverified
      approvals are denied; change_ref required; run-time approver rejected
  H7  approver registry: mint needs the approver's own credential; identity comes from it
  H8  evidence honesty: rollback is plan-only; secrets redacted; PDF markup is escaped
  H9  /metrics + /healthz + /api/ledger/verify contract
  H11 AEGIS_PEER_AS_POLICY (D1): the default ``hitl`` makes a neighbor add HITL (sealable, needs
      approval) while router bgp / local-as stay BLOCK; ``block`` restores the original BLOCK
  H12 ledger SIEM anchor: entries arrive over UDP syslog with the chain hashes; a dead
      sink never blocks the append and is counted
  H13 air-gap is the DEFAULT: unset/typo → on, only "0" opts out; from_env() drops the cloud
      backend by default even with ANTHROPIC_API_KEY; HttpBackend refuses a non-loopback
      model URL by default
  H14 guard-rejected preflights and denied mints are recorded in the ledger
  H16 authority HITL/HOTL always needs a verified second-person approval at the gate and is
      recorded as needs_approval in the bundle, whatever the computed risk tier
  H15 a run-time ``approver`` name is never a granted approval: the verdict stays
      needs_approval, granted_by stays null, and the ledger records the claim as unverified
  H10 offline CLI (python -m aegis.verify): genuine seal PASS (exit 0), forged FAIL
      (exit 1), missing seal with --pubkey FAIL, tampered ledger FAIL

Usage:  python3 -m aegis.tests.hardening_test
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
import sys
import tempfile

from ..core.backends.simulator import SimulatorBackend
from ..core.orchestrator.pipeline import run_preflight
from ..core.promote import gate
from ..core.promote.connectors import DryRunConnector
from ..core.promote.promote import PromoteDenied, promote
from ..core.promote.tokens import mint_token_for_bundle
from ..core.seal import Ed25519Signer, seal_bundle
from ..core import runtime
from ..evidence.bundler import compute_sha256
from ..evidence.ledger import Ledger, LedgerError, verify_chain
from ..evidence.secrets import plaintext_hits, redact
from ..evidence.junos import to_set
from ..evidence.pdf import render_pdf

FAILS: list[str] = []
CHECKS = 0
KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
API = "hardening-api-key"


def check(name: str, cond: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(f"{name}: {detail}")


def _needs_approval_bundle() -> dict:
    """A bounded, non-blocked bundle that needs approval (deterministic sim search)."""
    for i in range(400):
        b = run_preflight(f"add vlan {100 + i} to leaf", backend=SimulatorBackend(
            converge_fail_rate=0.0, batfish_error_rate=0.0), lab="single", operator="alice")
        au = b["change"]["authority"]
        if (b["verdict"]["decision"] != "blocked" and b["change"]["risk_tier"] in ("medium", "high")
                and au["allowed"] and au["effective"] != "block"):
            return b
    raise RuntimeError("no needs-approval bundle found in sim search")


def _forge(b: dict) -> dict:
    f = copy.deepcopy(b)
    f.pop("seal", None)
    f["verdict"] = {"decision": "ship_ready", "reason": "forged"}
    f["change"]["risk_tier"] = "low"
    f["integrity"]["sha256"] = compute_sha256(f)
    return f


def gate_and_ledger() -> None:
    signer = Ed25519Signer.generate()
    verifier = signer.verifier()
    b = _needs_approval_bundle()
    seal = seal_bundle(b, signer, sealed_at_utc="2026-10-22T00:00:00+00:00")

    # H1 — forgeries die at G0
    forged = _forge(b)
    d = gate.evaluate(forged, approver=None, approval_token=None, connector_is_live=False,
                      allow_live=False, seal=None, verifier=verifier, require_seal=True)
    check("H1.unsealed_forgery", not d.allowed and "unsealed" in d.reason, d.reason)
    d = gate.evaluate(forged, approver=None, approval_token=None, connector_is_live=False,
                      allow_live=False, seal=seal, verifier=verifier, require_seal=True)
    check("H1.stolen_seal", not d.allowed and "G3" in d.reason, d.reason)
    junk = copy.deepcopy(seal)
    junk["signature"]["value"] = "AAAA"
    d = gate.evaluate(b, approver=None, approval_token=None, connector_is_live=False,
                      allow_live=False, seal=junk, verifier=verifier, require_seal=True)
    check("H1.garbage_seal", not d.allowed and "seal verification failed" in d.reason, d.reason)
    other = Ed25519Signer.generate()
    d = gate.evaluate(b, approver=None, approval_token=None, connector_is_live=False,
                      allow_live=False, seal=seal_bundle(b, other, sealed_at_utc="x"),
                      verifier=verifier, require_seal=True)
    check("H1.foreign_key_seal", not d.allowed and "G1" in d.reason, d.reason)
    d = gate.evaluate(b, approver=None, approval_token=None, connector_is_live=False,
                      allow_live=False, seal=seal, verifier=None)
    check("H1.seal_without_verifier", not d.allowed, d.reason)

    os.environ["AEGIS_APPROVE_KEY"] = KEY
    try:
        # H3 — SoD at the gate (alice authored it)
        tok = mint_token_for_bundle("alice", b, ttl_sec=600)
        d = gate.evaluate(b, approver="alice", approval_token=tok, connector_is_live=False,
                          allow_live=False, seal=seal, verifier=verifier, require_seal=True)
        check("H3.self_approval_denied", not d.allowed and "separation of duties" in d.reason,
              d.reason)

        # H6 — production gate refuses asserted-unverified (key unset for this check)
        os.environ.pop("AEGIS_APPROVE_KEY", None)
        d = gate.evaluate(b, approver="bob", approval_token="anything", connector_is_live=False,
                          allow_live=False, seal=seal, verifier=verifier, require_seal=True,
                          require_verified_approval=True)
        check("H6.asserted_denied_in_prod", not d.allowed and "HMAC" in d.reason, d.reason)
        # iPvAwZKJ: the community default (require_verified_approval=False) must not accept
        # a free-text approver + token either; the reason says how to fix it
        d = gate.evaluate(b, approver="bob", approval_token="anything", connector_is_live=False,
                          allow_live=False, seal=seal, verifier=verifier, require_seal=True)
        check("H6.asserted_denied_in_community", not d.allowed and d.approval_method == "none"
              and "AEGIS_APPROVE_KEY" in d.reason, f"{d.allowed} {d.approval_method} {d.reason}")
        try:
            promote(b, connector=DryRunConnector(), approver="bob", approval_token="anything",
                    ledger=Ledger(), seal=seal, verifier=verifier, require_seal=True)
            check("H6.promote_asserted_denied", False, "promoted on an asserted approval")
        except PromoteDenied as e:
            check("H6.promote_asserted_denied", "AEGIS_APPROVE_KEY" in str(e), str(e))
        os.environ["AEGIS_APPROVE_KEY"] = KEY

        # H4 — single use, across restart
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "ledger.jsonl")
            led = Ledger(path)
            tok = mint_token_for_bundle("bob", b, ttl_sec=600)
            rec = promote(b, connector=DryRunConnector(), approver="bob", approval_token=tok,
                          ledger=led, seal=seal, verifier=verifier, require_seal=True)
            check("H4.first_use_ok", rec["status"] == "promoted", str(rec.get("status")))
            try:
                promote(b, connector=DryRunConnector(), approver="bob", approval_token=tok,
                        ledger=led, seal=seal, verifier=verifier, require_seal=True)
                check("H4.replay_denied", False, "replay was promoted")
            except PromoteDenied as e:
                check("H4.replay_denied", "single-use" in str(e), str(e))
            led2 = Ledger(path)          # simulated restart
            try:
                promote(b, connector=DryRunConnector(), approver="bob", approval_token=tok,
                        ledger=led2, seal=seal, verifier=verifier, require_seal=True)
                check("H4.replay_after_restart", False, "replay after restart was promoted")
            except PromoteDenied as e:
                check("H4.replay_after_restart", "single-use" in str(e), str(e))

            # H4 — a re-encoded copy of a spent token is the same token (Ujf5v6Mr): the
            # replay id must not change with padding / junk / alphabet tricks
            led3 = Ledger()
            tok3 = mint_token_for_bundle("bob", b, ttl_sec=600)
            rec3 = promote(b, connector=DryRunConnector(), approver="bob", approval_token=tok3,
                           ledger=led3, seal=seal, verifier=verifier, require_seal=True)
            check("H4.reencode.first_use_ok", rec3["status"] == "promoted", str(rec3.get("status")))
            for vname, vtok in (("pad", tok3 + "="), ("junk", tok3 + "!!!!"),
                                ("std_alphabet", tok3.replace("-", "+").replace("_", "/") + "==")):
                try:
                    promote(b, connector=DryRunConnector(), approver="bob", approval_token=vtok,
                            ledger=led3, seal=seal, verifier=verifier, require_seal=True)
                    check(f"H4.reencode.{vname}_denied", False, "re-encoded replay was promoted")
                except PromoteDenied:
                    check(f"H4.reencode.{vname}_denied", True)
            check("H4.reencode.one_promotion",
                  [e["kind"] for e in led3.entries()].count("promotion") == 1,
                  str([e["kind"] for e in led3.entries()]))

            # H5 — chain verifies, then tamper
            ok, n, why = verify_chain(path)
            kinds = [e["kind"] for e in led2.entries()]
            check("H5.chain_ok", ok and n >= 3, f"{ok} {n} {why}")
            check("H5.kinds", "approval_consumed" in kinds and "promotion" in kinds
                  and "promotion_denied" in kinds, str(kinds))
            lines = open(path, encoding="ascii").read().splitlines()
            edited = json.loads(lines[1])
            edited["approver"] = "mallory"
            bad = lines[:1] + [json.dumps(edited, sort_keys=True)] + lines[2:]
            open(path, "w", encoding="ascii").write("\n".join(bad) + "\n")
            ok, n, why = verify_chain(path)
            check("H5.edit_detected", not ok and n == 2, f"{ok} {n} {why}")
            open(path, "w", encoding="ascii").write("\n".join(lines[:1] + lines[2:]) + "\n")
            ok, n, why = verify_chain(path)
            check("H5.delete_detected", not ok and n == 2, f"{ok} {n} {why}")
            try:
                Ledger(path)
                check("H5.broken_refuses_load", False, "loaded a broken ledger")
            except LedgerError:
                check("H5.broken_refuses_load", True)
    finally:
        os.environ.pop("AEGIS_APPROVE_KEY", None)


def production_startup() -> None:
    saved = {k: os.environ.get(k) for k in ("AEGIS_MODE", "AEGIS_API_KEY", "AEGIS_APPROVE_KEY",
                                            "AEGIS_SEAL_KEY", "AEGIS_LEDGER_PATH",
                                            "AEGIS_APPROVER_KEYS")}
    try:
        for k in saved:
            os.environ.pop(k, None)
        os.environ["AEGIS_MODE"] = "production"
        try:
            runtime.assert_startup_ok()
            check("H6.refuses_unconfigured", False, "started unconfigured")
        except SystemExit as e:
            check("H6.refuses_unconfigured", "AEGIS_APPROVER_KEYS" in str(e), str(e))
        for k in ("AEGIS_API_KEY", "AEGIS_APPROVE_KEY", "AEGIS_SEAL_KEY", "AEGIS_LEDGER_PATH",
                  "AEGIS_APPROVER_KEYS"):
            os.environ[k] = "x"
        try:
            runtime.assert_startup_ok()
            check("H6.starts_configured", True)
        except SystemExit as e:
            check("H6.starts_configured", False, str(e))
        os.environ["AEGIS_MODE"] = "bogus"
        try:
            runtime.mode()
            check("H6.bad_mode_fatal", False, "accepted bogus mode")
        except SystemExit:
            check("H6.bad_mode_fatal", True)
        os.environ["AEGIS_MODE"] = "community"
        check("H6.change_ref.chg", runtime.valid_change_ref("CHG0012345"))
        check("H6.change_ref.jira", runtime.valid_change_ref("NETOPS-123"))
        check("H6.change_ref.bad", not runtime.valid_change_ref('CHG"; drop'))
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def evidence_honesty() -> None:
    b = run_preflight("add vlan 40 with plaintext bgp authentication-key abc123",
                      backend=SimulatorBackend(), lab="single", operator="ci")
    rb = b["rollback"]
    check("H8.rollback_plan_only", rb["tested_in_twin"] is False
          and rb["verification"] == "plan-only", str(rb.get("verification")))
    for raw, secret in (("username a password 0 Sup3rS3cret", "Sup3rS3cret"),
                        ("snmp-server community n0tpublic RO", "n0tpublic"),
                        ('set protocols bgp group G authentication-key "$9$xYzAbC"', "$9$xYzAbC"),
                        (" neighbor 1.1.1.1 password 7 0822455D0A16", "0822455D0A16")):
        check(f"H8.redact[{secret}]", secret not in redact(raw), redact(raw))
    check("H8.redact_idempotent", redact(redact("password 0 x1")) == redact("password 0 x1"))
    check("H8.no_false_positive_keychain",
          plaintext_hits('set security authentication-key-chains key-chain K key 0 secret "$9$q"') == [])
    flat = to_set("protocols { bgp { group G { inactive: authentication-key \"$9$q\"; "
                  "neighbor 1.1.1.1; } } }")
    check("H8.junos_inactive_dropped", "authentication-key" not in flat and "neighbor 1.1.1.1" in flat,
          flat)
    evil = copy.deepcopy(b)
    evil["change"]["generated_configs"][0]["device"] = '<link href="http://x">click</link><b>'
    evil["verdict"]["reason"] = "<font color=red>pwn"
    try:
        pdf = render_pdf(evil, authenticity="<b>unbalanced")
        check("H8.pdf_markup_escaped", pdf[:5] == b"%PDF-")
    except Exception as e:  # noqa: BLE001
        check("H8.pdf_markup_escaped", False, f"{type(e).__name__}: {e}")


def http_contract() -> None:
    from ..serve import app
    app.testing = True
    c = app.test_client()
    r = c.post("/api/preflight/run", json={"intent": "add vlan 10 to leaf-1", "lab": "single",
                                           "operator": "alice", "change_ref": "CHG0012345"})
    check("H9.run_change_ref", r.status_code == 200
          and (r.get_json() or {}).get("change", {}).get("change_ref") == "CHG0012345",
          f"{r.status_code} {r.get_data(as_text=True)[:160]}")
    bundle = r.get_json() or {}
    r = c.post("/api/preflight/run", json={"intent": "add vlan 10", "change_ref": "bad ref!"})
    check("H9.bad_change_ref_400", r.status_code == 400, str(r.status_code))

    # H2 — exports
    if bundle.get("seal"):
        r = c.post("/api/preflight/evidence/cab", json=bundle)
        check("H2.cab_seal_verified", r.status_code == 200
              and "seal verified" in (r.get_json() or {}).get("authenticity", ""),
              r.get_data(as_text=True)[:200])
        junk = copy.deepcopy(bundle)
        junk["seal"]["signature"]["value"] = "AAAA"
        r = c.post("/api/preflight/evidence/pdf", json=junk)
        check("H2.pdf_garbage_seal_422", r.status_code == 422, str(r.status_code))
    forged = _forge(bundle)
    r = c.post("/api/preflight/evidence/cab", json=forged)
    check("H2.cab_unsealed_labelled", r.status_code == 200
          and "UNSEALED" in (r.get_json() or {}).get("authenticity", ""),
          r.get_data(as_text=True)[:200])
    r = c.post("/api/preflight/promote", json={"bundle": forged, "connector": "dry_run"})
    check("H1.http_forgery_403", r.status_code == 403
          and "unsealed" in r.get_data(as_text=True), r.get_data(as_text=True)[:200])

    # H6 — community mode, AEGIS_APPROVE_KEY unset: an asserted approval is a 403 over HTTP
    if bundle.get("seal"):
        r = c.post("/api/preflight/promote", json={"bundle": bundle, "approver": "bob",
                                                   "approval_token": "x", "connector": "dry_run"})
        check("H6.http_community_asserted_403", r.status_code == 403
              and "AEGIS_APPROVE_KEY" in r.get_data(as_text=True),
              f"{r.status_code} {r.get_data(as_text=True)[:200]}")

    # H6 — production request-time rules
    os.environ["AEGIS_MODE"] = "production"
    try:
        r = c.post("/api/preflight/run", json={"intent": "add vlan 10"})
        check("H6.prod_requires_change_ref", r.status_code == 400
              and "change_ref" in r.get_data(as_text=True), r.get_data(as_text=True)[:160])
        r = c.post("/api/preflight/run", json={"intent": "add vlan 10", "change_ref": "CHG1",
                                               "approver": "bob"})
        check("H6.prod_rejects_runtime_approver", r.status_code == 400, str(r.status_code))
        r = c.post("/api/preflight/evidence/cab", json=forged)
        check("H6.prod_export_requires_seal", r.status_code == 422, str(r.status_code))
    finally:
        os.environ.pop("AEGIS_MODE", None)

    # H7 — approver registry + SoD at mint
    key_bob = "bob-personal-credential-123456"
    os.environ["AEGIS_APPROVE_KEY"] = KEY
    os.environ["AEGIS_API_KEY"] = API  # HMAC minting is refused on an unauthenticated server
    os.environ["AEGIS_APPROVER_KEYS"] = "bob:" + hashlib.sha256(key_bob.encode()).hexdigest()
    try:
        r = c.post("/api/approve/mint", json={"approver": "bob", "bundle": bundle},
                   headers={"X-Aegis-Key": API})
        check("H7.mint_needs_credential", r.status_code == 401, str(r.status_code))
        r = c.post("/api/approve/mint", json={"approver": "carol", "bundle": bundle},
                   headers={"X-Aegis-Key": API, "X-Aegis-Approver-Key": key_bob})
        check("H7.body_identity_mismatch", r.status_code == 403, str(r.status_code))
        r = c.post("/api/approve/mint", json={"bundle": bundle},
                   headers={"X-Aegis-Key": API, "X-Aegis-Approver-Key": key_bob})
        check("H7.identity_from_credential", r.status_code == 200
              and (r.get_json() or {}).get("approver") == "bob",
              f"{r.status_code} {r.get_data(as_text=True)[:160]}")
        os.environ["AEGIS_APPROVER_KEYS"] += ",alice:" + hashlib.sha256(b"alice-cred-0000000000").hexdigest()
        r = c.post("/api/approve/mint", json={"bundle": bundle},
                   headers={"X-Aegis-Key": API, "X-Aegis-Approver-Key": "alice-cred-0000000000"})
        check("H3.mint_sod_403", r.status_code == 403
              and "separation of duties" in r.get_data(as_text=True), r.get_data(as_text=True)[:160])
    finally:
        os.environ.pop("AEGIS_APPROVE_KEY", None)
        os.environ.pop("AEGIS_APPROVER_KEYS", None)
        os.environ.pop("AEGIS_API_KEY", None)

    # H9 — ops endpoints
    r = c.get("/healthz")
    check("H9.healthz", r.status_code == 200, str(r.status_code))
    r = c.get("/metrics")
    body = r.get_data(as_text=True)
    check("H9.metrics", r.status_code == 200 and "aegis_preflight_runs_total" in body
          and "aegis_info" in body, body[:200])
    r = c.get("/api/ledger/verify")
    lv = r.get_json() or {}
    check("H9.ledger_verify", r.status_code == 200 and lv.get("valid") is True
          and lv.get("entries_checked", 0) >= 1, str(lv))
    r = c.get("/preflight.js")
    check("H9.ui_js_served", r.status_code == 200 and "addEventListener" in r.get_data(as_text=True),
          str(r.status_code))
    csp = r.headers.get("Content-Security-Policy") or ""
    check("H9.csp_no_inline_script", "script-src 'self';" in csp and "script-src 'self' 'unsafe-inline'" not in csp,
          csp)
    ui = c.get("/preflight").get_data(as_text=True)
    check("H9.ui_no_inline_handlers", "onclick=" not in ui and "onchange=" not in ui
          and "<script>" not in ui, "inline script/handler present")
    r = c.get("/api/status")
    check("H9.status_mode", (r.get_json() or {}).get("mode") == "community", r.get_data(as_text=True))


def offline_cli() -> None:
    import base64 as b64
    from .. import verify as cli
    signer = Ed25519Signer.generate()
    b = _needs_approval_bundle()
    b["seal"] = seal_bundle(b, signer, sealed_at_utc="2026-10-22T00:00:00+00:00")
    with tempfile.TemporaryDirectory() as td:
        bp, pk, fp, lp = (os.path.join(td, n) for n in ("b.json", "pk.json", "f.json", "l.jsonl"))
        json.dump(b, open(bp, "w"))
        json.dump({"public_key_b64": b64.b64encode(signer.public_key_bytes()).decode()},
                  open(pk, "w"))
        check("H10.genuine_exit0", cli.main(["--bundle", bp, "--pubkey", pk, "--json"]) == 0)
        forged = _forge(b)
        forged["seal"] = b["seal"]
        json.dump(forged, open(fp, "w"))
        check("H10.forged_exit1", cli.main(["--bundle", fp, "--pubkey", pk, "--json"]) == 1)
        forged.pop("seal")
        json.dump(forged, open(fp, "w"))
        check("H10.unsealed_with_pubkey_exit1",
              cli.main(["--bundle", fp, "--pubkey", pk, "--json"]) == 1)
        led = Ledger(lp)
        led.append("preflight_run", run_id="a")
        led.append("preflight_run", run_id="b")
        check("H10.ledger_ok_exit0", cli.main(["--ledger", lp, "--json"]) == 0)
        open(lp, "a").write(open(lp).read().splitlines()[0] + "\n")
        check("H10.ledger_tamper_exit1", cli.main(["--ledger", lp, "--json"]) == 1)
        check("H10.usage_exit2", cli.main([]) == 2)


def peer_as_policy() -> None:
    from ..core.risk import classify_change, required_authority, Severity, Tier
    nbr = [{"device": "leaf-1", "vendor": "frr", "config": " neighbor 10.0.0.9 remote-as 65020",
            "grounded_commands": []}]
    own = [{"device": "leaf-1", "vendor": "frr", "config": "router bgp 65010",
            "grounded_commands": []}]
    os.environ["AEGIS_PEER_AS_POLICY"] = "block"
    check("H11.block_policy_neighbor_block",
          required_authority(Severity.LOW, classify_change(nbr)) == Tier.BLOCK)
    os.environ.pop("AEGIS_PEER_AS_POLICY", None)  # D1 default = hitl
    try:
        check("H11.hitl_neighbor",
              required_authority(Severity.LOW, classify_change(nbr)) == Tier.HITL)
        check("H11.hitl_never_auto",
              required_authority(Severity.NONE, classify_change(nbr)) >= Tier.HITL)
        check("H11.local_asn_still_block",
              required_authority(Severity.LOW, classify_change(own)) == Tier.BLOCK)
        b = run_preflight("", backend=SimulatorBackend(), lab="single", source="config_import",
                          imported_configs=nbr, operator="alice")
        check("H11.recorded", b["change"]["authority"]["change_class"].get("touches_peer_as") is True,
              str(b["change"]["authority"]["change_class"]))
        os.environ["AEGIS_PEER_AS_POLICY"] = "allow"
        try:
            classify_change(nbr)
            check("H11.bad_policy_fatal", False, "accepted 'allow'")
        except ValueError:
            check("H11.bad_policy_fatal", True)
        # D2 — reversible obfuscation fails PCI 8.3.2 by default; "report" restores PASS
        from ..evidence.compliance import map_controls
        j9 = [{"device": "mx1", "vendor": "junos", "grounded_commands": [],
               "config": 'set protocols bgp group G authentication-key "$9$AbCdEf"'}]
        bf = {"errors": 0, "warnings": 0, "passed": 1, "findings": []}

        def pci_832():
            rows = map_controls(j9, bf, ["pci_dss_v4"])
            return next(r for r in rows if r["control"] == "8.3.2")

        os.environ.pop("AEGIS_REVERSIBLE_SECRETS", None)
        row = pci_832()
        check("H11.d2_default_fail", row["status"] == "fail" and "reversible" in row["evidence"],
              str(row))
        os.environ["AEGIS_REVERSIBLE_SECRETS"] = "report"
        check("H11.d2_report_pass", pci_832()["status"] == "pass")
        os.environ["AEGIS_REVERSIBLE_SECRETS"] = "ignore"
        try:
            pci_832()
            check("H11.d2_bad_policy_fatal", False, "accepted 'ignore'")
        except ValueError:
            check("H11.d2_bad_policy_fatal", True)
        os.environ.pop("AEGIS_REVERSIBLE_SECRETS", None)
    finally:
        os.environ.pop("AEGIS_PEER_AS_POLICY", None)


def siem_anchor() -> None:
    import socket
    from ..evidence.ledger import SyslogSink
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(2)
    port = rx.getsockname()[1]
    led = Ledger(None, sink=SyslogSink(f"127.0.0.1:{port}/udp"))
    e = led.append("preflight_run", run_id="siem-1")
    try:
        msg = rx.recv(65535).decode()
        check("H12.syslog_received", msg.startswith("<110>1 ") and e["entry_sha256"] in msg
              and e["prev_sha256"] in msg, msg[:120])
    except socket.timeout:
        check("H12.syslog_received", False, "no datagram")
    finally:
        rx.close()

    def dead(_entry):
        raise OSError("siem down")
    led2 = Ledger(None, sink=dead)
    led2.append("preflight_run", run_id="x")
    check("H12.dead_sink_nonblocking", led2.head()["seq"] == 1
          and led2.head()["anchor_failures"] == 1, str(led2.head()))
    try:
        SyslogSink("no-port")
        check("H12.bad_spec_fatal", False, "accepted bad spec")
    except SystemExit:
        check("H12.bad_spec_fatal", True)


def airgap_default() -> None:
    from ..core.llm.airgap import airgap_enabled
    from ..core.llm.config import AdapterConfig
    from ..core.backends.http_backend import HttpBackend
    saved = {k: os.environ.get(k) for k in ("AEGIS_AIRGAP", "ANTHROPIC_API_KEY")}
    try:
        os.environ.pop("AEGIS_AIRGAP", None)
        check("H13.default_on", airgap_enabled() is True)
        os.environ["AEGIS_AIRGAP"] = "no"
        check("H13.typo_stays_on", airgap_enabled() is True)
        os.environ["AEGIS_AIRGAP"] = "0"
        check("H13.explicit_opt_out", airgap_enabled() is False)
        os.environ.pop("AEGIS_AIRGAP", None)
        os.environ["ANTHROPIC_API_KEY"] = "test-not-a-real-key"
        cfg = AdapterConfig.from_env()
        check("H13.cloud_dropped_by_default",
              cfg.airgap and all(sp.provider != "anthropic-cloud" for sp in cfg.chain),
              str([sp.provider for sp in cfg.chain]))
        try:
            HttpBackend(model_runner_url="http://10.9.9.9:12434")
            check("H13.http_backend_refuses_lan_model", False, "accepted")
        except RuntimeError:
            check("H13.http_backend_refuses_lan_model", True)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def rejections_ledgered() -> None:
    from ..serve import app, _LEDGER
    c = app.test_client()
    before = _LEDGER.head()["seq"]
    r = c.post("/api/preflight/run", json={"intent": "   ", "operator": "eve"})
    kinds = [e["kind"] for e in _LEDGER.entries()[before:]]
    check("H14.guard_rejection_ledgered", r.status_code == 400 and "preflight_rejected" in kinds,
          f"{r.status_code} {kinds}")
    r = c.post("/api/preflight/run", json=["not", "an", "object"])
    check("H14.non_object_body_no_500", r.status_code in (400, 200), str(r.status_code))
    os.environ["AEGIS_APPROVE_KEY"] = KEY
    os.environ["AEGIS_APPROVER_KEYS"] = "bob:" + hashlib.sha256(b"bob-cred-0000000000").hexdigest()
    os.environ["AEGIS_API_KEY"] = API
    try:
        before = _LEDGER.head()["seq"]
        c.post("/api/approve/mint", json={"approver": "bob", "bundle_sha256": "a" * 64},
               headers={"X-Aegis-Key": API})
        kinds = [e["kind"] for e in _LEDGER.entries()[before:]]
        check("H14.mint_denial_ledgered", "approval_mint_denied" in kinds, str(kinds))
    finally:
        os.environ.pop("AEGIS_APPROVE_KEY", None)
        os.environ.pop("AEGIS_APPROVER_KEYS", None)
        os.environ.pop("AEGIS_API_KEY", None)


def runtime_approver_not_granted() -> None:
    """mbDZXhDK: only an HMAC token (bound to the sealed bundle) is an approval. A name in
    the run request body must neither flip the verdict nor be sealed as granted_by."""
    from ..serve import app, _LEDGER
    # library: a high-tier change with a claimed approver
    b = run_preflight("add vlan 10 to leaf-1", backend=SimulatorBackend(), lab="single",
                      operator="alice", approver="cto@corp")
    ap = b["change"]["approval"]
    check("H15.lib.high_tier", b["change"]["risk_tier"] == "high" and ap["required"] is True,
          str(b["change"]["risk_tier"]))
    check("H15.lib.verdict_needs_approval", b["verdict"]["decision"] == "needs_approval",
          str(b["verdict"]))
    check("H15.lib.granted_by_null", ap.get("granted_by") is None and ap.get("granted_utc") is None,
          str(ap))
    check("H15.lib.name_not_sealed", "cto@corp" not in json.dumps(b), "claimed approver in bundle")
    # HTTP, community mode (the default)
    c = app.test_client()
    r = c.post("/api/preflight/run", json={"intent": "add vlan 10 to leaf-1", "lab": "single",
                                           "operator": "alice", "approver": "cto@corp"})
    hb = r.get_json() or {}
    hap = (hb.get("change") or {}).get("approval") or {}
    check("H15.http.verdict_needs_approval", r.status_code == 200
          and (hb.get("verdict") or {}).get("decision") == "needs_approval",
          f"{r.status_code} {(hb.get('verdict') or {})}")
    check("H15.http.granted_by_null", hap.get("granted_by") is None, str(hap))
    pdf = c.post("/api/preflight/evidence/pdf", json=hb)
    check("H15.http.pdf_renders", pdf.status_code == 200, str(pdf.status_code))
    rows = [e for e in _LEDGER.entries()
            if e.get("kind") == "preflight_run" and e.get("run_id") == hb.get("run_id")]
    check("H15.ledger.claim_recorded_unverified", len(rows) == 1
          and rows[0].get("claimed_approver") == "cto@corp"
          and rows[0].get("claimed_approver_verified") is False, str(rows))
    # the approver claim never unlocks promotion either (no token -> no approval)
    r = c.post("/api/preflight/promote", json={"bundle": hb, "approver": "cto@corp",
                                               "connector": "dry_run"})
    check("H15.http.promote_denied", r.status_code == 403, f"{r.status_code}")


def authority_requires_approval() -> None:
    """YzNoXPaU: a zero-impact peering change is risk_tier=low yet authority HITL. The sealed
    record and the gate must both say a person has to approve it."""
    nbr = [{"device": "leaf-1", "vendor": "frr", "config": " neighbor 10.0.0.9 remote-as 65020",
            "grounded_commands": []}]
    low = None
    for lab in ("y", "z", "q", "w", "v", "u", "t", "s", "r", "p"):
        b = run_preflight("", backend=SimulatorBackend(), lab=lab, source="config_import",
                          imported_configs=nbr, operator="alice")
        if b["change"]["risk_tier"] == "low" and b["change"]["authority"]["required"] == "hitl":
            low = b
            break
    check("H16.found_low_risk_hitl_bundle", low is not None, "sim search found none")
    if low is None:
        return
    check("H16.pipeline.needs_approval_recorded", low["change"]["approval"]["required"] is True,
          str(low["change"]["approval"]))
    check("H16.pipeline.verdict_needs_approval", low["verdict"]["decision"] == "needs_approval",
          str(low["verdict"]))

    def forced(required: str) -> dict:
        """The same change as a (hypothetical) ship_ready/low bundle with the given authority,
        re-sealed -- exercises the GATE rule on its own, independent of the pipeline."""
        f = copy.deepcopy(low)
        f["verdict"] = {"decision": "ship_ready", "reason": "forced"}
        f["change"]["approval"] = {"required": False, "granted_by": None, "granted_utc": None}
        f["change"]["authority"]["required"] = required
        f["change"]["authority"]["effective"] = required
        f["integrity"]["sha256"] = compute_sha256(f)
        return f

    kw = dict(connector_is_live=False, allow_live=False)
    os.environ["AEGIS_APPROVE_KEY"] = KEY
    try:
        for req in ("hitl", "hotl"):
            f = forced(req)
            d = gate.evaluate(f, approver=None, approval_token=None, **kw)
            check(f"H16.gate.{req}_without_approval_denied", not d.allowed
                  and req.upper() in d.reason and "approval" in d.reason, f"{d.allowed} {d.reason}")
            d = gate.evaluate(f, approver="bob", approval_token="junk", **kw)
            check(f"H16.gate.{req}_random_token_denied", not d.allowed, d.reason)
            tok = mint_token_for_bundle("bob", f, ttl_sec=600)
            d = gate.evaluate(f, approver="bob", approval_token=tok, **kw)
            check(f"H16.gate.{req}_verified_approval_allowed", d.allowed
                  and d.approval_method == "hmac-sha256", f"{d.allowed} {d.reason}")
            tok_a = mint_token_for_bundle("alice", f, ttl_sec=600)
            d = gate.evaluate(f, approver="alice", approval_token=tok_a, **kw)
            check(f"H16.gate.{req}_self_approval_denied", not d.allowed
                  and "separation of duties" in d.reason, f"{d.allowed} {d.reason}")
        # control: AUTO needs no approval; BLOCK stays a ceiling denial
        d = gate.evaluate(forced("auto"), approver=None, approval_token=None, **kw)
        check("H16.gate.auto_needs_no_approval", d.allowed, d.reason)
        d = gate.evaluate(forced("block"), approver=None, approval_token=None, **kw)
        check("H16.gate.block_still_ceiling_denied", not d.allowed
              and "self-escalation" in d.reason.lower(), d.reason)
    finally:
        os.environ.pop("AEGIS_APPROVE_KEY", None)


def main() -> int:
    airgap_default()
    rejections_ledgered()
    siem_anchor()
    peer_as_policy()
    offline_cli()
    gate_and_ledger()
    production_startup()
    evidence_honesty()
    http_contract()
    runtime_approver_not_granted()
    authority_requires_approval()
    if FAILS:
        print("\n=== HARDENING TEST: FAIL ===")
        for f in FAILS:
            print("  -", f)
        return 1
    print(f"\n=== HARDENING TEST: PASS ({CHECKS} checks) ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
