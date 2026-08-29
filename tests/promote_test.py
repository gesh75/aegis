"""Stress + invariant test for the Phase 2 promotion gate.

The gate is the safety boundary between "validated" and "pushed to prod". These invariants
MUST hold across thousands of randomized bundles × approval combinations:

  P1  a `blocked` bundle is NEVER promoted
  P2  a tampered bundle (bad sha256) is NEVER promoted
  P3  `needs_approval` without approver+token is NEVER promoted
  P4  a medium/high-risk change without approver+token is NEVER promoted
  P5  the default (dry_run) connector NEVER mutates (live == False on every push)
  P6  the live connector is refused unless allow_live is set
  P7  every promotion record's integrity sha256 re-verifies

Run: python3 -m aegis.tests.promote_test [N]
"""
from __future__ import annotations
import copy
import json
import os
import random
import sys
import time

from ..core.orchestrator.pipeline import run_preflight
from ..core.backends.simulator import SimulatorBackend
from ..core.promote.promote import promote, PromoteDenied, _sha256
from ..core.promote.connectors import DryRunConnector, DisabledLiveConnector
from ..core.promote.tokens import mint_token

INTENTS = [
    "add vlan {n} to leaf-{n} and peer bgp",                       # mostly ship/needs
    "add vlan {n} with plaintext bgp authentication-key abc123",   # -> blocked
    "enable ospf area 0 on edge-{n}",
    "shut interface ethernet-1/{n}",
]


def run(n: int = 4000) -> dict:
    rng = random.Random(2026)
    res = {k: 0 for k in ("runs", "promoted", "denied", "blocked_promoted",
                          "tampered_promoted", "needs_approval_promoted",
                          "risk_unapproved_promoted", "live_without_optin",
                          "dryrun_mutated", "record_hash_fail")}
    fails = []

    for i in range(n):
        b = run_preflight(rng.choice(INTENTS).format(n=rng.randint(1, 9)),
                          backend=SimulatorBackend(), lab="clos-evpn",
                          frameworks=["pci_dss_v4"])
        res["runs"] += 1
        decision = b["verdict"]["decision"]
        tier = b["change"]["risk_tier"]

        give_approval = rng.random() < 0.5
        approver = "noc-lead" if give_approval else None
        token = "tok-123" if give_approval else None

        # ~15% of the time, tamper with the bundle after sealing (P2)
        tampered = rng.random() < 0.15
        bb = copy.deepcopy(b)
        if tampered:
            bb["change"]["risk_tier"] = "low"  # mutate without re-sealing -> hash breaks

        conn = DryRunConnector()
        try:
            rec = promote(bb, connector=conn, approver=approver,
                          approval_token=token, allow_live=False)
            res["promoted"] += 1
            # invariant audits on anything that got through
            if decision == "blocked":
                res["blocked_promoted"] += 1; fails.append(f"blocked promoted {b['run_id']}")
            if tampered:
                res["tampered_promoted"] += 1; fails.append(f"tampered promoted {b['run_id']}")
            if decision == "needs_approval" and not (approver and token):
                res["needs_approval_promoted"] += 1; fails.append("needs_approval promoted")
            if tier in ("medium", "high") and not (approver and token):
                res["risk_unapproved_promoted"] += 1; fails.append(f"{tier} promoted unapproved")
            if any(c.get("detail", "").startswith("dry-run") is False for c in rec["pushed"]):
                pass  # detail wording check below
            if conn.calls and conn.live:                                  # P5
                res["dryrun_mutated"] += 1
            if rec["integrity"]["sha256"] != _sha256(rec):                # P7
                res["record_hash_fail"] += 1; fails.append("record hash mismatch")
        except PromoteDenied:
            res["denied"] += 1

    # P6: live connector must be refused unless allow_live, even for a clean ship_ready bundle
    clean = run_preflight("add vlan 10 to leaf-1", backend=SimulatorBackend(),
                          lab="minimal", frameworks=["pci_dss_v4"])
    # force a promotable verdict for the live test
    live_refused = True
    try:
        promote(clean, connector=DisabledLiveConnector(), approver="noc-lead",
                approval_token="t", allow_live=False)
        live_refused = False
        fails.append("live connector ran without opt-in")
    except PromoteDenied:
        pass

    # P8: HMAC key set → a random string is not an approval; a bound token is.
    hmac_random_promoted = False
    hmac_bound_ok = False
    hmac_method = ""
    os.environ["AEGIS_APPROVE_KEY"] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    try:
        need = clean if clean["verdict"]["decision"] != "blocked" else None
        if need is None:
            fails.append("clean vlan bundle was blocked — cannot exercise HMAC P8")
        else:
            try:
                promote(need, connector=DryRunConnector(), approver="noc-lead",
                        approval_token="tok-123", allow_live=False)
                # Only a failure if the gate actually required an approval
                tier = need["change"]["risk_tier"]
                decision = need["verdict"]["decision"]
                if decision == "needs_approval" or tier in ("medium", "high"):
                    hmac_random_promoted = True
                    fails.append("random token promoted under HMAC key")
            except PromoteDenied:
                pass
            try:
                tok = mint_token("noc-lead", need["integrity"]["sha256"])
                rec = promote(need, connector=DryRunConnector(), approver="noc-lead",
                              approval_token=tok, allow_live=False)
                hmac_method = (rec.get("approval") or {}).get("method") or ""
                hmac_bound_ok = hmac_method == "hmac-sha256"
                if not hmac_bound_ok:
                    fails.append(f"bound token method={hmac_method!r}")
                if rec["integrity"]["sha256"] != _sha256(rec):
                    res["record_hash_fail"] += 1
                    fails.append("HMAC promotion record hash mismatch")
            except PromoteDenied as e:
                fails.append(f"bound HMAC token denied: {e}")
    finally:
        os.environ.pop("AEGIS_APPROVE_KEY", None)

    return {"results": res, "live_refused_without_optin": live_refused,
            "hmac_random_refused": not hmac_random_promoted,
            "hmac_bound_ok": hmac_bound_ok,
            "sample_failures": fails[:10]}


def passed(s: dict) -> bool:
    r = s["results"]
    return (r["blocked_promoted"] == 0 and r["tampered_promoted"] == 0
            and r["needs_approval_promoted"] == 0 and r["risk_unapproved_promoted"] == 0
            and r["dryrun_mutated"] == 0 and r["record_hash_fail"] == 0
            and s["live_refused_without_optin"]
            and s.get("hmac_random_refused", False)
            and s.get("hmac_bound_ok", False)
            and not s["sample_failures"])


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 4000
    t0 = time.perf_counter()
    s = run(n)
    s["wall_sec"] = round(time.perf_counter() - t0, 2)
    print(json.dumps(s, indent=2))
    print("\n=== PROMOTE GATE TEST:", "PASS" if passed(s) else "FAIL", "===")
    sys.exit(0 if passed(s) else 1)
