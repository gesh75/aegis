"""OSCAL AR + CAB export contract.

Honesty rules this suite locks:

  O1  to_oscal wraps assessment-results with oscal-version 1.1.2
  O2  metadata.remarks admits this is not a FedRAMP package
  O3  a plaintext-auth intent produces at least one finding (PCI 8.3.2)
  O4  a clean intent produces zero findings
  C1  to_cab kind is aegis-cab-v1
  C2  rollback.verified_in_twin is always False
  C3  blocked verdict never claims intents_that_hold
  H1  HTTP export 400 without sha, 422 on tamper, 200 JSON on a valid bundle

Reads the canonical bundle shape: validation.compliance, change.intent, created_utc.

Usage:  python3 -m aegis.tests.oscal_test
"""
from __future__ import annotations
import copy
import sys

from ..core.orchestrator.pipeline import run_preflight
from ..core.backends.simulator import SimulatorBackend
from ..evidence.oscal import to_oscal, OSCAL_VERSION, EXPORT_KIND
from ..evidence.cab import to_cab, CAB_KIND
from ..serve import app

FAILS: list[str] = []
CHECKS = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(f"{name}: {detail}")


def _run(intent: str) -> dict:
    return run_preflight(intent, backend=SimulatorBackend(), lab="single",
                         frameworks=["pci_dss_v4"], operator="ci")


def _findings(ar: dict) -> list:
    return ((ar.get("assessment-results") or {}).get("results") or [{}])[0].get("findings") or []


def _fail_rows(bundle: dict) -> list:
    rows = ((bundle.get("validation") or {}).get("compliance") or [])
    return [c for c in rows if c.get("status") == "fail"]


def main() -> int:
    clean = _run("add vlan 10 to leaf-1")
    bad = _run("add vlan 40 with plaintext bgp authentication-key abc123")

    ar = to_oscal(clean)
    check("oscal.kind", ar.get("kind") == EXPORT_KIND, str(ar.get("kind")))
    meta = (ar.get("assessment-results") or {}).get("metadata") or {}
    check("oscal.version", meta.get("oscal-version") == OSCAL_VERSION, str(meta.get("oscal-version")))
    remarks = str(meta.get("remarks", ""))
    check("oscal.not_fedramp", "not a fedramp" in remarks.lower(), remarks[:80])
    check("oscal.uuid", (ar.get("assessment-results") or {}).get("uuid") == clean["run_id"],
          str((ar.get("assessment-results") or {}).get("uuid")))
    clean_findings = _findings(ar)
    check("oscal.clean_no_findings", len(clean_findings) == 0,
          f"findings={len(clean_findings)}")

    bad_ar = to_oscal(bad)
    bad_findings = _findings(bad_ar)
    fail_rows = _fail_rows(bad)
    check("oscal.plaintext_fail_rows", len(fail_rows) >= 1,
          f"validation.compliance fail rows={len(fail_rows)}")
    check("oscal.plaintext_findings",
          len(bad_findings) == len(fail_rows) and len(bad_findings) >= 1,
          f"findings={len(bad_findings)} fail_rows={len(fail_rows)}")
    titles = " ".join(f.get("title", "") for f in bad_findings)
    check("oscal.plaintext_pci_832", "8.3.2" in titles, titles)

    cab = to_cab(clean)
    check("cab.kind", cab.get("kind") == CAB_KIND, str(cab.get("kind")))
    check("cab.rollback_unverified", cab.get("rollback", {}).get("verified_in_twin") is False,
          str(cab.get("rollback")))
    check("cab.honesty", "not executed" in str(cab.get("rollback", {}).get("honesty", "")),
          str(cab.get("rollback", {}).get("honesty")))
    check("cab.what_changed", isinstance(cab.get("what_changed"), list) and cab["what_changed"],
          str(cab.get("what_changed"))[:80])
    check("cab.rollback_steps", isinstance(cab.get("rollback", {}).get("steps"), list)
          and cab["rollback"]["steps"], str(cab.get("rollback", {}).get("steps"))[:80])

    bad_cab = to_cab(bad)
    check("cab.blocked_no_hold", bad_cab.get("intents_that_hold") is False,
          f"decision={bad['verdict']['decision']} hold={bad_cab.get('intents_that_hold')}")
    check("cab.blocked_has_fails", isinstance(bad_cab.get("compliance_fails"), list)
          and len(bad_cab["compliance_fails"]) >= 1,
          str(len(bad_cab.get("compliance_fails") or [])))

    app.testing = True
    c = app.test_client()

    r = c.post("/api/preflight/evidence/oscal", json={"not": "a bundle"})
    check("http.oscal.400", r.status_code == 400, str(r.status_code))
    r = c.post("/api/preflight/evidence/cab", json={"not": "a bundle"})
    check("http.cab.400", r.status_code == 400, str(r.status_code))

    tampered = copy.deepcopy(clean)
    tampered["change"]["risk_tier"] = "low"
    r = c.post("/api/preflight/evidence/oscal", json=tampered)
    check("http.oscal.422", r.status_code == 422, str(r.status_code))
    r = c.post("/api/preflight/evidence/cab", json=tampered)
    check("http.cab.422", r.status_code == 422, str(r.status_code))

    r = c.post("/api/preflight/evidence/oscal", json=clean)
    body = r.get_json() if r.status_code == 200 else {}
    check("http.oscal.200", r.status_code == 200, f"{r.status_code} {r.get_data(as_text=True)[:120]}")
    check("http.oscal.ctype", r.mimetype == "application/json", r.mimetype)
    check("http.oscal.shape", (body.get("assessment-results") or {}).get("uuid") == clean["run_id"],
          str((body.get("assessment-results") or {}).get("uuid")))
    check("http.oscal.kind", body.get("kind") == EXPORT_KIND, str(body.get("kind")))

    r = c.post("/api/preflight/evidence/cab", json=clean)
    body = r.get_json() if r.status_code == 200 else {}
    check("http.cab.200", r.status_code == 200, f"{r.status_code}")
    check("http.cab.kind", body.get("kind") == CAB_KIND, str(body.get("kind")))

    if FAILS:
        print("\n=== OSCAL/CAB EXPORT TEST: FAIL ===")
        for f in FAILS:
            print("  -", f)
        return 1
    print(f"\n=== OSCAL/CAB EXPORT TEST: PASS ({CHECKS} checks) ===")
    return 0


def test_oscal_cab() -> None:
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())
