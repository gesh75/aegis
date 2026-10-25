"""LIVE Batfish contract — runs against a real batfish/allinone service (CI `batfish` job).

Proves the pybatfish oracle end to end on a real Cisco IOS snapshot
(tests/fixtures/batfish, see its README):

  L1  engine is batfish, both snapshots parse (fidelity ok), reference was used
  L2  guest-cannot-reach-cde: pass before → FAIL after (SSH permit above the deny) — regression
  L3  guest-can-reach-web:    pass before → pass after (no false regression)
  L4  no-undefined-references and no-shadowed-acl-lines: pass → FAIL — regressions
  L5  full pipeline (config_import) → verdict blocked, reason names the regressions, the
      sealed bundle carries the differential and integrity-verifies
  L6  a clean candidate (identical to reference) → all intents pass, nothing blocked by intents

Without pybatfish/AEGIS_BATFISH_HOST it SKIPS (exit 0) — unless AEGIS_REQUIRE_BATFISH=1
(set in CI), where a skip is a failure.

Usage:  AEGIS_BATFISH_HOST=127.0.0.1 python3 -m aegis.tests.batfish_live_test
"""
from __future__ import annotations

import json
import os
import sys

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "batfish")
FAILS: list[str] = []
CHECKS = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(f"{name}: {detail}")


def _skip(why: str) -> int:
    if os.environ.get("AEGIS_REQUIRE_BATFISH") == "1":
        print(f"=== BATFISH LIVE TEST: FAIL (required but unavailable: {why}) ===")
        return 1
    print(f"=== BATFISH LIVE TEST: SKIP ({why}) ===")
    return 0


def main() -> int:
    try:
        import pybatfish  # noqa: F401
    except ImportError:
        return _skip("pybatfish not installed")
    if not (os.environ.get("AEGIS_BATFISH_HOST") or "").strip():
        return _skip("AEGIS_BATFISH_HOST not set")
    os.environ["AEGIS_BATFISH_SNAPSHOT_DIR"] = os.path.join(FIX, "reference")

    from ..core.intents import load_intents
    from ..core.intents.runner import run_intents
    from ..core.orchestrator.pipeline import run_preflight
    from ..core.backends.simulator import SimulatorBackend
    from ..evidence.bundler import verify

    intents = load_intents(os.path.join(FIX, "intents.json"))
    candidate = open(os.path.join(FIX, "candidate_r1.cfg"), encoding="utf-8").read()
    reference = open(os.path.join(FIX, "reference", "configs", "r1.cfg"), encoding="utf-8").read()

    rec = run_intents(intents, [{"device": "r1", "vendor": "ios", "config": candidate}])
    print(json.dumps(rec, indent=2)[:6000])
    by = {r["id"]: r for r in rec["results"]}
    check("L1.engine", rec["engine"] == "batfish", rec["engine"])
    check("L1.fidelity", bool(rec.get("fidelity") and rec["fidelity"]["ok"]), str(rec.get("fidelity")))
    check("L1.reference_used", rec["snapshot"].get("reference") is True, str(rec["snapshot"]))
    cde = by.get("guest-cannot-reach-cde", {})
    check("L2.cde_regression", cde.get("before") == "pass" and cde.get("status") == "fail"
          and cde.get("regression") is True, json.dumps(cde))
    check("L2.cde_example_flow", bool(cde.get("examples")), json.dumps(cde))
    web = by.get("guest-can-reach-web", {})
    check("L3.web_still_allowed", web.get("before") == "pass" and web.get("status") == "pass",
          json.dumps(web))
    for iid in ("no-undefined-references", "no-shadowed-acl-lines"):
        r = by.get(iid, {})
        check(f"L4.{iid}", r.get("before") == "pass" and r.get("status") == "fail"
              and r.get("regression") is True, json.dumps(r))
    check("L4.regression_count", rec["regressions"] == 3, str(rec["regressions"]))

    sim = SimulatorBackend(converge_fail_rate=0.0, batfish_error_rate=0.0)
    b = run_preflight("", backend=sim, lab="single", source="config_import", operator="ci",
                      imported_configs=[{"device": "r1", "vendor": "ios", "config": candidate}],
                      intents=intents)
    check("L5.blocked", b["verdict"]["decision"] == "blocked"
          and "3 regression" in b["verdict"]["reason"], b["verdict"]["reason"])
    check("L5.sealed_differential", b["validation"]["intents"]["regressions"] == 3 and verify(b))

    clean = run_intents(intents, [{"device": "r1", "vendor": "ios", "config": reference}])
    check("L6.clean_all_pass", all(r["status"] == "pass" for r in clean["results"])
          and clean["regressions"] == 0, json.dumps(clean["results"])[:1500])

    if FAILS:
        print("\n=== BATFISH LIVE TEST: FAIL ===")
        for f in FAILS:
            print("  -", f)
        return 1
    print(f"\n=== BATFISH LIVE TEST: PASS ({CHECKS} checks against a real Batfish) ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
