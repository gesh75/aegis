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
  F1  firewall snapshot (Juniper SRX fw1 + Palo Alto fw2, tests/fixtures/batfish/firewall)
      parses; fw1 is a junos-set-merge, fw2 a full-config replace
  F2  firewall_policy untrust→trust deny: pass → FAIL on both vendors (a temp-vendor permit
      rule) — regressions
  F3  nat: SRX web VIP DNAT pass → FAIL (pool retargeted to 10.2.0.99) — regression
  F4  no false regressions: SRX trust→untrust allow, SRX and PAN source NAT stay pass

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

    firewall()

    if FAILS:
        print("\n=== BATFISH LIVE TEST: FAIL ===")
        for f in FAILS:
            print("  -", f)
        return 1
    print(f"\n=== BATFISH LIVE TEST: PASS ({CHECKS} checks against a real Batfish) ===")
    return 0


def firewall() -> None:
    from ..core.intents import load_intents
    from ..core.intents.runner import run_intents

    fw = os.path.join(FIX, "firewall")
    os.environ["AEGIS_BATFISH_SNAPSHOT_DIR"] = os.path.join(fw, "reference")
    intents = load_intents(os.path.join(fw, "intents.json"))
    configs = [
        {"device": "fw1", "vendor": "junos",
         "config": open(os.path.join(fw, "candidate_fw1.set"), encoding="utf-8").read()},
        {"device": "fw2", "vendor": "panos",
         "config": open(os.path.join(fw, "candidate_fw2.cfg"), encoding="utf-8").read()},
    ]
    rec = run_intents(intents, configs)
    print(json.dumps(rec, indent=2)[:8000])
    by = {r["id"]: r for r in rec["results"]}
    check("F1.engine", rec["engine"] == "batfish", rec["engine"])
    check("F1.fidelity", bool(rec.get("fidelity") and rec["fidelity"]["ok"]),
          str(rec.get("fidelity")))
    modes = {m["device"]: m["mode"] for m in rec["snapshot"].get("merge", [])}
    check("F1.merge_modes", modes == {"fw1": "junos-set-merge", "fw2": "replace"}, str(modes))
    for iid in ("srx-untrust-cannot-reach-trust", "pan-untrust-cannot-reach-trust",
                "srx-web-vip-dnat"):
        r = by.get(iid, {})
        check(f"F2.{iid}", r.get("before") == "pass" and r.get("status") == "fail"
              and r.get("regression") is True, json.dumps(r))
    check("F3.dnat_names_wrong_target", "10.2.0.99" in json.dumps(by.get("srx-web-vip-dnat")),
          json.dumps(by.get("srx-web-vip-dnat")))
    for iid in ("srx-trust-reaches-untrust-https", "srx-inside-snat", "pan-inside-snat"):
        r = by.get(iid, {})
        check(f"F4.{iid}", r.get("before") == "pass" and r.get("status") == "pass",
              json.dumps(r))
    check("F4.regression_count", rec["regressions"] == 3, str(rec["regressions"]))
    if any(f.startswith(("F2.", "F4.")) for f in FAILS):
        _explain_firewall(fw)


def _explain_firewall(fw: str) -> None:
    """Diagnostics only: print the full Batfish traces for the untrust→trust flows on the
    REFERENCE snapshot, so a failure shows which hop/filter let the flow through."""
    from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints
    from ..core.intents.batfish_oracle import BatfishSnapshots
    from ..core.intents.snapshot import read_base

    ref = {f"configs/{k}.cfg": v for k, v in read_base(os.path.join(fw, "reference")).items()}
    with BatfishSnapshots(os.environ["AEGIS_BATFISH_HOST"], "aegis-diag", None, ref) as (_, o):
        bf, snap = o.bf, o.snapshot
        print("\n--- DIAG: parse warnings ---")
        try:
            print(bf.q.parseWarning().answer(snapshot=snap).frame().to_string()[:3000])
        except Exception as exc:  # noqa: BLE001
            print("parseWarning failed:", exc)
        for start, src, dst in (("@enter(fw1[ge-0/0/1.0])", "203.0.113.2", "10.1.0.0"),
                                ("@enter(fw1[ge-0/0/1.0])", "203.0.113.2", "10.1.0.5"),
                                ("@enter(fw2[ethernet1/2])", "198.51.100.2", "10.11.0.5")):
            print(f"\n--- DIAG: traceroute {start} {src}->{dst} tcp/80 ---")
            try:
                fr = bf.q.traceroute(startLocation=start, headers=HeaderConstraints(
                    srcIps=src, dstIps=dst, ipProtocols=["TCP"], dstPorts="80")
                ).answer(snapshot=snap).frame()
                for _, row in fr.iterrows():
                    for t in row["Traces"]:
                        print(str(t)[:2500])
            except Exception as exc:  # noqa: BLE001
                print("traceroute failed:", exc)
        for node, iface, dst in (("fw1", "ge-0/0/1.0", "10.1.0.0/24"),
                                 ("fw2", "ethernet1/2", "10.11.0.0/24")):
            print(f"\n--- DIAG: reachability SUCCESS {node}[{iface}] -> {dst} ---")
            try:
                fr = bf.q.reachability(
                    pathConstraints=PathConstraints(startLocation=f"@enter({node}[{iface}])"),
                    headers=HeaderConstraints(dstIps=dst, ipProtocols=["TCP"]),
                    actions="SUCCESS").answer(snapshot=snap).frame()
                for _, row in fr.head(3).iterrows():
                    print("FLOW", row["Flow"])
                    print(str(row["Traces"][0])[:2500])
            except Exception as exc:  # noqa: BLE001
                print("reachability failed:", exc)


if __name__ == "__main__":
    sys.exit(main())
