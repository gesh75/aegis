"""Contract tests for HttpBackend parsers.

These feed RESPONSE FIXTURES shaped exactly like the real DCN_Network_Tool :5757
handlers (extracted from src/app.py + src/tests on 2026-05-28) through the pure parser
functions and assert they map cleanly onto the Backend protocol types.

This verifies the PARSING contract without a live server. The remaining live step is
network reachability + the three net-new twin endpoints (documented in http_backend.py).

Run:  python3 -m aegis.tests.contract_test
"""
from __future__ import annotations
import json
import sys

from ..core.backends.http_backend import (
    parse_batfish, parse_nornir_bgp, parse_pyats_diff, parse_configgen)

# ── fixtures: exact shapes returned by the real handlers ─────────────────

BATFISH_BAD = {  # plaintext auth + missing export policy
    "errors": 2, "warnings": 1, "passes": 9,
    "findings": [
        {"severity": "error", "message": "ERROR: plaintext BGP authentication-key"},
        {"severity": "error", "message": "ERROR: Missing export policy on external BGP peer"},
        {"severity": "warn",  "message": "WARN: hold-time below recommended"},
        {"severity": "pass",  "message": "PASS: BFD configured"},
    ],
    "llm_summary": "2 critical issues found.",
}
BATFISH_CLEAN = {"errors": 0, "warnings": 0, "passes": 11, "findings": [
    {"severity": "pass", "message": "PASS: md5 authentication present"}],
    "llm_summary": "No critical issues found."}

NORNIR_OK = {
    "task": "BGP Health", "site": "de-fra", "devices": 6, "workers": 50,
    "elapsed": 3.2, "ok": 6, "warn": 0, "error": 0,
    "results": [{"hostname": f"de-fra-core-0{i}", "status": "ok",
                 "output": "65010   Established   1245", "elapsed": 0.4}
                for i in range(1, 7)],
}
NORNIR_DEGRADED = {
    "task": "BGP Health", "site": "de-fra", "devices": 6, "workers": 50,
    "elapsed": 3.4, "ok": 4, "warn": 1, "error": 1,
    "results": [
        {"hostname": "de-fra-core-01", "status": "ok",    "output": "Established 1245", "elapsed": 0.4},
        {"hostname": "de-fra-core-02", "status": "warn",  "output": "Idle",             "elapsed": 0.4},
        {"hostname": "de-fra-edge-01", "status": "error", "output": "Connection refused","elapsed": 0.4},
    ],
}
NORNIR_IPV6 = {
    "task": "BGP Health", "site": "de-fra", "devices": 1, "workers": 50,
    "elapsed": 0.4, "ok": 1, "warn": 0, "error": 0,
    "results": [{
        "hostname": "de-fra-core-01", "status": "ok", "elapsed": 0.4,
        "output": (
            "2001:db8::1 4 65001 10 10 0 0 0 00:10:00 42\n"
            "2001:0db8:0000:0001:0000:0000:0000:0002 4 65002 10 10 0 0 0 00:10:00 Estab"
            "2001:db8:0:1::2 4 65002 10 10 0 0 0 00:10:00 Estab"
        ),
    }],
}

PYATS_DIFF = {
    "hostname": "de-fra-core-01", "total_changes": 3,
    "diffs": [
        {"type": "interface", "name": "eth0", "pre": "up", "post": "up"},
        {"type": "bgp", "name": "10.0.0.2", "pre_up": True, "post_up": False},
        {"type": "bgp", "name": "10.0.0.3", "pre_up": True, "post_up": True},
    ],
}

LLM_CONFIGGEN = (
    "<think>ok</think>\n"
    '{"configs":[{"device":"leaf-2","vendor":"srlinux",'
    '"config":"set interface ethernet-1/2 vlan 40","grounded_commands":["set / interface"]},'
    '{"device":"leaf-3","vendor":"ceos","config":"vlan 40","grounded_commands":["vlan"]}]}'
)

FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        FAILS.append(f"{name}: {detail}")


def main() -> int:
    # batfish
    b = parse_batfish(BATFISH_BAD)
    check("batfish.errors", b["errors"] == 2, str(b))
    check("batfish.passes->passed", b["passed"] == 9, str(b))
    check("batfish.findings", len(b["findings"]) == 4 and "plaintext" in b["findings"][0])
    check("batfish.clean", parse_batfish(BATFISH_CLEAN)["errors"] == 0)

    # nornir bgp
    up, nodes, conv = parse_nornir_bgp(NORNIR_OK)
    check("nornir.ok.nodes", nodes == 6, f"nodes={nodes}")
    check("nornir.ok.converged", conv is True)
    check("nornir.ok.bgp_up", up >= 6, f"up={up}")
    up2, nodes2, conv2 = parse_nornir_bgp(NORNIR_DEGRADED)
    check("nornir.degraded.notconverged", conv2 is False, f"conv={conv2}")
    check("nornir.degraded.nodes", nodes2 == 6)
    ipv6_up, _, _ = parse_nornir_bgp(NORNIR_IPV6)
    check("nornir.ipv6.bgp_up", ipv6_up == 2, f"up={ipv6_up}")
    malformed_up, _, _ = parse_nornir_bgp({
        "devices": 1, "error": 1,
        "results": [{"status": "warn", "output": ":" * 20_000}],
    })
    check("nornir.malformed_ipv6.bgp_up", malformed_up == 0, f"up={malformed_up}")

    # pyats diff
    d = parse_pyats_diff(PYATS_DIFF)
    check("pyats.dropped", d["sessions_dropped"] == ["10.0.0.2"], str(d))
    check("pyats.affected", d["devices_affected"] == 3, str(d))
    check("pyats.routes_empty", d["routes_added"] == [] and d["routes_removed"] == [])

    # configgen (with qwen3 <think> preamble)
    cfgs = parse_configgen(LLM_CONFIGGEN, "clos-evpn")
    check("configgen.count", len(cfgs) == 2, str(cfgs))
    check("configgen.vendor", cfgs[0]["vendor"] == "srlinux")
    check("configgen.grounded", cfgs[0]["grounded_commands"] == ["set / interface"])
    # fail closed: unparseable LLM output must raise, never become a passing stub
    try:
        parse_configgen("not json at all", "single")
        garbage_raises = False
    except Exception as exc:  # noqa: BLE001
        garbage_raises = "generation_failed" in str(exc)
    check("configgen.garbage_fails_closed", garbage_raises)

    # show the typed results so the mapping is visible
    print(json.dumps({
        "batfish_bad": b,
        "nornir_ok": {"bgp_up": up, "nodes": nodes, "converged": conv},
        "nornir_degraded": {"bgp_up": up2, "nodes": nodes2, "converged": conv2},
        "pyats_diff": d,
        "configgen": cfgs,
    }, indent=2))

    if FAILS:
        print("\n=== CONTRACT TEST: FAIL ===")
        for f in FAILS:
            print("  -", f)
        return 1
    print(f"\n=== CONTRACT TEST: PASS ({4+4+3+4} checks) ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
