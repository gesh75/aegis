"""Stress + validity test for the evidence-PDF renderer.

Generates many sim bundles (covering all three verdicts + compliance fails) and renders
each to PDF, asserting every output is a structurally valid, non-trivial PDF and that the
renderer never throws. Run: python3 -m aegis.tests.pdf_test [N]
"""
from __future__ import annotations
import random
import sys
import time

from ..core.orchestrator.pipeline import run_preflight
from ..core.backends.simulator import SimulatorBackend
from ..evidence.pdf import render_pdf

INTENTS = [
    "add vlan {n} to leaf-{n} and peer bgp",
    "add vlan {n} with plaintext bgp authentication-key abc123",  # -> blocked/PCI fail
    "enable ospf area 0 on edge-{n}",
    "shut interface ethernet-1/{n}",
    "migrate vlan {n} to evpn on leaf devices",
]
LABS = ["clos-evpn", "minimal", "edge-slice"]
FRAMEWORKS = [["pci_dss_v4"], ["pci_dss_v4", "soc2", "nist_800-53"]]


def run(n: int = 1500) -> dict:
    rng = random.Random(99)
    res = {"runs": 0, "pdf_ok": 0, "bad_header": 0, "too_small": 0, "errors": 0,
           "verdicts": {}}
    sizes = []
    fails = []
    for i in range(n):
        intent = rng.choice(INTENTS).format(n=rng.randint(1, 9))
        b = run_preflight(intent, backend=SimulatorBackend(),
                          lab=rng.choice(LABS), frameworks=rng.choice(FRAMEWORKS),
                          approver=("noc-lead" if rng.random() < 0.4 else None))
        res["verdicts"][b["verdict"]["decision"]] = \
            res["verdicts"].get(b["verdict"]["decision"], 0) + 1
        res["runs"] += 1
        try:
            pdf = render_pdf(b)
        except Exception as e:  # noqa: BLE001
            res["errors"] += 1
            fails.append(f"{type(e).__name__}: {e}")
            continue
        if not pdf.startswith(b"%PDF"):
            res["bad_header"] += 1; fails.append(f"bad header {b['run_id']}"); continue
        if len(pdf) < 1500 or b"%%EOF" not in pdf[-1024:]:
            res["too_small"] += 1; fails.append(f"truncated {b['run_id']}"); continue
        sizes.append(len(pdf))
        res["pdf_ok"] += 1
    res["avg_pdf_bytes"] = int(sum(sizes) / len(sizes)) if sizes else 0
    res["sample_failures"] = fails[:5]
    return res


def passed(s: dict) -> bool:
    return (s["pdf_ok"] == s["runs"] and s["errors"] == 0
            and s["bad_header"] == 0 and s["too_small"] == 0
            and len(s["verdicts"]) >= 2)  # at least 2 verdict types exercised


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1500
    t0 = time.perf_counter()
    s = run(n)
    s["wall_sec"] = round(time.perf_counter() - t0, 2)
    import json
    print(json.dumps(s, indent=2))
    print("\n=== PDF TEST:", "PASS" if passed(s) else "FAIL", "===")
    sys.exit(0 if passed(s) else 1)
