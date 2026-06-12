"""SOC 2 (AICPA Trust Services Criteria).

Change management is the criterion AEGIS maps to: every change is validated in a twin
before it can be promoted.
"""
from __future__ import annotations
from ._base import ComplianceSignal, control, PASS, NA, PROCESS_MAPPED

FRAMEWORK = "soc2"


def evaluate(sig: ComplianceSignal) -> list[dict]:
    # CC8.1 — Change Management: changes are authorized, designed, tested, approved.
    # Only assert twin validation when a converged twin run is actually recorded.
    twin_ok = sig.twin_tested() and sig.twin_converged()
    return [control(
        FRAMEWORK, "CC8.1",
        PASS if twin_ok else NA,
        "change validated via preflight digital-twin run before deployment; "
        "promotion gated on human approval" if twin_ok
        else "no converged twin run recorded — change testing not "
             "demonstrable for this run",
        PROCESS_MAPPED)]


SELF_TEST = [
    ({"configs": [{"device": "d", "vendor": "frr", "config": "# add vlan 10",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []},
      "twin": {"converged": True}},
     "CC8.1", PASS),
]
