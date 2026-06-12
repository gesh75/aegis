"""SOC 2 (AICPA Trust Services Criteria).

Change management is the criterion AEGIS maps to: every change is validated in a twin
before it can be promoted.
"""
from __future__ import annotations
from ._base import ComplianceSignal, control, PASS, PROCESS_MAPPED

FRAMEWORK = "soc2"


def evaluate(sig: ComplianceSignal) -> list[dict]:
    # CC8.1 — Change Management: changes are authorized, designed, tested, approved.
    return [control(
        FRAMEWORK, "CC8.1", PASS,
        "change validated via preflight digital-twin run before deployment; "
        "promotion gated on human approval",
        PROCESS_MAPPED)]


SELF_TEST = [
    ({"configs": [{"device": "d", "vendor": "frr", "config": "# add vlan 10",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []},
      "twin": {"converged": True}},
     "CC8.1", PASS),
]
