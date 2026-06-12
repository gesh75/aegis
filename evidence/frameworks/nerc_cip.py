"""NERC CIP-010 — Configuration Change Management & Vulnerability Assessments.

Maps three CIP-010-4 Table R1 parts that AEGIS's change->twin->validate loop speaks to,
for changes affecting BES Cyber Systems (and associated EACMS/PACS/PCA):

  R1.1 — Develop a baseline configuration.           (process-mapped)
  R1.2 — Authorize and document changes that deviate from the existing baseline.
                                                       (process-mapped: twin-tested + gated)
  R1.4 — Following the change, verify that required cyber security controls in CIP-005 and
         CIP-007 are not adversely affected.          (config-checked)

R1.4 is the only one AEGIS can actually attest from artifacts: it PASSES only when static
analysis (Batfish) is clean AND the twin/diff shows no BGP/ESP sessions were dropped — a
direct, observable proxy for "required cyber security controls were not adversely affected".
R1.1 and R1.2 are process-mapped: AEGIS records the proposed baseline and runs the change
through a digital twin before any human-gated promotion, but the formal baseline document
and the change authorization record live in the entity's change-management system, not here.

HONESTY: evidence describes THIS run only — never that the entity is NERC-CIP certified.
Control identifiers verified against NERC CIP-010-4 Table R1 (nerc.com, 2026-06-02).
"""
from __future__ import annotations
from ._base import ComplianceSignal, control, PASS, FAIL, NA, CONFIG_CHECKED, PROCESS_MAPPED

FRAMEWORK = "nerc_cip"


def evaluate(sig: ComplianceSignal) -> list[dict]:
    out: list[dict] = []

    # R1.1 — Develop a baseline configuration (OS/firmware, software, ports, patches).
    # AEGIS captures the proposed config text as the candidate baseline; the authoritative
    # baseline record is maintained in the entity's asset/change-management system.
    out.append(control(
        FRAMEWORK, "CIP-010-R1.1", PASS,
        "proposed config captured as candidate baseline for the affected device(s); "
        "authoritative baseline record maintained in entity CMDB",
        PROCESS_MAPPED))

    # R1.2 — Authorize and document changes that deviate from the existing baseline.
    # AEGIS validates the deviation in a digital twin and emits a sealed evidence bundle;
    # promotion to production is gated on human authorization (the documented authorization
    # itself is recorded in the entity's change-management system).
    twin_ok = sig.twin_tested() and sig.twin_converged()
    out.append(control(
        FRAMEWORK, "CIP-010-R1.2",
        PASS if twin_ok else NA,
        "deviation from baseline validated in digital twin and sealed in evidence bundle; "
        "production promotion gated on human authorization" if twin_ok
        else "no converged twin run recorded — baseline-deviation testing "
             "not demonstrable for this run",
        PROCESS_MAPPED))

    # R1.4 — Following the change, verify required CIP-005/CIP-007 controls are not adversely
    # affected. Config-checked: PASS only when static analysis is clean AND no sessions were
    # dropped in the twin (dropped BGP/ESP sessions = a CIP-005/CIP-007 control degraded).
    clean = sig.batfish_clean()
    dropped = sig.sessions_dropped()
    adverse = (not clean) or dropped
    if adverse:
        if not clean and dropped:
            why = (f"{sig.batfish_errors()} static-analysis error(s) and "
                   "session(s) dropped in twin")
        elif not clean:
            why = f"{sig.batfish_errors()} static-analysis error(s) post-change"
        else:
            why = "session(s) dropped in twin (CIP-005/CIP-007 control degraded)"
        out.append(control(
            FRAMEWORK, "CIP-010-R1.4", FAIL,
            f"post-change verification: {why}",
            CONFIG_CHECKED))
    else:
        out.append(control(
            FRAMEWORK, "CIP-010-R1.4", PASS,
            "post-change verification: static analysis clean and no sessions dropped in twin "
            "(required CIP-005/CIP-007 controls not adversely affected)",
            CONFIG_CHECKED))

    return out


SELF_TEST = [
    # Clean change, twin diff drops nothing -> R1.4 PASS (controls not adversely affected).
    ({"configs": [{"device": "de-fra-core-01", "vendor": "frr",
                   "config": "router bgp 65001\n neighbor 10.200.0.12 remote-as 65002",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 2, "findings": []},
      "diff": {"sessions_dropped": []}},
     "CIP-010-R1.4", PASS),

    # Batfish errors post-change -> R1.4 FAIL (adverse effect on required controls).
    ({"configs": [{"device": "de-fra-core-01", "vendor": "frr",
                   "config": "router bgp 65001\n neighbor 10.200.0.99 remote-as 65099",
                   "grounded_commands": []}],
      "batfish": {"errors": 3, "warnings": 1, "passed": 0, "findings": ["undefined peer"]},
      "diff": {"sessions_dropped": []}},
     "CIP-010-R1.4", FAIL),

    # Clean static analysis but the twin dropped a session -> R1.4 FAIL.
    ({"configs": [{"device": "uk-lon-core-01", "vendor": "frr",
                   "config": "no neighbor 10.200.0.11 remote-as 65001",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []},
      "diff": {"sessions_dropped": ["uk-lon-core-01<->de-fra-core-01"]}},
     "CIP-010-R1.4", FAIL),

    # Baseline authorization passes only when a converged twin run is recorded.
    ({"configs": [{"device": "de-fra-core-01", "vendor": "frr",
                   "config": "router bgp 65001\n neighbor 10.200.0.12 remote-as 65002",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 2, "findings": []},
      "twin": {"converged": True},
      "diff": {"sessions_dropped": []}},
     "CIP-010-R1.2", PASS),

    # No twin run recorded -> R1.2 NA (twin testing not demonstrable).
    ({"configs": [{"device": "de-fra-core-01", "vendor": "frr",
                   "config": "router bgp 65001\n neighbor 10.200.0.12 remote-as 65002",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 2, "findings": []},
      "diff": {"sessions_dropped": []}},
     "CIP-010-R1.2", NA),
]
