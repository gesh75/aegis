"""HIPAA Security Rule — 45 CFR Part 164, Subpart C (Tier 2).

Scope: covered entities and business associates that transmit electronic protected
health information (ePHI) over an electronic communications network. AEGIS maps three
Security Rule standards to a network change:

  - 164.312(e)(1) Transmission Security (Technical Safeguard) — CONFIG-CHECKED. The
    proposed config is inspected for plaintext / weak authentication material that would
    expose ePHI in transit; present => FAIL, otherwise PASS.
  - 164.308(a)(8) Evaluation (Administrative Safeguard) — PROCESS-MAPPED. The Security
    Rule requires a technical evaluation in response to operational changes; AEGIS
    performs that evaluation in the digital twin before deployment.
  - 164.312(b) Audit Controls (Technical Safeguard) — PROCESS-MAPPED. Requires
    mechanisms that record and examine system activity; AEGIS emits a sealed, hashed
    evidence record of this change.

HONESTY RULE: only Transmission Security is config-checked (we actually read the config).
The other two are process-mapped — satisfied by the AEGIS pipeline structure for THIS run
(twin-tested + deterministically verified + sealed evidence + human-gated promotion). None
of these rows assert the org is "HIPAA certified"; each describes only this single change.
"""
from __future__ import annotations
from ._base import (
    ComplianceSignal, control, PASS, FAIL, NA, CONFIG_CHECKED, PROCESS_MAPPED,
)

FRAMEWORK = "hipaa"


def evaluate(sig: ComplianceSignal) -> list[dict]:
    out: list[dict] = []

    # 164.312(e)(1) — Transmission Security (config-checked).
    # Guard ePHI in transit: plaintext / weak credentials on the change FAIL the control.
    # When the change touches no routed/transit-bearing config the control does not apply.
    weak_auth = sig.has_plaintext_secret()
    transmits = sig.has_routing_proto()
    if weak_auth:
        out.append(control(
            FRAMEWORK, "164.312(e)(1)", FAIL,
            "plaintext/weak authentication material in generated config — "
            "ePHI in transit not guarded against unauthorized access",
            CONFIG_CHECKED))
    elif transmits:
        out.append(control(
            FRAMEWORK, "164.312(e)(1)", PASS,
            "no plaintext/weak authentication material on transit-bearing config "
            "(routing protocol session); ePHI transmission safeguard intact",
            CONFIG_CHECKED))
    else:
        out.append(control(
            FRAMEWORK, "164.312(e)(1)", NA,
            "change carries no routed/transit-bearing config — transmission-security "
            "safeguard not applicable to this change",
            CONFIG_CHECKED))

    # 164.308(a)(8) — Evaluation (process-mapped).
    # Periodic technical evaluation in response to operational changes affecting ePHI
    # security: AEGIS runs that evaluation in the digital twin prior to deployment.
    twin_ok = sig.twin_tested() and sig.twin_converged()
    out.append(control(
        FRAMEWORK, "164.308(a)(8)",
        PASS if twin_ok else NA,
        "technical evaluation performed in digital twin before deployment "
        "(twin converged) in response to this operational change" if twin_ok
        else "no converged twin evaluation recorded for this change — "
             "technical evaluation not demonstrable for this run",
        PROCESS_MAPPED))

    # 164.312(b) — Audit Controls (process-mapped).
    # Mechanism that records and examines activity: AEGIS seals a tamper-evident,
    # content-hashed evidence record of the change and its verification.
    out.append(control(
        FRAMEWORK, "164.312(b)", PASS,
        "change activity recorded in a sealed, content-hashed AEGIS evidence bundle "
        "(static analysis + twin verification captured for examination)",
        PROCESS_MAPPED))

    return out


SELF_TEST = [
    # (signal kwargs, control_id, expected_status)

    # Transmission Security FAIL — plaintext BGP auth-key in the proposed config.
    ({"configs": [{"device": "core-01", "vendor": "frr",
                   "config": "# set bgp authentication-key plaintext abc123",
                   "grounded_commands": []}],
      "batfish": {"errors": 1, "warnings": 0, "passed": 1,
                  "findings": ["core-01: plaintext BGP auth-key"]}},
     "164.312(e)(1)", FAIL),

    # Transmission Security PASS — routed change, no plaintext/weak credentials.
    ({"configs": [{"device": "core-01", "vendor": "frr",
                   "config": "router bgp 65001\n neighbor 10.0.0.2 remote-as 65002",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 2, "findings": []}},
     "164.312(e)(1)", PASS),

    # Transmission Security NA — non-routed change (no transit-bearing config).
    ({"configs": [{"device": "sw-01", "vendor": "frr",
                   "config": "# add vlan 10", "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "164.312(e)(1)", NA),

    # Evaluation PASS — converged twin run recorded.
    ({"configs": [{"device": "core-01", "vendor": "frr",
                   "config": "# add vlan 10", "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []},
      "twin": {"converged": True}},
     "164.308(a)(8)", PASS),

    # Evaluation NA — no twin evaluation available for this run.
    ({"configs": [{"device": "core-01", "vendor": "frr",
                   "config": "# add vlan 10", "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "164.308(a)(8)", NA),

    # Audit Controls PASS — sealed evidence record always emitted for the change.
    ({"configs": [{"device": "core-01", "vendor": "frr",
                   "config": "# add vlan 10", "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "164.312(b)", PASS),
]
