"""PCI DSS v4.0 — Payment Card Industry Data Security Standard.

Scope: any entity that stores, processes, or transmits cardholder data. The two controls
AEGIS asserts are both config-checked off the proposed change.
"""
from __future__ import annotations
from ._base import ComplianceSignal, control, PASS, FAIL, CONFIG_CHECKED

FRAMEWORK = "pci_dss_v4"


def evaluate(sig: ComplianceSignal) -> list[dict]:
    out: list[dict] = []

    # 1.2.1 — network security controls config standards (NSC rulesets enforced)
    missing = sig.missing_export_policy()
    out.append(control(
        FRAMEWORK, "1.2.1",
        FAIL if missing else PASS,
        "BGP neighbor missing export/import policy" if missing
        else "export/import policy present on BGP neighbors",
        CONFIG_CHECKED))

    # 8.3.1 — strong cryptography for authentication; no plaintext credentials
    plain = sig.has_plaintext_secret()
    out.append(control(
        FRAMEWORK, "8.3.1",
        FAIL if plain else PASS,
        "plaintext authentication material in config" if plain
        else "no plaintext authentication material in generated config",
        CONFIG_CHECKED))

    return out


SELF_TEST = [
    # (signal kwargs, control_id, expected_status)
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "# set bgp authentication-key plaintext abc123",
                   "grounded_commands": []}],
      "batfish": {"errors": 1, "warnings": 0, "passed": 1,
                  "findings": ["d: plaintext BGP auth-key (PCI 8.3.1 fail)"]}},
     "8.3.1", FAIL),
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "# add vlan 10", "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "8.3.1", PASS),
]
