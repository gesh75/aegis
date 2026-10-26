"""PCI DSS v4.0 — Payment Card Industry Data Security Standard.

Scope: any entity that stores, processes, or transmits cardholder data. The two controls
AEGIS asserts are both config-checked off the proposed change.
"""
from __future__ import annotations
from ._base import ComplianceSignal, control, PASS, FAIL, CONFIG_CHECKED
from .. import secrets

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

    # 8.3.2 — strong cryptography for authentication; no plaintext credentials
    # D2: reversible obfuscation (type 7, $9$) fails by default; AEGIS_REVERSIBLE_SECRETS=report
    # restores PASS-with-note. Compliance rows are evidence — they do not change the verdict.
    labels = sig.plaintext_secret_labels()
    reversible = sig.reversible_secret_labels()
    rev_fails = bool(reversible) and secrets.reversible_policy() == "fail"
    note = (f"; reversible obfuscation present ({', '.join(reversible)}) — not strong "
            "cryptography" + ("" if rev_fails else
                              ", review against your key-management policy")) if reversible else ""
    if labels:
        evidence = f"plaintext authentication material in config ({', '.join(labels)})"
    elif rev_fails:
        evidence = "no plaintext authentication material"
    else:
        evidence = "no plaintext authentication material in generated config"
    out.append(control(
        FRAMEWORK, "8.3.2",
        FAIL if labels or rev_fails else PASS,
        evidence + note,
        CONFIG_CHECKED))

    return out


SELF_TEST = [
    # (signal kwargs, control_id, expected_status)
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "# set bgp authentication-key plaintext abc123",
                   "grounded_commands": []}],
      "batfish": {"errors": 1, "warnings": 0, "passed": 1,
                  "findings": ["d: plaintext BGP auth-key (PCI 8.3.2 fail)"]}},
     "8.3.2", FAIL),
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "# add vlan 10", "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "8.3.2", PASS),
    # vendor-aware cleartext detection: Cisco type 0, SNMP v2c community, Junos non-$9$
    ({"configs": [{"device": "r1", "vendor": "ios",
                   "config": "username admin privilege 15 password 0 cisco123",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "8.3.2", FAIL),
    ({"configs": [{"device": "r1", "vendor": "ios",
                   "config": "snmp-server community public RO", "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "8.3.2", FAIL),
    ({"configs": [{"device": "mx1", "vendor": "junos",
                   "config": 'set protocols bgp group G authentication-key "letmein"',
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "8.3.2", FAIL),
    # D2 default (AEGIS_REVERSIBLE_SECRETS=fail): reversible obfuscation fails 8.3.2
    ({"configs": [{"device": "mx1", "vendor": "junos",
                   "config": 'set protocols bgp group G authentication-key "$9$AbCdEf"',
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "8.3.2", FAIL),
    ({"configs": [{"device": "r1", "vendor": "ios",
                   "config": "username ops password 7 0822455D0A16",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "8.3.2", FAIL),
    # a hash is not reversible: still PASS
    ({"configs": [{"device": "r1", "vendor": "ios",
                   "config": "username ops secret 9 $9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "8.3.2", PASS),
]
