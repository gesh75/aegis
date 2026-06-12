"""NIST SP 800-53 — Security and Privacy Controls (Configuration Management family).

The two CM controls AEGIS maps to: change control (CM-3) and secure config settings
(CM-6). CM-6 is config-checked (insecure directives fail it); CM-3 is process-mapped.
"""
from __future__ import annotations
from ._base import ComplianceSignal, control, PASS, FAIL, CONFIG_CHECKED, PROCESS_MAPPED

FRAMEWORK = "nist_800-53"


def evaluate(sig: ComplianceSignal) -> list[dict]:
    out: list[dict] = []

    # CM-3 — Configuration Change Control (formal test/review before production)
    out.append(control(
        FRAMEWORK, "CM-3", PASS,
        "change verified in digital twin prior to production",
        PROCESS_MAPPED))

    # CM-6 — Configuration Settings (enforce secure settings; no insecure directives)
    bad = not sig.batfish_clean() or sig.has_plaintext_secret()
    out.append(control(
        FRAMEWORK, "CM-6",
        FAIL if bad else PASS,
        "insecure directive(s) flagged by static analysis" if bad
        else "config baseline enforced (no insecure directives)",
        CONFIG_CHECKED))

    return out


SELF_TEST = [
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "# set bgp authentication-key plaintext abc123",
                   "grounded_commands": []}],
      "batfish": {"errors": 2, "warnings": 0, "passed": 0, "findings": []}},
     "CM-6", FAIL),
    ({"configs": [{"device": "d", "vendor": "frr", "config": "# add vlan 10",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CM-6", PASS),
]
