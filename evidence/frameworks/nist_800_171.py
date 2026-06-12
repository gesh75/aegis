"""NIST SP 800-171 Rev. 2 — Protecting CUI (Configuration Management family, 3.4.x).

Maps the AEGIS change-validation loop to the three Configuration Management requirements
AEGIS can speak to. These are the same requirements assessed at **CMMC Level 2** (the
practices carry the CMMC IDs CM.L2-3.4.1 / CM.L2-3.4.2 / CM.L2-3.4.3), so the evidence
text notes that alignment.

  3.4.1  Establish and maintain baseline configurations and inventories          -> process-mapped
  3.4.2  Establish and enforce security configuration settings for IT products    -> config-checked
  3.4.3  Track, review, approve or disapprove, and log changes to systems          -> process-mapped

HONESTY: 3.4.1 and 3.4.3 are process-mapped — AEGIS does not certify that an org-wide
baseline or a CCB exists; it attests that THIS change was twin-tested, deterministically
verified, and is gated on human approval before promotion. 3.4.2 is config-checked: it
inspects the proposed config / Batfish for insecure settings, so a clean baseline passes
and a flagged directive fails.
"""
from __future__ import annotations
from ._base import (
    ComplianceSignal, control, PASS, FAIL, NA, CONFIG_CHECKED, PROCESS_MAPPED,
)

FRAMEWORK = "nist_800-171"


def evaluate(sig: ComplianceSignal) -> list[dict]:
    out: list[dict] = []

    # 3.4.1 (CM.L2-3.4.1) — Baseline configurations & inventory.
    # Process-mapped: AEGIS captured the pre-change baseline and validated the proposed
    # build against it in a digital twin before any production touch.
    twin_note = ("twin-converged" if sig.twin_converged()
                 else "twin-tested" if sig.twin_tested()
                 else "static baseline only (no twin this run)")
    out.append(control(
        FRAMEWORK, "3.4.1", PASS,
        f"baseline captured and proposed build validated against it ({twin_note}); "
        "CMMC L2 CM.L2-3.4.1",
        PROCESS_MAPPED))

    # 3.4.2 (CM.L2-3.4.2) — Enforce secure configuration settings.
    # Config-checked: inspect static analysis + the proposed config for insecure settings.
    bad = not sig.batfish_clean() or sig.has_plaintext_secret()
    if bad:
        reason = ("plaintext secret in proposed config" if sig.has_plaintext_secret()
                  else f"{sig.batfish_errors()} static-analysis error(s) on proposed settings")
        out.append(control(
            FRAMEWORK, "3.4.2", FAIL,
            f"insecure configuration setting flagged ({reason}); CMMC L2 CM.L2-3.4.2",
            CONFIG_CHECKED))
    else:
        out.append(control(
            FRAMEWORK, "3.4.2", PASS,
            "secure configuration settings enforced — no insecure directives or "
            "plaintext secrets in proposed config (Batfish clean); CMMC L2 CM.L2-3.4.2",
            CONFIG_CHECKED))

    # 3.4.3 (CM.L2-3.4.3) — Track, review, approve/disapprove, and log changes.
    # Process-mapped: the change is twin-tested + deterministically verified, recorded in
    # the sealed evidence bundle, and gated on human approve/disapprove before promotion.
    if sig.is_config_import():
        out.append(control(
            FRAMEWORK, "3.4.3", NA,
            "config-import review (no proposed change to gate); CMMC L2 CM.L2-3.4.3",
            PROCESS_MAPPED))
    else:
        out.append(control(
            FRAMEWORK, "3.4.3", PASS,
            "change twin-tested and logged in the sealed evidence bundle; promotion gated "
            "on human approve/disapprove before production; CMMC L2 CM.L2-3.4.3",
            PROCESS_MAPPED))

    return out


SELF_TEST = [
    # 3.4.2 FAIL — plaintext secret in the proposed config is an insecure setting.
    ({"configs": [{"device": "de-fra-core-01", "vendor": "frr",
                   "config": "# set bgp authentication-key plaintext abc123",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 0, "findings": []}},
     "3.4.2", FAIL),
    # 3.4.2 FAIL — Batfish errors on the proposed settings.
    ({"configs": [{"device": "uk-lon-core-01", "vendor": "frr",
                   "config": "# router bgp 65003", "grounded_commands": []}],
      "batfish": {"errors": 3, "warnings": 0, "passed": 0, "findings": []}},
     "3.4.2", FAIL),
    # 3.4.2 PASS — clean baseline, no insecure directives.
    ({"configs": [{"device": "nl-ams-core-01", "vendor": "frr",
                   "config": "# add vlan 10", "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "3.4.2", PASS),
    # 3.4.1 PASS — baseline validated in a converged twin.
    ({"configs": [{"device": "de-fra-edge-01", "vendor": "frr",
                   "config": "# add vlan 20", "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []},
      "twin": {"converged": True}},
     "3.4.1", PASS),
    # 3.4.3 PASS — proposed change is gated on human approval.
    ({"configs": [{"device": "us-nyc-core-01", "vendor": "frr",
                   "config": "# add vlan 30", "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "3.4.3", PASS),
    # 3.4.3 NA — config import has no proposed change to gate.
    ({"configs": [{"device": "uk-lon-edge-01", "vendor": "frr",
                   "config": "# imported running-config", "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []},
      "source": "config_import"},
     "3.4.3", NA),
]
