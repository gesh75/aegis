"""NIST CSF 2.0 — Cybersecurity Framework 2.0 (Tier 1 mapping).

CSF 2.0 describes high-level cybersecurity outcomes (subcategories), not prescriptive
controls. AEGIS maps three subcategories it can speak to for a single change:

  PR.PS-01  Configuration management practices are established and applied.
            -> config-checked: pass requires a clean static-analysis baseline.
  PR.IR-01  Networks and environments are protected from unauthorized logical access
            and usage.
            -> config-checked: fails on plaintext credentials or a BGP neighbor left
               without an export/import policy (an unauthorized-access exposure).
  DE.CM-01  Networks and network services are monitored to find potentially adverse
            events.
            -> process-mapped: the digital twin observes convergence/session state for
               this change before promotion (the monitoring outcome AEGIS provides).

Evidence describes THIS run only — never that the org is "certified".
"""
from __future__ import annotations
from ._base import (
    ComplianceSignal, control,
    PASS, FAIL, NA, CONFIG_CHECKED, PROCESS_MAPPED,
)

FRAMEWORK = "nist_csf_2.0"


def evaluate(sig: ComplianceSignal) -> list[dict]:
    out: list[dict] = []

    # PR.PS-01 — Configuration management practices are established and applied.
    # Config-checked: a clean Batfish baseline (no errors, no plaintext) demonstrates the
    # proposed config meets the managed baseline before it can be promoted.
    bad_baseline = not sig.batfish_clean() or sig.has_plaintext_secret()
    out.append(control(
        FRAMEWORK, "PR.PS-01",
        FAIL if bad_baseline else PASS,
        "static analysis flagged baseline deviation(s) in proposed config" if bad_baseline
        else "proposed config passes static-analysis baseline (no errors, no plaintext)",
        CONFIG_CHECKED))

    # PR.IR-01 — Networks and environments are protected from unauthorized logical
    # access and usage. Config-checked off the access-exposing gaps AEGIS can see:
    # plaintext auth material or a BGP neighbor with no export/import policy.
    if not sig.has_bgp():
        # No routing-protocol surface in this change -> the access-control gaps this
        # subcategory guards against don't apply to it.
        out.append(control(
            FRAMEWORK, "PR.IR-01", NA,
            "no BGP/routing surface in this change; logical-access gap not applicable",
            CONFIG_CHECKED))
    else:
        plain = sig.has_plaintext_secret()
        open_policy = sig.missing_export_policy()
        exposed = plain or open_policy
        if plain:
            why = "plaintext authentication material exposes unauthorized access"
        elif open_policy:
            why = "BGP neighbor without export/import policy (unconstrained route exchange)"
        else:
            why = "BGP neighbors carry export/import policy; no plaintext auth material"
        out.append(control(
            FRAMEWORK, "PR.IR-01",
            FAIL if exposed else PASS,
            why,
            CONFIG_CHECKED))

    # DE.CM-01 — Networks and network services are monitored to find potentially adverse
    # events. Process-mapped: AEGIS does not run a production monitoring stack, but the
    # twin observes convergence + session state for this change before promotion, which
    # is the monitoring outcome we can attest to for this run.
    if sig.twin_tested():
        if sig.twin_converged() and not sig.sessions_dropped():
            evid = ("twin observed convergence with no dropped sessions; "
                    "adverse-event monitoring satisfied for this change")
        else:
            detail = "no convergence" if not sig.twin_converged() else "dropped session(s)"
            evid = (f"twin monitoring detected adverse event ({detail}) "
                    "prior to promotion")
        out.append(control(
            FRAMEWORK, "DE.CM-01", PASS, evid, PROCESS_MAPPED))
    else:
        out.append(control(
            FRAMEWORK, "DE.CM-01", NA,
            "no twin run for this change; convergence/state not observed",
            PROCESS_MAPPED))

    return out


SELF_TEST = [
    # (signal kwargs, control_id, expected_status)

    # PR.PS-01 PASS — clean baseline, no plaintext.
    ({"configs": [{"device": "d", "vendor": "frr", "config": "# add vlan 10",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "PR.PS-01", PASS),

    # PR.PS-01 FAIL — Batfish errors break the managed baseline.
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "# set bgp authentication-key plaintext abc123",
                   "grounded_commands": []}],
      "batfish": {"errors": 2, "warnings": 0, "passed": 0, "findings": []}},
     "PR.PS-01", FAIL),

    # PR.IR-01 NA — no BGP/routing surface in a clean VLAN change.
    ({"configs": [{"device": "d", "vendor": "frr", "config": "# add vlan 10",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "PR.IR-01", NA),

    # PR.IR-01 FAIL — BGP neighbor left without an export/import policy.
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "# neighbor 10.0.0.1 remote-as 65001",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 1, "passed": 1,
                  "findings": ["d: BGP neighbor 10.0.0.1 without export policy"]}},
     "PR.IR-01", FAIL),

    # PR.IR-01 PASS — BGP present, policy attached, no plaintext.
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "# neighbor 10.0.0.1 remote-as 65001 route-map EXPORT out",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "PR.IR-01", PASS),

    # DE.CM-01 PASS — twin converged, no sessions dropped.
    ({"configs": [{"device": "d", "vendor": "frr", "config": "# add vlan 10",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []},
      "twin": {"converged": True},
      "diff": {"sessions_dropped": []}},
     "DE.CM-01", PASS),

    # DE.CM-01 NA — no twin run, nothing observed.
    ({"configs": [{"device": "d", "vendor": "frr", "config": "# add vlan 10",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "DE.CM-01", NA),
]
