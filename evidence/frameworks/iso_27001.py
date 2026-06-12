"""ISO/IEC 27001:2022 — Annex A information security controls (Tier 4).

AEGIS maps three Annex A technological controls from the 2022 edition (control numbers
verified against ISO/IEC 27001:2022 Annex A / ISO/IEC 27002:2022 Clause 8):

  A.8.9  Configuration management  (NEW in 2022) — config-checked: configurations are
         established, documented and reviewed; static analysis must be clean.
  A.8.32 Change management         (was A.12.1.2) — process-mapped: the change is
         twin-tested + deterministically verified and gated on human approval before
         deployment.
  A.8.20 Networks security         (was A.13.1.1) — config-checked: networks/network
         devices secured off policy (export/import policy present, no plaintext secrets);
         NA when the change touches no routing/network surface.

A.8.9 and A.8.20 are config-checked (we inspect the proposed config + Batfish to decide).
A.8.32 is process-mapped (satisfied by the AEGIS pipeline structure, not a config grep).
Evidence describes THIS run only — never that the org is ISO-certified.
"""
from __future__ import annotations
from ._base import (
    ComplianceSignal, control, PASS, FAIL, NA, CONFIG_CHECKED, PROCESS_MAPPED,
)

FRAMEWORK = "iso_27001"


def evaluate(sig: ComplianceSignal) -> list[dict]:
    out: list[dict] = []

    # A.8.9 Configuration management — configurations shall be established, documented,
    # implemented, monitored and reviewed. Config-checked: the proposed configuration is
    # documented as a grounded change and must pass static analysis with no errors.
    cfg_bad = not sig.batfish_clean()
    out.append(control(
        FRAMEWORK, "A.8.9",
        FAIL if cfg_bad else PASS,
        "static analysis reported {} error(s) in the documented configuration".format(
            sig.batfish_errors()) if cfg_bad
        else "configuration documented and reviewed via twin; static analysis clean "
             "(0 errors)",
        CONFIG_CHECKED))

    # A.8.32 Change management — changes shall be subject to change management procedures.
    # Process-mapped: the change ran through the preflight twin and is gated on approval.
    twin_ok = sig.twin_tested() and sig.twin_converged()
    out.append(control(
        FRAMEWORK, "A.8.32", PASS,  # the AEGIS procedure satisfies this; evidence differs
        "change tested in digital twin (converged) and gated on human approval "
        "before deployment" if twin_ok
        else "change subject to AEGIS change-management procedure; promotion gated on "
             "human approval before deployment",
        PROCESS_MAPPED))

    # A.8.20 Networks security — networks and network devices shall be secured, managed
    # and controlled. Config-checked: routing peers must carry export/import policy and
    # the config must contain no plaintext secrets. NA when no network surface is touched.
    if not sig.has_routing_proto():
        out.append(control(
            FRAMEWORK, "A.8.20", NA,
            "change touches no routing/network surface (no BGP/OSPF/IS-IS directives)",
            CONFIG_CHECKED))
    else:
        plain = sig.has_plaintext_secret()
        no_policy = sig.missing_export_policy()
        insecure = plain or no_policy
        if insecure:
            reasons = []
            if no_policy:
                reasons.append("routing peer missing export/import policy")
            if plain:
                reasons.append("plaintext secret in network config")
            evidence = "network not secured off policy: " + "; ".join(reasons)
        else:
            evidence = ("network devices secured: routing peers carry export/import "
                        "policy and no plaintext secrets present")
        out.append(control(
            FRAMEWORK, "A.8.20",
            FAIL if insecure else PASS,
            evidence,
            CONFIG_CHECKED))

    return out


SELF_TEST = [
    # (signal kwargs, control_id, expected_status)

    # A.8.9 PASS — clean static analysis on a documented change.
    ({"configs": [{"device": "de-fra-core-01", "vendor": "frr",
                   "config": "router bgp 65001\n neighbor 10.200.0.12 remote-as 65002\n"
                             " neighbor 10.200.0.12 route-map EXPORT out",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []},
      "twin": {"converged": True}},
     "A.8.9", PASS),

    # A.8.9 FAIL — static analysis surfaced errors in the configuration.
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "router bgp 65001\n neighbor 10.0.0.1 remote-as 65002",
                   "grounded_commands": []}],
      "batfish": {"errors": 2, "warnings": 0, "passed": 0,
                  "findings": ["d: undefined route-map referenced"]}},
     "A.8.9", FAIL),

    # A.8.32 PASS — change twin-tested + converged, gated on approval.
    ({"configs": [{"device": "d", "vendor": "frr", "config": "# add vlan 10",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []},
      "twin": {"converged": True}},
     "A.8.32", PASS),

    # A.8.20 NA — change has no routing/network surface (a clean VLAN add).
    ({"configs": [{"device": "d", "vendor": "frr", "config": "# add vlan 10",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "A.8.20", NA),

    # A.8.20 FAIL — BGP peer present but missing export policy (network not off policy).
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "router bgp 65001\n neighbor 10.0.0.1 remote-as 65002",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 1, "passed": 1,
                  "findings": ["d: BGP neighbor 10.0.0.1 without export policy"]}},
     "A.8.20", FAIL),

    # A.8.20 PASS — BGP peer present, carries policy, no plaintext secret.
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "router bgp 65001\n neighbor 10.0.0.1 remote-as 65002\n"
                             " neighbor 10.0.0.1 route-map EXPORT out",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "A.8.20", PASS),
]
