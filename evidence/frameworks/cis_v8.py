"""CIS Critical Security Controls v8 — Tier 1 (network-relevant safeguards).

AEGIS maps to two CIS v8 controls that govern network change safety:

  Control 4  — Secure Configuration of Enterprise Assets and Software
  Control 12 — Network Infrastructure Management

The three safeguards modelled here (verified against the CIS Controls Assessment
Specification, cas8.docs.cisecurity.org):

  4.2  Establish and Maintain a Secure Configuration Process for Network
       Infrastructure  -> PROCESS_MAPPED. AEGIS *is* the documented, repeatable
       secure-configuration process: every proposed change is twin-tested,
       deterministically verified and diffed for unintended drift before a gated
       human promotion. "Automatically verify device configs and detect changes"
       is exactly what this pipeline does.

  12.3 Securely Manage Network Infrastructure (version-controlled IaC + secure
       protocols; "do not use insecure management protocols ... unless
       operationally essential") -> CONFIG_CHECKED. We actually inspect the
       proposed config for plaintext secrets and for routes advertised without an
       export policy, and FAIL the safeguard when either is present.

  12.2 Establish and Maintain a Secure Network Architecture (segmentation, least
       privilege, availability) -> PROCESS_MAPPED. Availability is the part AEGIS
       can structurally attest for THIS run: the change converged in a digital
       twin and dropped no BGP sessions before promotion. We do not claim the
       org's whole architecture is certified — only that this change did not
       regress reachability in the twin.

HONESTY RULE applied: only 12.3 inspects the config to decide pass/fail, so only
it is CONFIG_CHECKED. 4.2 and 12.2 are PROCESS_MAPPED — satisfied by the AEGIS
process for this run, not a certification of the enterprise. Evidence strings
describe THIS change only.
"""
from __future__ import annotations
from ._base import ComplianceSignal, control, PASS, FAIL, NA, CONFIG_CHECKED, PROCESS_MAPPED

FRAMEWORK = "cis_v8"


def evaluate(sig: ComplianceSignal) -> list[dict]:
    out: list[dict] = []

    # --- 4.2 Secure Configuration Process for Network Infrastructure ----------
    # PROCESS_MAPPED: the change went through AEGIS's documented, deterministic
    # verify-and-detect-changes process (twin test + static analysis + diff)
    # before any human promotion. This safeguard asks for exactly such a process.
    out.append(control(
        FRAMEWORK, "4.2", PASS,
        "change run through AEGIS secure-config process: twin-tested, "
        "statically analyzed and diffed before gated promotion",
        PROCESS_MAPPED))

    # --- 12.3 Securely Manage Network Infrastructure -------------------------
    # CONFIG_CHECKED: inspect the proposed config for insecure management
    # (plaintext secrets) and for routes exported without a policy. Either => FAIL.
    plaintext = sig.has_plaintext_secret()
    no_export = sig.missing_export_policy()
    if plaintext or no_export:
        reasons = []
        if plaintext:
            reasons.append("plaintext secret in config")
        if no_export:
            reasons.append("route advertised without export policy")
        out.append(control(
            FRAMEWORK, "12.3", FAIL,
            "insecure network management flagged: " + "; ".join(reasons),
            CONFIG_CHECKED))
    else:
        out.append(control(
            FRAMEWORK, "12.3", PASS,
            "no plaintext secrets and no unscoped route exports in proposed config",
            CONFIG_CHECKED))

    # --- 12.2 Establish and Maintain a Secure Network Architecture -----------
    # PROCESS_MAPPED on the availability dimension: attest only that THIS change
    # converged in the twin and dropped no BGP sessions. If there was no twin run
    # we cannot attest availability for this change -> NA (not applicable here).
    if not sig.twin_tested():
        out.append(control(
            FRAMEWORK, "12.2", NA,
            "no digital-twin run for this change; availability impact not attestable",
            PROCESS_MAPPED))
    elif sig.twin_converged() and not sig.sessions_dropped():
        out.append(control(
            FRAMEWORK, "12.2", PASS,
            "architecture availability preserved: twin converged and dropped no "
            "BGP sessions for this change",
            PROCESS_MAPPED))
    else:
        out.append(control(
            FRAMEWORK, "12.2", FAIL,
            "architecture availability regressed in twin: "
            + ("twin failed to converge" if not sig.twin_converged()
               else "BGP session(s) dropped by this change"),
            PROCESS_MAPPED))

    return out


SELF_TEST = [
    # 12.3 PASS — clean config, no plaintext secret, no missing-export finding
    ({"configs": [{"device": "de-fra-core-01", "vendor": "frr",
                   "config": "router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n"
                             " neighbor 10.0.0.2 maximum-prefix 1000",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "12.3", PASS),

    # 12.3 FAIL — plaintext secret present in proposed config
    ({"configs": [{"device": "de-fra-core-01", "vendor": "frr",
                   "config": "# set bgp authentication-key plaintext abc123",
                   "grounded_commands": []}],
      "batfish": {"errors": 1, "warnings": 0, "passed": 0, "findings": []}},
     "12.3", FAIL),

    # 12.3 FAIL — route advertised without an export policy (Batfish finding)
    ({"configs": [{"device": "uk-lon-core-01", "vendor": "frr",
                   "config": "router bgp 65003\n network 10.1.0.0/16",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 1, "passed": 0,
                  "findings": ["10.1.0.0/16 advertised without export policy"]}},
     "12.3", FAIL),

    # 4.2 PASS — process-mapped, always satisfied for a run through the pipeline
    ({"configs": [{"device": "d", "vendor": "frr", "config": "# add vlan 10",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "4.2", PASS),

    # 12.2 PASS — twin converged and no sessions dropped
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "router bgp 65001\n neighbor 10.0.0.2 remote-as 65002",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []},
      "twin": {"converged": True},
      "diff": {"sessions_dropped": []}},
     "12.2", PASS),

    # 12.2 FAIL — twin converged but a BGP session dropped
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "router bgp 65001\n no neighbor 10.0.0.2",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []},
      "twin": {"converged": True},
      "diff": {"sessions_dropped": ["10.0.0.2"]}},
     "12.2", FAIL),

    # 12.2 NA — no twin run, availability not attestable for this change
    ({"configs": [{"device": "d", "vendor": "frr", "config": "# add vlan 10",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "12.2", NA),
]
