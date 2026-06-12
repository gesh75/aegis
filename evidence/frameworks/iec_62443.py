"""IEC/ISA 62443-3-3 — System security requirements and security levels (OT/ICS).

Scope: industrial automation and control systems (IACS). Part 3-3 defines System
Requirements (SR) derived from the seven Foundational Requirements (FR). AEGIS maps the
SRs it can actually verify against a proposed network change:

  FR 1 (Identification & authentication control)
    SR 1.1 — Human user identification and authentication        (config-checked)
    SR 1.2 — Software process and device identification & auth   (config-checked)
  FR 3 (System integrity)
    SR 3.1 — Communication integrity                             (config-checked)
  FR 7 (Resource availability)
    SR 7.6 — Network and security configuration settings         (config-checked)

Control IDs/titles verified against the official IEC 62443-3-3 table of contents
(IEC webstore + ISA-62443-3-3 ToC) on 2026-06-02.

HONESTY: each row describes ONLY this proposed change as seen in the generated config and
Batfish static analysis — never a site-wide certification of the IACS. On the simulator's
minimal configs the hardening directives are usually absent, so a clean BGP change
legitimately comes back NA (capability not exercised by this change) or FAIL (auth/config
surface present but the required directive is missing) — that is AEGIS catching a real gap.
"""
from __future__ import annotations
from ._base import ComplianceSignal, control, PASS, FAIL, NA, CONFIG_CHECKED

FRAMEWORK = "iec_62443"


def evaluate(sig: ComplianceSignal) -> list[dict]:
    out: list[dict] = []

    # ---- FR 1: Identification & authentication control ------------------
    # SR 1.1 — Human user identification and authentication.
    # SR 1.2 — Software process and device identification and authentication.
    # We can inspect the change for auth material. If the change introduces no
    # authentication surface at all (no users, no BGP/peer auth, no AAA), the SR is
    # not exercised by this change -> NA. If auth material IS present, it must not be
    # plaintext (plaintext credentials fail identification/authentication integrity).
    has_auth_surface = sig.has_token(
        "authentication", "auth", "password", "username", "user ",
        "aaa", "tacacs", "radius", "key-chain", "key chain", "secret")
    plain = sig.has_plaintext_secret()

    if not has_auth_surface:
        sr11_status, sr11_ev = NA, \
            "change introduces no human-user authentication surface (SR not exercised)"
        sr12_status, sr12_ev = NA, \
            "change introduces no device/software-process authentication surface"
    elif plain:
        sr11_status, sr11_ev = FAIL, \
            "authentication material present in plaintext (no strong human-user auth)"
        sr12_status, sr12_ev = FAIL, \
            "device/process credential present in plaintext (weak device authentication)"
    else:
        sr11_status, sr11_ev = PASS, \
            "human-user authentication configured without plaintext credentials"
        sr12_status, sr12_ev = PASS, \
            "device/process authentication configured without plaintext credentials"

    out.append(control(FRAMEWORK, "SR 1.1", sr11_status, sr11_ev, CONFIG_CHECKED))
    out.append(control(FRAMEWORK, "SR 1.2", sr12_status, sr12_ev, CONFIG_CHECKED))

    # ---- FR 3: System integrity ----------------------------------------
    # SR 3.1 — Communication integrity (protect integrity of transmitted information).
    # For a routed change this maps to protocol-session authentication: routing
    # adjacencies / management channels must be authenticated and not run in the clear.
    # No routing/peering in this change -> capability not exercised (NA).
    if not sig.has_routing_proto():
        sr31_status, sr31_ev = NA, \
            "change adds no routing/peering session whose integrity is in scope"
    elif plain:
        sr31_status, sr31_ev = FAIL, \
            "routing/session credential transmitted in plaintext (integrity not protected)"
    elif sig.has_token("authentication", "key-chain", "key chain",
                       "message-digest", "md5", "password"):
        sr31_status, sr31_ev = PASS, \
            "routing/session integrity protected via configured session authentication"
    else:
        sr31_status, sr31_ev = FAIL, \
            "routing/peering session has no session authentication (integrity unprotected)"
    out.append(control(FRAMEWORK, "SR 3.1", sr31_status, sr31_ev, CONFIG_CHECKED))

    # ---- FR 7: Resource availability -----------------------------------
    # SR 7.6 — Network and security configuration settings (be configurable to
    # recommended network/security baselines; provide the deployed settings). AEGIS
    # treats this as: the proposed config must be clean against the static baseline
    # (Batfish) and carry no plaintext security material that violates the baseline.
    baseline_violation = (not sig.batfish_clean()) or plain
    out.append(control(
        FRAMEWORK, "SR 7.6",
        FAIL if baseline_violation else PASS,
        "config deviates from network/security baseline (static-analysis errors or "
        "plaintext security material)" if baseline_violation
        else "config conforms to network/security baseline (Batfish clean, no plaintext "
             "security material)",
        CONFIG_CHECKED))

    return out


SELF_TEST = [
    # (signal kwargs, control_id, expected_status)

    # Plaintext BGP auth-key -> SR 1.2 device auth FAIL.
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "# neighbor 10.0.0.1 password plaintext abc123",
                   "grounded_commands": []}],
      "batfish": {"errors": 1, "warnings": 0, "passed": 0,
                  "findings": ["d: plaintext BGP password"]}},
     "SR 1.2", FAIL),

    # Plaintext routing credential -> SR 3.1 communication integrity FAIL.
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "# router bgp 65001\n#  neighbor 10.0.0.1 password plaintext abc123",
                   "grounded_commands": []}],
      "batfish": {"errors": 1, "warnings": 0, "passed": 0, "findings": []}},
     "SR 3.1", FAIL),

    # Pure L2 VLAN add, no auth surface -> SR 1.1 not exercised -> NA.
    ({"configs": [{"device": "d", "vendor": "frr", "config": "# add vlan 10",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "SR 1.1", NA),

    # Clean L2 change, Batfish clean, no plaintext -> SR 7.6 baseline PASS.
    ({"configs": [{"device": "d", "vendor": "frr", "config": "# add vlan 10",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "SR 7.6", PASS),

    # BGP session with key-chain authentication, no plaintext -> SR 3.1 PASS.
    ({"configs": [{"device": "d", "vendor": "frr",
                   "config": "# router bgp 65001\n#  neighbor 10.0.0.1 password 7 key-chain BGPKEY",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "SR 3.1", PASS),
]
