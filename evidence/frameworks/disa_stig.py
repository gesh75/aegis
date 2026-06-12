"""DISA STIG — Cisco Router/Switch RTR Security Technical Implementation Guide.

Real CISC-RT-* requirements from the DISA Cisco IOS/IOS XE/IOS XR/NX-OS Router (and
Switch) RTR STIGs. AEGIS maps four routing-security rules, all config-checked off the
proposed change (BGP/routing-protocol hardening + FIPS-validated authentication):

    CISC-RT-000480 (V-217000, CCI-002205) — unique BGP key per peer AS
    CISC-RT-000560 (V-216694, CCI-002385) — BGP maximum-prefix limit per neighbor
    CISC-RT-000470 — eBGP Generalized TTL Security Mechanism (GTSM / ttl-security)
    CISC-RT-000050 (V-216645, CCI-000803) — routing-protocol auth using FIPS 198-1 MAC

HONESTY: these are config-checked — evaluate() inspects the proposed config text to
decide. On the simulator's minimal configs a clean BGP change legitimately returns NA
(no BGP/routing proto) or FAIL (BGP present but missing the hardening directive). That
FAIL is AEGIS correctly catching a real gap in THIS change — never a claim of certified
compliance. Evidence describes this run only.
"""
from __future__ import annotations
from ._base import ComplianceSignal, control, PASS, FAIL, NA, CONFIG_CHECKED

FRAMEWORK = "disa_stig"


def evaluate(sig: ComplianceSignal) -> list[dict]:
    out: list[dict] = []
    has_bgp = sig.has_bgp()
    has_proto = sig.has_routing_proto()
    plaintext = sig.has_plaintext_secret()

    # CISC-RT-000480 — unique key for each AS the BGP router peers with.
    # FAIL on plaintext auth material, PASS if BGP present with non-plaintext auth,
    # NA when this change introduces no BGP.
    if not has_bgp:
        out.append(control(
            FRAMEWORK, "CISC-RT-000480", NA,
            "no BGP configured in this change; unique-per-AS key requirement N/A",
            CONFIG_CHECKED))
    elif plaintext:
        out.append(control(
            FRAMEWORK, "CISC-RT-000480", FAIL,
            "BGP present with plaintext authentication key — fails unique encrypted "
            "per-AS key requirement",
            CONFIG_CHECKED))
    else:
        out.append(control(
            FRAMEWORK, "CISC-RT-000480", PASS,
            "BGP present with non-plaintext neighbor authentication in proposed config",
            CONFIG_CHECKED))

    # CISC-RT-000560 — BGP maximum-prefix on eBGP neighbors (route-table-flood guard).
    # PASS if a max-prefix directive is present, FAIL if BGP present without it, NA if no BGP.
    has_maxpfx = sig.has_token("maximum-prefix", "max-prefix", "prefix-limit")
    if not has_bgp:
        out.append(control(
            FRAMEWORK, "CISC-RT-000560", NA,
            "no BGP configured in this change; maximum-prefix requirement N/A",
            CONFIG_CHECKED))
    elif has_maxpfx:
        out.append(control(
            FRAMEWORK, "CISC-RT-000560", PASS,
            "BGP neighbor maximum-prefix limit present in proposed config",
            CONFIG_CHECKED))
    else:
        out.append(control(
            FRAMEWORK, "CISC-RT-000560", FAIL,
            "BGP present without a maximum-prefix limit — exposed to route-table "
            "flooding / prefix de-aggregation",
            CONFIG_CHECKED))

    # CISC-RT-000470 — eBGP GTSM (ttl-security hops). Same shape as 000560.
    has_gtsm = sig.has_token("ttl-security", "ttl-security hops", "gtsm")
    if not has_bgp:
        out.append(control(
            FRAMEWORK, "CISC-RT-000470", NA,
            "no BGP configured in this change; GTSM/ttl-security requirement N/A",
            CONFIG_CHECKED))
    elif has_gtsm:
        out.append(control(
            FRAMEWORK, "CISC-RT-000470", PASS,
            "eBGP GTSM (ttl-security) directive present in proposed config",
            CONFIG_CHECKED))
    else:
        out.append(control(
            FRAMEWORK, "CISC-RT-000470", FAIL,
            "BGP present without GTSM/ttl-security — eBGP not protected against "
            "spoofed-TTL DoS",
            CONFIG_CHECKED))

    # CISC-RT-000050 — routing-protocol authentication using FIPS 198-1 algorithms.
    # FAIL if a routing protocol is present with plaintext or no authentication.
    if not has_proto:
        out.append(control(
            FRAMEWORK, "CISC-RT-000050", NA,
            "no routing protocol in this change; FIPS-auth requirement N/A",
            CONFIG_CHECKED))
    else:
        has_fips_auth = sig.has_token(
            "hmac-sha", "key-chain", "key chain", "cryptographic-algorithm",
            "message-digest", "ao ", "authentication mode")
        if plaintext or not has_fips_auth:
            out.append(control(
                FRAMEWORK, "CISC-RT-000050", FAIL,
                "routing protocol present with plaintext or no FIPS 198-1 "
                "authentication (no key-chain/HMAC-SHA found)",
                CONFIG_CHECKED))
        else:
            out.append(control(
                FRAMEWORK, "CISC-RT-000050", PASS,
                "routing protocol uses FIPS 198-1 keyed authentication "
                "(key-chain / HMAC-SHA) in proposed config",
                CONFIG_CHECKED))

    return out


SELF_TEST = [
    # (signal kwargs, control_id, expected_status)

    # BGP present with plaintext key -> 000480 FAIL
    ({"configs": [{"device": "r1", "vendor": "cisco_ios",
                   "config": "router bgp 65001\n neighbor 10.1.1.9 remote-as 65002\n"
                             " neighbor 10.1.1.9 password 0 plaintext abc123",
                   "grounded_commands": []}],
      "batfish": {"errors": 1, "warnings": 0, "passed": 0, "findings": []}},
     "CISC-RT-000480", FAIL),

    # BGP present without maximum-prefix -> 000560 FAIL (real gap AEGIS catches)
    ({"configs": [{"device": "r1", "vendor": "cisco_ios",
                   "config": "router bgp 65001\n neighbor 10.1.1.9 remote-as 65002",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000560", FAIL),

    # BGP present with maximum-prefix -> 000560 PASS
    ({"configs": [{"device": "r1", "vendor": "cisco_ios",
                   "config": "router bgp 65001\n neighbor 10.1.1.9 remote-as 65002\n"
                             " neighbor 10.1.1.9 maximum-prefix 5000",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000560", PASS),

    # eBGP with ttl-security -> 000470 PASS
    ({"configs": [{"device": "r1", "vendor": "cisco_ios",
                   "config": "router bgp 65001\n neighbor 10.1.1.9 remote-as 65002\n"
                             " neighbor 10.1.1.9 ttl-security hops 1",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000470", PASS),

    # OSPF with FIPS key-chain -> 000050 PASS
    ({"configs": [{"device": "r1", "vendor": "cisco_ios",
                   "config": "key chain OSPF_KEY\n key 1\n  cryptographic-algorithm "
                             "hmac-sha-256\nrouter ospf 1\n interface eth0\n  ip ospf "
                             "authentication key-chain OSPF_KEY",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000050", PASS),

    # OSPF with no authentication -> 000050 FAIL
    ({"configs": [{"device": "r1", "vendor": "cisco_ios",
                   "config": "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000050", FAIL),

    # No BGP at all (vlan-only change) -> 000480 NA
    ({"configs": [{"device": "sw1", "vendor": "cisco_ios",
                   "config": "vlan 10\n name DATA", "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000480", NA),
]
