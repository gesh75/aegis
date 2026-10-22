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
import re

from ._base import ComplianceSignal, control, PASS, FAIL, NA, CONFIG_CHECKED

FRAMEWORK = "disa_stig"


# Junos set-form BGP (hierarchical configs are flattened by ComplianceSignal.text()).
# The scope prefix (routing-instance / logical-system) keeps same-named groups apart.
_JUNOS_SCOPE = r"^set\s+((?:logical-systems\s+\S+\s+)?(?:routing-instances\s+\S+\s+)?)protocols\s+bgp\s+"
_JUNOS_NEIGHBOR = re.compile(_JUNOS_SCOPE + r"group\s+(\S+)\s+neighbor\s+(\S+)(.*)$")
_JUNOS_GROUP_AUTH = re.compile(_JUNOS_SCOPE + r"group\s+(\S+)\s+authentication-key(?:-chain)?\s")
_JUNOS_GLOBAL_AUTH = re.compile(_JUNOS_SCOPE + r"authentication-key(?:-chain)?\s")
_JUNOS_NEIGHBOR_AUTH = re.compile(r"^\s*authentication-key(?:-chain)?\s")


def _bgp_peers_and_authenticated_peers(sig: ComplianceSignal) -> tuple[set[str], set[str]]:
    """Return BGP peers and peers with an explicit auth directive.

    Cisco/FRR/EOS: ``neighbor X remote-as`` + ``neighbor X password|key-chain|...``.
    Junos: ``set [ri] protocols bgp group G neighbor X`` authenticated at neighbor,
    group, or global (per routing-instance) level by ``authentication-key[-chain]``.
    """
    peers: set[str] = set()
    authenticated: set[str] = set()
    junos_peers: dict[str, tuple[str, str]] = {}      # peer id -> (scope, group)
    group_auth: set[tuple[str, str]] = set()
    global_auth: set[str] = set()
    for line in sig.text().splitlines():
        peer = re.search(r"\bneighbor\s+(\S+)\s+remote-as\b", line)
        if peer:
            peers.add(peer.group(1))

        auth = re.search(
            r"\bneighbor\s+(\S+)\s+"
            r"(?:password\s+[789]\b|key-chain\b|authentication-key\s+encrypted\b|ao\b)",
            line,
        )
        if auth:
            authenticated.add(auth.group(1))

        jn = _JUNOS_NEIGHBOR.search(line)
        if jn:
            scope, group, nbr, rest = jn.groups()
            pid = f"junos:{scope.strip()}|{group}|{nbr}"
            junos_peers[pid] = (scope, group)
            if _JUNOS_NEIGHBOR_AUTH.search(rest):
                authenticated.add(pid)
            continue
        jg = _JUNOS_GROUP_AUTH.search(line)
        if jg:
            group_auth.add((jg.group(1), jg.group(2)))
            continue
        jgl = _JUNOS_GLOBAL_AUTH.search(line)
        if jgl:
            global_auth.add(jgl.group(1))

    for pid, (scope, group) in junos_peers.items():
        peers.add(pid)
        if (scope, group) in group_auth or scope in global_auth:
            authenticated.add(pid)
    return peers, authenticated


def _has_protocol_auth_binding(sig: ComplianceSignal) -> bool:
    """Require authentication to be attached to a routing peer/interface."""
    for line in sig.text().splitlines():
        if re.search(
            r"\bneighbor\s+\S+\s+(?:key-chain|ao|authentication-key)\b", line
        ):
            return True
        if re.search(r"\bprotocols\s+bgp\s+(?:group\s+\S+\s+)?authentication-key-chain\b",
                     line):
            return True
        if re.search(r"\b(?:ospf|isis|rip)\b.*\bauthentication\b", line):
            return True
    return False


# FIPS 198-1 = keyed-hash with an approved hash (HMAC-SHA*) or AES-CMAC. MD5
# ("message-digest", "authentication mode md5", Junos plain authentication-key = TCP-MD5)
# is NOT FIPS 198-1 and must not produce a PASS.
_FIPS_ALG = ("hmac-sha", "aes-128-cmac", "aes-cmac", "ao ")


def evaluate(sig: ComplianceSignal) -> list[dict]:
    out: list[dict] = []
    has_bgp = sig.has_bgp()
    has_proto = sig.has_routing_proto()
    plaintext = sig.has_plaintext_secret()
    bgp_peers, authenticated_bgp_peers = _bgp_peers_and_authenticated_peers(sig)
    all_bgp_peers_authenticated = bool(bgp_peers) and bgp_peers <= authenticated_bgp_peers

    # CISC-RT-000480 — unique key for each AS the BGP router peers with.
    # FAIL on plaintext auth material, PASS if BGP present with non-plaintext auth,
    # NA when this change introduces no BGP.
    if not has_bgp:
        out.append(control(
            FRAMEWORK, "CISC-RT-000480", NA,
            "no BGP configured in this change; unique-per-AS key requirement N/A",
            CONFIG_CHECKED))
    elif plaintext or not all_bgp_peers_authenticated:
        out.append(control(
            FRAMEWORK, "CISC-RT-000480", FAIL,
            "BGP present with plaintext, missing, or unverifiable per-peer encrypted "
            "authentication — fails unique encrypted per-AS key requirement",
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
    # Junos has no ttl-security knob; GTSM is a lo0 filter term matching ttl-except 255.
    has_gtsm = sig.has_token("ttl-security", "ttl-security hops", "gtsm", "ttl-except 255")
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
        has_fips_algorithm = sig.has_token(*_FIPS_ALG)
        has_fips_auth = has_fips_algorithm and _has_protocol_auth_binding(sig)
        if plaintext or not has_fips_auth:
            out.append(control(
                FRAMEWORK, "CISC-RT-000050", FAIL,
                "routing protocol present with plaintext or no FIPS 198-1 "
                "authentication (no HMAC-SHA / AES-CMAC bound to a peer or IGP "
                "interface; MD5 is not FIPS 198-1)",
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

    # Unrelated key-chain/HMAC tokens do not authenticate a BGP peer.
    ({"configs": [{"device": "r1", "vendor": "cisco_ios",
                   "config": "router bgp 65001\n neighbor 10.1.1.9 remote-as 65002\n"
                             " neighbor 10.1.1.9 maximum-prefix 5000\n"
                             "key chain UNUSED\n cryptographic-algorithm hmac-sha-256",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000480", FAIL),

    ({"configs": [{"device": "r1", "vendor": "cisco_ios",
                   "config": "router bgp 65001\n neighbor 10.1.1.9 remote-as 65002\n"
                             "key chain UNUSED\n cryptographic-algorithm hmac-sha-256",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000050", FAIL),

    # Every BGP peer has explicit, encrypted authentication.
    ({"configs": [{"device": "r1", "vendor": "cisco_ios",
                   "config": "router bgp 65001\n neighbor 10.1.1.9 remote-as 65002\n"
                             " neighbor 10.1.1.9 password 7 encrypted-value",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000480", PASS),

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

    # ── Junos (set form) ─────────────────────────────────────────────────────
    # group-level $9$ key covers every neighbor in the group -> 000480 PASS
    ({"configs": [{"device": "mx1", "vendor": "junos",
                   "config": "set protocols bgp group EBGP peer-as 65010\n"
                             "set protocols bgp group EBGP neighbor 10.1.1.1\n"
                             'set protocols bgp group EBGP authentication-key "$9$AbCdEf"',
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000480", PASS),

    # neighbor in a group with NO authentication -> 000480 FAIL
    ({"configs": [{"device": "mx1", "vendor": "junos",
                   "config": "set protocols bgp group EBGP peer-as 65010\n"
                             "set protocols bgp group EBGP neighbor 10.1.1.1",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000480", FAIL),

    # cleartext Junos key (not $9$) -> 000480 FAIL
    ({"configs": [{"device": "mx1", "vendor": "junos",
                   "config": "set protocols bgp group EBGP neighbor 10.1.1.1\n"
                             'set protocols bgp group EBGP authentication-key "letmein"',
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000480", FAIL),

    # Junos prefix-limit -> 000560 PASS
    ({"configs": [{"device": "mx1", "vendor": "junos",
                   "config": "set protocols bgp group EBGP neighbor 10.1.1.1 family inet "
                             "unicast prefix-limit maximum 5000",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000560", PASS),

    # TCP-MD5 authentication-key alone is NOT FIPS 198-1 -> 000050 FAIL
    ({"configs": [{"device": "mx1", "vendor": "junos",
                   "config": "set protocols bgp group EBGP neighbor 10.1.1.1\n"
                             'set protocols bgp group EBGP authentication-key "$9$AbCdEf"',
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000050", FAIL),

    # key-chain with hmac-sha bound at group level (TCP-AO style) -> 000050 PASS
    ({"configs": [{"device": "mx1", "vendor": "junos",
                   "config": "set security authentication-key-chains key-chain KC key 0 "
                             'secret "$9$q" algorithm hmac-sha-1-96\n'
                             "set protocols bgp group EBGP neighbor 10.1.1.1\n"
                             "set protocols bgp group EBGP authentication-key-chain KC",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000050", PASS),

    # ── Junos (hierarchical form, flattened by ComplianceSignal) ─────────────
    ({"configs": [{"device": "mx1", "vendor": "junos",
                   "config": "protocols {\n bgp {\n  group EBGP {\n   peer-as 65010;\n"
                             '   authentication-key "$9$AbCdEf";\n'
                             "   neighbor 10.1.1.1;\n  }\n }\n}",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000480", PASS),

    # an INACTIVE key is not in effect -> 000480 FAIL
    ({"configs": [{"device": "mx1", "vendor": "junos",
                   "config": "protocols {\n bgp {\n  group EBGP {\n"
                             '   inactive: authentication-key "$9$AbCdEf";\n'
                             "   neighbor 10.1.1.1;\n  }\n }\n}",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000480", FAIL),

    # Cisco OSPF MD5 message-digest is NOT FIPS 198-1 -> 000050 FAIL
    ({"configs": [{"device": "r1", "vendor": "ios",
                   "config": "interface Gi0/0\n ip ospf message-digest-key 1 md5 7 0822455D\n"
                             "router ospf 1\n area 0 authentication message-digest",
                   "grounded_commands": []}],
      "batfish": {"errors": 0, "warnings": 0, "passed": 1, "findings": []}},
     "CISC-RT-000050", FAIL),
]
