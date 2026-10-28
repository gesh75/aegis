"""aegis/tests/authority_test.py — #5 deterministic authority gate + no-self-escalation.

House style: pytest-discoverable test_* + a dep-light __main__ runner
(CI: python3 -m aegis.tests.authority_test). Pure logic, no network. Includes the CROSS-2
differential of the canonical severity engine vs the two legacy AEGIS scorers
(guards.risk_tier 3-bucket, bundler._severity 5-bucket).
"""
from __future__ import annotations

import itertools
import os
import sys

from aegis.core.backends.base import GeneratedConfig
from aegis.core.backends.simulator import SimulatorBackend
from aegis.core.orchestrator.guards import risk_tier
from aegis.core.orchestrator.pipeline import run_preflight
from aegis.core.risk import (
    ChangeClass,
    Severity,
    Tier,
    authorize,
    classify_change,
    required_authority,
    unify_severity,
)
from aegis.core.seal import Ed25519Signer, seal_response
from aegis.evidence.bundler import _severity  # legacy 5-bucket scorer (differential ref)


def _cfg(config: str, device: str = "leaf-1") -> GeneratedConfig:
    return GeneratedConfig(device=device, vendor="frr", config=config, grounded_commands=[])


# ── unify_severity reconciles the two legacy scorers ────────────────────────────

def test_unify_severity_table() -> None:
    cases = [
        # (errors, devices, dropped, converged) -> canonical severity
        (0, 0, 0, True, Severity.NONE),
        (0, 1, 0, True, Severity.LOW),
        (0, 3, 0, True, Severity.MEDIUM),
        (0, 4, 0, True, Severity.HIGH),
        (0, 1, 1, True, Severity.HIGH),       # a dropped session is HIGH
        (1, 1, 0, True, Severity.CRITICAL),   # batfish error
        (0, 1, 0, False, Severity.CRITICAL),  # non-convergence
    ]
    for e, d, dr, c, exp in cases:
        got = unify_severity(batfish_errors=e, devices_affected=d, sessions_dropped=dr, converged=c)
        assert got == exp, f"{(e, d, dr, c)} -> {got.name}, want {exp.name}"


def test_differential_vs_legacy_scorers() -> None:
    """CROSS-2 differential: canonical vs guards.risk_tier (3-bucket) and bundler._severity
    (5-bucket). The canonical equals the richer (bundler) engine by construction; guards
    disagrees in documented ways (it has no NONE/CRITICAL and over-tiers a clean 1-device)."""
    map3 = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH}
    map5 = {"none": Severity.NONE, "low": Severity.LOW, "medium": Severity.MEDIUM,
            "high": Severity.HIGH, "critical": Severity.CRITICAL}
    disagreements = []
    for e, d, dr, c in itertools.product((0, 1), (0, 1, 2, 4), (0, 1), (True, False)):
        canon = unify_severity(batfish_errors=e, devices_affected=d, sessions_dropped=dr, converged=c)
        bundler = map5[_severity(d, dr, e, c)]
        guards = map3[risk_tier(batfish_errors=e, devices_affected=d, sessions_dropped=dr, converged=c)]
        assert canon == bundler, f"canon {canon.name} != bundler {bundler.name} for {(e, d, dr, c)}"
        if canon != guards:
            disagreements.append((e, d, dr, c, canon.name, guards.name))
    assert disagreements, "expected guards-vs-canonical disagreements (the reason to unify)"
    # the headline disagreement: one clean device -> canonical LOW, guards MEDIUM
    assert (0, 1, 0, True, "LOW", "MEDIUM") in disagreements
    # guards collapses non-convergence (CRITICAL) into HIGH
    assert (0, 1, 0, False, "CRITICAL", "HIGH") in disagreements


# ── classify_change: AS/RD/RT (reliable) + spine/underlay (heuristic) ────────────

def test_classify_detects_asn() -> None:
    old = os.environ.get("AEGIS_PEER_AS_POLICY")
    try:
        os.environ.pop("AEGIS_PEER_AS_POLICY", None)  # D1 default: hitl
        assert classify_change([_cfg("router bgp 65001")]).touches_asn
        assert classify_change([_cfg("set routing-options autonomous-system 65001")]).touches_asn
        peer = classify_change([_cfg("set protocols bgp group X peer-as 65002")])
        assert peer.touches_peer_as and not peer.touches_asn
        peer = classify_change([_cfg("neighbor 10.0.0.1 remote-as 65003")])
        assert peer.touches_peer_as and not peer.touches_asn
        os.environ["AEGIS_PEER_AS_POLICY"] = "block"  # original: any AS is fabric identity
        assert classify_change([_cfg("set protocols bgp group X peer-as 65002")]).touches_asn
        assert classify_change([_cfg("neighbor 10.0.0.1 remote-as 65003")]).touches_asn
        assert not classify_change([_cfg("interface eth0\n ip address 10.0.0.1/31")]).touches_asn
    finally:
        if old is None:
            os.environ.pop("AEGIS_PEER_AS_POLICY", None)
        else:
            os.environ["AEGIS_PEER_AS_POLICY"] = old


def test_classify_detects_rd_rt() -> None:
    assert classify_change([_cfg("set routing-instances V route-distinguisher 65000:1")]).touches_rd_rt
    assert classify_change([_cfg("route-target target:65000:100")]).touches_rd_rt
    assert not classify_change([_cfg("interface eth0")]).touches_rd_rt


# ── fabric-identity regexes: every vendor spelling, table-driven ────────────────
# Positives are statements that set the device's own / local-override AS (or an RD/RT) in
# the spellings real vendors and structured (JSON/XML) renderings use. Negatives are
# near-misses that must NOT trip the BLOCK floor. Synthetic values only (RFC 5737 / 5398).

_LOCAL_AS_POSITIVE = [
    "set / network-instance default protocols bgp group ebgp local-as as-number 65001",
    "local-as as-number 65001",
    "local-as    as-number    4200000001",
    "local-as { as-number 65001 }",
    "local-as {\n  as-number 65001\n}",
    '{"local-as": {"as-number": 65001}}',
    '"local-as": [{"as-number": 65001}]',
    "<local-as><as-number>65001</as-number></local-as>",
    '"autonomous-system": 65001',
    "<autonomous-system>65001</autonomous-system>",
    "set / network-instance default protocols bgp autonomous-system 65001",
    "set routing-options autonomous-system 65001",
    "set routing-options autonomous-system 65000.1",
    "neighbor 192.0.2.1 local-as 65002 no-prepend replace-as",
    "LOCAL-AS AS-NUMBER 65001",
    "local_as: 65001",
    "local-as future-unrecognized-form",     # any local-as text fails closed
    "router bgp 65001",
    "router bgp 65000.1",
]
_LOCAL_AS_NEGATIVE = [
    "interface ethernet-1/1\n subinterface 0 ipv4 address 192.0.2.1/31",
    "ip as-path access-list 10 permit ^65001_",
    "set protocols bgp group X neighbor 192.0.2.1 description local-site",
    "description local assets",
    "set / network-instance default protocols bgp neighbor 192.0.2.1 peer-as 65002",
    "neighbor 192.0.2.1 remote-as external",
    "router ospf 1",
    "vlan 100 name local",
]
_PEER_AS_POSITIVE = [
    "neighbor 192.0.2.1 remote-as 65002",
    "neighbor 192.0.2.1 remote-as external",
    "neighbor 192.0.2.1 remote-as internal",
    "neighbor 192.0.2.1 remote-as 4200000002",
    "set protocols bgp group X peer-as 65002",
    "set / network-instance default protocols bgp neighbor 192.0.2.1 peer-as 65002",
    '"peer-as": 65002',
    "<peer-as>65002</peer-as>",
    "PEER-AS 65002",
]
_PEER_AS_NEGATIVE = [
    "interface eth0\n ip address 192.0.2.1/31",
    "neighbor 192.0.2.1 description uplink",
    "set protocols bgp group X local-as 65001",       # local, not peer
]


def _hitl_policy():
    old = os.environ.get("AEGIS_PEER_AS_POLICY")
    os.environ.pop("AEGIS_PEER_AS_POLICY", None)      # D1 default: hitl
    return old


def _restore_policy(old) -> None:
    if old is None:
        os.environ.pop("AEGIS_PEER_AS_POLICY", None)
    else:
        os.environ["AEGIS_PEER_AS_POLICY"] = old


def test_local_as_forms_set_touches_asn() -> None:
    old = _hitl_policy()
    try:
        for text in _LOCAL_AS_POSITIVE:
            cc = classify_change([_cfg(text)])
            assert cc.touches_asn, f"local-AS form not detected: {text!r}"
            assert required_authority(Severity.LOW, cc) == Tier.BLOCK, f"not BLOCK: {text!r}"
        for text in _LOCAL_AS_NEGATIVE:
            assert not classify_change([_cfg(text)]).touches_asn, f"false local-AS hit: {text!r}"
    finally:
        _restore_policy(old)


def test_peer_as_forms_set_peer_flag_or_block() -> None:
    old = _hitl_policy()
    try:
        for text in _PEER_AS_POSITIVE:
            cc = classify_change([_cfg(text)])
            assert cc.touches_peer_as and not cc.touches_asn, f"peer-AS form (hitl): {text!r}"
            assert required_authority(Severity.LOW, cc) >= Tier.HITL, f"peer below HITL: {text!r}"
        for text in _PEER_AS_NEGATIVE:
            assert not classify_change([_cfg(text)]).touches_peer_as, f"false peer hit: {text!r}"
        os.environ["AEGIS_PEER_AS_POLICY"] = "block"  # original: a peer AS is fabric identity
        for text in _PEER_AS_POSITIVE:
            cc = classify_change([_cfg(text)])
            assert cc.touches_asn, f"peer-AS form not BLOCK under policy=block: {text!r}"
            assert required_authority(Severity.LOW, cc) == Tier.BLOCK
        for text in _LOCAL_AS_POSITIVE:
            assert classify_change([_cfg(text)]).touches_asn, f"block policy: {text!r}"
    finally:
        _restore_policy(old)


_RD_RT_POSITIVE = [
    "rd 65000:1", "rd 4200000000:1", "rd 10.0.0.1:100", "rd 1.100:100", "rd 65000.65000:1",
    "rd auto", "RD AUTO", "rt 65000:100", "rt 10.0.0.1:100",
    " vrf definition CUST\n  rd 10.0.0.1:100",
    "vrf context CUST\n  rd auto",
    "vrf-target target:10.0.0.1:1", "vrf-target auto", "vrf-target import target:65000:1",
    "set extcommunity rt 10.0.0.1:100", "set extcommunity rt 65000.1:100 additive",
    "set policy-options community C members target:10.0.0.1:1",
    "set policy-options community C members target:65000.1:1",
    "set policy-options community C members target:65000:1",
    "route-target both auto", "route-target import 10.0.0.1:100",
    "route-distinguisher 10.0.0.1:1",
    "set / network-instance X protocols bgp-vpn bgp-instance 1 route-distinguisher rd 65000:1",
    "rd vpn export 10.0.0.1:100", "rt vpn both 65000:100",
    '"rd": "10.0.0.1:100"', "<rd>10.0.0.1:100</rd>", '"rt": "auto"',
    "vpn-target 65000:1 export-extcommunity",
]
_RD_RT_NEGATIVE = [
    "interface eth0",
    "interface Ethernet1/1\n description 3rd floor uplink",
    "description rd office",
    "description rt auto-tuned",
    "description target: new server",
    "hostname core-rd",
    "hostname core-rt 1",
    "ip route 192.0.2.0/24 198.51.100.1",
    "ntp server 192.0.2.1 prefer",
    "set protocols bgp group X peer-as 65002",
]


def test_rd_rt_forms_set_touches_rd_rt() -> None:
    for text in _RD_RT_POSITIVE:
        cc = classify_change([_cfg(text)])
        assert cc.touches_rd_rt, f"RD/RT form not detected: {text!r}"
        assert required_authority(Severity.NONE, cc) == Tier.BLOCK, f"not BLOCK: {text!r}"
    for text in _RD_RT_NEGATIVE:
        assert not classify_change([_cfg(text)]).touches_rd_rt, f"false RD/RT hit: {text!r}"


def test_classifier_linear_on_hostile_input() -> None:
    """Regexes stay linear: long near-miss inputs classify in well under a second."""
    import time
    hostile = ["rd " + "a" * 200_000, "rt" + " " * 200_000 + "x", "local" + "-" * 100_000,
               ("rd " * 50_000), "target:" + "1." * 100_000, "autonomous" + "-" * 100_000]
    t0 = time.monotonic()
    for text in hostile:
        classify_change([_cfg(text)])
    assert time.monotonic() - t0 < 2.0, "classifier is not linear on hostile input"


def _run_import(vendor: str, config: str) -> dict:
    return run_preflight("", backend=SimulatorBackend(converge_fail_rate=0.0,
                                                      batfish_error_rate=0.0),
                         lab="single", source="config_import", operator="ci",
                         imported_configs=[{"device": "leaf-1", "vendor": vendor,
                                            "config": config}])


def test_end_to_end_vendor_spellings_are_block_and_unsealed() -> None:
    """The shipped path (config_import -> authority -> seal): each spelling the old regexes
    missed must record required=block, allowed=false, and get NO seal."""
    old = _hitl_policy()
    try:
        signer = Ed25519Signer.generate()
        cases = [
            ("srlinux", "set / network-instance default protocols bgp group ebgp "
                        "local-as as-number 65001"),
            ("ios", "vrf definition CUST\n rd 10.0.0.1:100"),
            ("junos", "set routing-instances CUST vrf-target auto"),
            ("ios", "route-map RM permit 10\n set extcommunity rt 10.0.0.1:100"),
        ]
        for vendor, config in cases:
            b = _run_import(vendor, config)
            au = b["change"]["authority"]
            assert au["required"] == "block" and not au["allowed"], f"{config!r}: {au}"
            seal, reason = seal_response(b, signer, "2026-01-01T00:00:00+00:00")
            assert seal is None and reason, f"sealed a fabric-identity change: {config!r}"
        b = _run_import("ios", "interface Loopback9\n description test")
        au = b["change"]["authority"]
        assert au["required"] != "block" and not au["change_class"]["touches_asn"] \
            and not au["change_class"]["touches_rd_rt"], f"a plain change forced to BLOCK: {au}"
    finally:
        _restore_policy(old)


def test_classify_spine_underlay_heuristic() -> None:
    assert classify_change([_cfg("x", device="dc1-spine-01")]).touches_spine
    assert classify_change([_cfg("router ospf 1\n network 10.0.0.0/24 area 0")]).touches_underlay
    leaf = classify_change([_cfg("# add vlan 10", device="leaf-1")])
    assert not leaf.touches_spine and not leaf.touches_underlay


# ── required_authority: severity base + hard-force overrides ─────────────────────

def test_severity_base_mapping() -> None:
    none = ChangeClass()
    assert required_authority(Severity.NONE, none) == Tier.AUTO
    assert required_authority(Severity.LOW, none) == Tier.AUTO
    assert required_authority(Severity.MEDIUM, none) == Tier.HITL
    assert required_authority(Severity.HIGH, none) == Tier.HOTL
    assert required_authority(Severity.CRITICAL, none) == Tier.BLOCK


def test_hardforce_fabric_identity_is_always_block() -> None:
    assert required_authority(Severity.LOW, ChangeClass(touches_asn=True)) == Tier.BLOCK
    assert required_authority(Severity.NONE, ChangeClass(touches_rd_rt=True)) == Tier.BLOCK


def test_hardforce_spine_underlay_never_auto() -> None:
    assert required_authority(Severity.LOW, ChangeClass(touches_spine=True)) == Tier.HOTL
    assert required_authority(Severity.NONE, ChangeClass(touches_underlay=True)) == Tier.HOTL
    # severity can still escalate above the spine/underlay floor
    assert required_authority(Severity.CRITICAL, ChangeClass(touches_spine=True)) == Tier.BLOCK


def test_hardforce_property_fabric_identity_never_below_block() -> None:
    for sev in Severity:
        for asn, rdrt in itertools.product((True, False), repeat=2):
            t = required_authority(sev, ChangeClass(touches_asn=asn, touches_rd_rt=rdrt))
            if asn or rdrt:
                assert t == Tier.BLOCK, f"fabric-identity must BLOCK (sev={sev.name})"


def test_spine_underlay_never_auto_property() -> None:
    for sev in Severity:
        for sp, ul in itertools.product((True, False), repeat=2):
            t = required_authority(sev, ChangeClass(touches_spine=sp, touches_underlay=ul))
            if sp or ul:
                assert t >= Tier.HOTL, f"spine/underlay must be >= HOTL (sev={sev.name})"


# ── no-self-escalation ceiling ──────────────────────────────────────────────────

def test_authorize_allows_within_ceiling() -> None:
    d = authorize(Tier.HITL, Tier.HOTL)
    assert d.allowed and d.effective == Tier.HITL


def test_authorize_blocks_self_escalation() -> None:
    d = authorize(Tier.HOTL, Tier.HITL)
    assert not d.allowed and d.effective == Tier.BLOCK and "NO-SELF-ESCALATION" in d.reason


def test_no_self_escalation_zero_violations_property() -> None:
    """The invariant: effective authority is NEVER above the ceiling. 0 violations over
    every (required, ceiling) pair."""
    violations = 0
    for required in Tier:
        for ceiling in Tier:
            d = authorize(required, ceiling)
            if d.effective != Tier.BLOCK and d.effective > ceiling:
                violations += 1
    assert violations == 0, f"{violations} self-escalation violations"


def test_end_to_end_low_severity_asn_change_is_blocked() -> None:
    """A twin-clean, single-device change that edits an AS number must still BLOCK:
    severity alone (LOW) would say AUTO; the change class forces BLOCK, and an AUTO-ceiling
    agent cannot push it."""
    configs = [_cfg("router bgp 65010\n neighbor 10.0.0.1 remote-as 65011", device="leaf-1")]
    sev = unify_severity(batfish_errors=0, devices_affected=1, sessions_dropped=0, converged=True)
    assert sev == Severity.LOW
    cc = classify_change(configs)
    assert cc.touches_asn
    req = required_authority(sev, cc)
    assert req == Tier.BLOCK
    assert not authorize(req, Tier.AUTO).allowed


# ── runner ───────────────────────────────────────────────────────────────────────

def _run_all() -> int:
    funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failures = 0
    for fn in funcs:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(funcs) - failures}/{len(funcs)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_run_all())
