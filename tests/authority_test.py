"""aegis/tests/authority_test.py — #5 deterministic authority gate + no-self-escalation.

House style: pytest-discoverable test_* + a dep-light __main__ runner
(CI: python3 -m aegis.tests.authority_test). Pure logic, no network. Includes the CROSS-2
differential of the canonical severity engine vs the two legacy AEGIS scorers
(guards.risk_tier 3-bucket, bundler._severity 5-bucket).
"""
from __future__ import annotations

import itertools
import sys

from aegis.core.backends.base import GeneratedConfig
from aegis.core.orchestrator.guards import risk_tier
from aegis.core.risk import (
    ChangeClass,
    Severity,
    Tier,
    authorize,
    classify_change,
    required_authority,
    unify_severity,
)
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
    assert classify_change([_cfg("router bgp 65001")]).touches_asn
    assert classify_change([_cfg("set protocols bgp group X peer-as 65002")]).touches_asn
    assert classify_change([_cfg("neighbor 10.0.0.1 remote-as 65003")]).touches_asn
    assert not classify_change([_cfg("interface eth0\n ip address 10.0.0.1/31")]).touches_asn


def test_classify_detects_rd_rt() -> None:
    assert classify_change([_cfg("set routing-instances V route-distinguisher 65000:1")]).touches_rd_rt
    assert classify_change([_cfg("route-target target:65000:100")]).touches_rd_rt
    assert not classify_change([_cfg("interface eth0")]).touches_rd_rt


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
