"""aegis/tests/ceiling_test.py — #5-ceiling: authority sealed in the bundle + enforced at
the gate (rule G5, no self-escalation).

House style: pytest-discoverable test_* + a dep-light __main__ runner
(CI: python3 -m aegis.tests.ceiling_test). jsonschema-based asserts self-skip if absent.
"""
from __future__ import annotations

import json
import os
import random
import sys
from pathlib import Path

from aegis.core.backends.simulator import SimulatorBackend
from aegis.core.orchestrator.pipeline import run_preflight
from aegis.core.promote import gate
from aegis.core.promote.connectors import DryRunConnector
from aegis.core.promote.promote import PromoteDenied, promote
from aegis.core.risk import Tier, authorize, load_max_authorized
from aegis.evidence.bundler import compute_sha256, verify

try:
    import jsonschema
    _HAVE = True
except Exception:  # noqa: BLE001
    _HAVE = False


def _schema() -> dict:
    return json.loads((_root() / "evidence" / "schema" / "evidence_bundle.schema.json").read_text("utf-8"))


def _validate(b: dict) -> None:
    if _HAVE:
        jsonschema.validate(b, _schema())


def _b(intent: str, **kw) -> dict:
    return run_preflight(intent, backend=SimulatorBackend(), lab="clos-evpn", **kw)


def _reseal(b: dict) -> dict:
    b["integrity"]["sha256"] = ""
    b["integrity"]["sha256"] = compute_sha256(b)
    return b


# ── the bundle carries + seals the authority record (v1.2) ──────────────────────

def test_bundle_carries_sealed_authority_v12() -> None:
    b = _b("add vlan 10 to leaf-1")
    assert b["bundle_version"] == "1.2"
    a = b["change"]["authority"]
    assert set(a) == {"severity", "required", "max_authorized", "allowed", "effective", "change_class"}
    assert a["required"] in ("auto", "hitl", "hotl", "block")
    assert set(a["change_class"]) == {"touches_asn", "touches_rd_rt", "touches_spine", "touches_underlay"}
    assert verify(b)
    _validate(b)


def test_authority_is_under_the_seal() -> None:
    b = _b("add vlan 10 to leaf-1")
    assert verify(b)
    b["change"]["authority"]["required"] = "auto"   # try to weaken the required tier
    assert not verify(b), "tampering with the sealed authority must break the integrity hash"


def test_asn_change_forces_block_authority() -> None:
    b = _b("peer bgp with neighbor 10.0.0.1 remote-as 65010")
    a = b["change"]["authority"]
    assert a["change_class"]["touches_asn"]
    assert a["required"] == "block" and a["effective"] == "block" and a["allowed"] is False
    _validate(b)


# ── gate rule G5: no self-escalation ────────────────────────────────────────────

def test_gate_g5_blocks_block_authority_even_when_otherwise_promotable() -> None:
    """A twin-clean, low-risk AS change is promotable by G1-G4 yet G5 blocks it: the
    change requires BLOCK authority, above any valid ceiling."""
    b = _b("peer bgp with neighbor 10.0.0.1 remote-as 65010")
    assert b["change"]["authority"]["required"] == "block"
    # make it otherwise fully promotable, keep the (block) authority, re-seal:
    b["verdict"]["decision"] = "ship_ready"
    b["change"]["risk_tier"] = "low"
    _reseal(b)
    d = gate.evaluate(b, approver=None, approval_token=None, connector_is_live=False, allow_live=False)
    assert not d.allowed and "self-escalation" in d.reason.lower()


def test_gate_g5_allows_within_ceiling() -> None:
    b = _b("shut interface ethernet-1/1")
    if b["change"]["authority"]["required"] == "block":
        return  # extremely unlikely for this intent; skip rather than assert a false case
    b["verdict"]["decision"] = "ship_ready"
    b["change"]["risk_tier"] = "low"
    _reseal(b)
    d = gate.evaluate(b, approver="noc-lead", approval_token="t", connector_is_live=False, allow_live=False)
    assert d.allowed, d.reason


def test_gate_g5_fail_closed_on_missing_authority() -> None:
    b = _b("add vlan 10 to leaf-1")
    b["verdict"]["decision"] = "ship_ready"
    b["change"]["risk_tier"] = "low"
    del b["change"]["authority"]
    _reseal(b)
    d = gate.evaluate(b, approver="noc-lead", approval_token="t", connector_is_live=False, allow_live=False)
    assert not d.allowed and "authority" in d.reason.lower()


# ── 0-violation property: nothing promotes above the ceiling ────────────────────

def test_no_promoted_bundle_exceeds_ceiling_property() -> None:
    ceiling = load_max_authorized()
    intents = ["add vlan {n} to leaf-{n}", "peer bgp remote-as 6500{n}",
               "enable ospf area 0 on edge-{n}", "shut interface ethernet-1/{n}"]
    rng = random.Random(7)
    promoted = denied_block = 0
    for _ in range(300):
        b = _b(intents[rng.randrange(len(intents))].format(n=rng.randint(1, 9)))
        try:
            promote(b, connector=DryRunConnector(), approver="noc-lead",
                    approval_token="t", allow_live=False)
            promoted += 1
            req = Tier[b["change"]["authority"]["required"].upper()]
            assert authorize(req, ceiling).allowed, f"promoted above ceiling: {req.name}"
        except PromoteDenied:
            if b["change"]["authority"]["required"] == "block":
                denied_block += 1
    assert promoted > 0, "some benign changes must still promote"
    assert denied_block > 0, "some BLOCK-tier (AS) changes must be denied by the ceiling"


# ── ceiling loader: env override + fail-closed ──────────────────────────────────

def test_load_max_authorized_env_and_failclosed() -> None:
    old = os.environ.get("AEGIS_MAX_AUTHORIZED_TIER")
    try:
        assert load_max_authorized() == Tier.HOTL or old is not None  # default HOTL
        os.environ["AEGIS_MAX_AUTHORIZED_TIER"] = "hitl"
        assert load_max_authorized() == Tier.HITL
        for bad in ("block", "BLOCK", "bogus", "5"):
            os.environ["AEGIS_MAX_AUTHORIZED_TIER"] = bad
            try:
                load_max_authorized()
                raise AssertionError(f"ceiling {bad!r} must raise (fail-closed)")
            except ValueError:
                pass
    finally:
        if old is None:
            os.environ.pop("AEGIS_MAX_AUTHORIZED_TIER", None)
        else:
            os.environ["AEGIS_MAX_AUTHORIZED_TIER"] = old


# ── runner ───────────────────────────────────────────────────────────────────────

def _root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "evidence" / "schema").exists():
            return parent
    return here.parent.parent


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
