"""One-page CAB packet.

What changed, which intents still hold, rollback plan. Rollback is a *plan*,
not a verified execution — `rollback.verified_in_twin` is always False unless
a later phase actually applies the reverse in the twin.
"""
from __future__ import annotations


CAB_KIND = "aegis-cab-v1"


def _compliance_rows(bundle: dict) -> list:
    val = bundle.get("validation")
    if isinstance(val, dict) and "compliance" in val:
        return list(val.get("compliance") or [])
    return list(bundle.get("compliance") or [])


def _rollback_steps(bundle: dict) -> list:
    rb = bundle.get("rollback")
    if isinstance(rb, dict):
        return list(rb.get("plan") or rb.get("steps") or [])
    if isinstance(rb, list):
        return list(rb)
    return []


def to_cab(bundle: dict) -> dict:
    """Pure function. Does not verify the bundle — callers must bundler.verify first."""
    change = bundle.get("change") or {}
    twin = bundle.get("twin") or {}
    verdict = bundle.get("verdict") or {}
    configs = list(change.get("generated_configs") or [])
    rollback = _rollback_steps(bundle)
    fails = [c for c in _compliance_rows(bundle) if c.get("status") == "fail"]
    decision = verdict.get("decision")
    hold = decision not in (None, "blocked", "guard_rejected") and bool(twin.get("converged"))
    bgp = twin.get("bgp_sessions") or {}
    before = twin.get("bgp_before", bgp.get("before"))
    after = twin.get("bgp_after", bgp.get("after"))
    return {
        "kind": CAB_KIND,
        "run_id": bundle.get("run_id"),
        "created": bundle.get("created_utc") or bundle.get("created"),
        "operator": bundle.get("operator"),
        "intent": bundle.get("intent") or change.get("intent"),
        "source": bundle.get("source") or change.get("source"),
        "what_changed": [
            {
                "device": c.get("device"),
                "vendor": c.get("vendor"),
                "grounded": list(c.get("grounded_commands") or []),
                "lines": len(str(c.get("config") or "").splitlines()),
            }
            for c in configs
        ],
        "twin": {
            "id": twin.get("twin_id") or twin.get("topology"),
            "lab": twin.get("lab") or twin.get("topology"),
            "converged": twin.get("converged"),
            "apply_succeeded": twin.get("apply_succeeded"),
            "bgp": f"{before}→{after}",
        },
        "intents_that_hold": hold,
        "rollback": {
            "steps": rollback,
            "verified_in_twin": False,
            "honesty": "plan generated; reversal was not executed in this run",
        },
        "compliance_fails": fails,
        "verdict": verdict,
        "authority": change.get("authority"),
        "risk_tier": change.get("risk_tier"),
        "integrity": bundle.get("integrity"),
        "seal_present": isinstance(bundle.get("seal"), dict),
        "seal_reason": bundle.get("seal_reason"),
    }
