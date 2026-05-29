"""Deterministic guards: pre-checks, risk tiering, approval gate.

Pure functions, no AI. This is what an auditor inspects to understand *why* a change
was allowed or blocked. Logic must be explainable and stable.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class PreCheck:
    ok: bool
    reason: str


def precheck_intent(intent: str) -> PreCheck:
    """Reject malformed / obviously unsafe intents before spending twin resources."""
    if intent is None or not intent.strip():
        return PreCheck(False, "empty intent")
    if len(intent) > 4000:
        return PreCheck(False, "intent exceeds 4000 chars (possible injection/abuse)")
    # crude prompt-injection tripwire — the LLM step is sandboxed, but flag anyway
    lowered = intent.lower()
    for needle in ("ignore previous", "disregard instructions", "system prompt"):
        if needle in lowered:
            return PreCheck(False, f"intent contains injection marker: {needle!r}")
    return PreCheck(True, "ok")


def risk_tier(*, batfish_errors: int, devices_affected: int,
              sessions_dropped: int, converged: bool) -> str:
    """Map verified twin outcome -> low | medium | high. Deterministic."""
    if batfish_errors > 0 or not converged or sessions_dropped > 0:
        return "high"
    if devices_affected >= 4:
        return "high"
    if devices_affected >= 1:
        return "medium"
    return "low"


def approval_required(tier: str) -> bool:
    """High-risk changes never auto-ship; they require an explicit human approve."""
    return tier == "high"
