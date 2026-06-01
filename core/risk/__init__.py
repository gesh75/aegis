"""core/risk/ — deterministic authority model (#5): severity vs authority, hard-force
overrides for fabric-identity / spine / underlay, and the no-self-escalation ceiling."""
from __future__ import annotations

from .authority import (
    AuthorityDecision,
    ChangeClass,
    Severity,
    Tier,
    authorize,
    classify_change,
    required_authority,
    unify_severity,
)

__all__ = [
    "Severity",
    "Tier",
    "ChangeClass",
    "AuthorityDecision",
    "classify_change",
    "unify_severity",
    "required_authority",
    "authorize",
]
