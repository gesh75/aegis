"""The approval gate — the deterministic policy that decides whether a verified change may
be promoted to production. Pure function; this is what an auditor inspects.

Rules (all must hold to ALLOW):
  G1  integrity: the bundle's sha256 must re-verify (no tampering between verify and push)
  G2  verdict:   `blocked` is never promotable; `ship_ready` is; `needs_approval` is only
                 promotable WITH a human approver + approval token
  G3  risk:      any medium/high-risk change requires approver + approval token
  G4  live:      using the live connector additionally requires explicit opt-in (allow_live)
"""
from __future__ import annotations
from dataclasses import dataclass

from ...evidence.bundler import verify
from ..risk import Tier, authorize, load_max_authorized


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str


def evaluate(bundle: dict, *, approver: str | None, approval_token: str | None,
             connector_is_live: bool, allow_live: bool) -> GateDecision:
    if not verify(bundle):                                             # G1
        return GateDecision(False, "integrity check failed — bundle tampered or malformed")

    decision = bundle.get("verdict", {}).get("decision")
    tier = bundle.get("change", {}).get("risk_tier")
    has_approval = bool(approver) and bool(approval_token)

    if decision == "blocked":                                         # G2
        return GateDecision(False, "verdict is blocked — not promotable")
    if decision == "needs_approval" and not has_approval:             # G2
        return GateDecision(False, "verdict needs_approval — human approver + token required")
    if decision not in ("ship_ready", "needs_approval"):
        return GateDecision(False, f"unpromotable verdict '{decision}'")

    if tier in ("medium", "high") and not has_approval:               # G3
        return GateDecision(False, f"{tier}-risk change requires approver + approval token")

    if connector_is_live and not allow_live:                          # G4
        return GateDecision(False, "live connector blocked — set AEGIS_PROMOTE_ALLOW_LIVE=1 "
                                   "and wire an audited connector")

    # G5  authority ceiling — NO SELF-ESCALATION. The change's REQUIRED authority is sealed
    #     in the bundle (covered by the G1 integrity check); re-derive the ceiling decision
    #     here so the gate enforces its OWN ceiling at promote time, not a recorded boolean.
    #     A change needing more autonomy than the ceiling allows -- or any hard-BLOCK change
    #     (AS/RD/RT / critical) -- is never promotable.
    authority = bundle.get("change", {}).get("authority")
    if not authority:
        return GateDecision(False, "no authority record — cannot confirm the autonomy bound "
                                   "(fail-closed)")
    try:
        required = Tier[str(authority.get("required", "")).upper()]
    except KeyError:
        return GateDecision(False, f"unrecognized required authority {authority.get('required')!r}")
    ceiling = load_max_authorized()
    if not authorize(required, ceiling).allowed:                      # G5
        return GateDecision(False, f"no-self-escalation: change requires {required.name} "
                                   f"authority, above the {ceiling.name} ceiling — blocked")

    return GateDecision(True, f"{tier or 'unknown'}-risk {decision} approved for promotion")
