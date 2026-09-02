"""The approval gate — the deterministic policy that decides whether a verified change may
be promoted to production. Pure function; this is what an auditor inspects.

Rules (all must hold to ALLOW):
  G1  integrity: the bundle's sha256 must re-verify (no tampering between verify and push)
  G2  verdict:   `blocked` is never promotable; `ship_ready` is; `needs_approval` is only
                 promotable WITH a human approver + a verified approval token
  G3  risk:      any medium/high-risk change requires approver + verified approval token
  G4  live:      using the live connector additionally requires explicit opt-in (allow_live)
  G5  ceiling:   re-derive required ≤ max_authorized at promote time. No self-escalation.

Approval tokens (T1 #9 / #24): when ``AEGIS_APPROVE_KEY`` is set, G2/G3 require an
HMAC-SHA256 token bound to this bundle's sha256 + the approver identity + an expiry.
v2 tokens also bind the grounded-config hash and the target inventory fingerprint.
A random non-empty string is a deny. When the key is unset the pair is recorded as
``asserted-unverified`` so the honesty tier is visible on the promotion record.
"""
from __future__ import annotations
from dataclasses import dataclass

from ...evidence.bundler import verify
from ..risk import Tier, authorize, load_max_authorized
from .tokens import config_digest, inventory_digest, verify_approval


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    approval_method: str = "none"
    token_sha256: str | None = None


def evaluate(bundle: dict, *, approver: str | None, approval_token: str | None,
             connector_is_live: bool, allow_live: bool,
             live_inventory_sha256: str | None = None) -> GateDecision:
    if not verify(bundle):                                             # G1
        return GateDecision(False, "integrity check failed — bundle tampered or malformed")

    decision = bundle.get("verdict", {}).get("decision")
    tier = bundle.get("change", {}).get("risk_tier")
    digest = (bundle.get("integrity") or {}).get("sha256") or ""
    cfg = config_digest(bundle)
    inv = (live_inventory_sha256 or "").strip().lower() or inventory_digest(bundle)
    approval = verify_approval(approver, approval_token, digest,
                               config_sha256=cfg, inventory_sha256=inv)
    has_approval = approval.ok

    def _deny(reason: str) -> GateDecision:
        return GateDecision(False, reason, approval.method, approval.token_sha256)

    if decision == "blocked":                                         # G2
        return _deny("verdict is blocked — not promotable")
    if decision == "needs_approval" and not has_approval:             # G2
        return _deny(f"verdict needs_approval — {approval.reason}")
    if decision not in ("ship_ready", "needs_approval"):
        return _deny(f"unpromotable verdict '{decision}'")

    if tier in ("medium", "high") and not has_approval:               # G3
        return _deny(f"{tier}-risk change requires approver + verified approval token "
                     f"({approval.reason})")

    if connector_is_live and not allow_live:                          # G4
        return _deny("live connector blocked — set AEGIS_PROMOTE_ALLOW_LIVE=1 "
                     "and wire an audited connector")

    # G5  authority ceiling — NO SELF-ESCALATION. The change's REQUIRED authority is sealed
    #     in the bundle (covered by the G1 integrity check); re-derive the ceiling decision
    #     here so the gate enforces its OWN ceiling at promote time, not a recorded boolean.
    #     A change needing more autonomy than the ceiling allows -- or any hard-BLOCK change
    #     (AS/RD/RT / critical) -- is never promotable.
    authority = bundle.get("change", {}).get("authority")
    if not authority:
        return _deny("no authority record — cannot confirm the autonomy bound "
                     "(fail-closed)")
    try:
        required = Tier[str(authority.get("required", "")).upper()]
    except KeyError:
        return _deny(f"unrecognized required authority {authority.get('required')!r}")
    ceiling = load_max_authorized()
    if not authorize(required, ceiling).allowed:                      # G5
        return _deny(f"no-self-escalation: change requires {required.name} "
                     f"authority, above the {ceiling.name} ceiling — blocked")

    return GateDecision(True, f"{tier or 'unknown'}-risk {decision} approved for promotion",
                        approval.method if has_approval else "none",
                        approval.token_sha256 if has_approval else None)
