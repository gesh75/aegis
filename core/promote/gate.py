"""The approval gate — the deterministic policy that decides whether a verified change may
be promoted to production. Pure function; this is what an auditor inspects.

Rules (all must hold to ALLOW):
  G0  authenticity: when a seal + pinned verifier are supplied (always, on the server),
                 the detached Ed25519 seal must verify (G0..G6 of verify_seal). The
                 bundle sha256 alone is self-consistency — anyone can recompute it over
                 forged content — so a forged ``ship_ready`` bundle dies here.
  G1  integrity: the bundle's sha256 must re-verify (no tampering between verify and push)
  G2  verdict:   `blocked` is never promotable; `ship_ready` is; `needs_approval` is only
                 promotable WITH a human approver + a verified approval token
  G3  risk:      any medium/high-risk change requires approver + verified approval token;
                 so does any change whose sealed authority is HITL or HOTL, whatever its
                 risk tier (a zero-impact peering change is still a human decision)
  G4  live:      using the live connector additionally requires explicit opt-in (allow_live)
  G5  ceiling:   re-derive required ≤ max_authorized at promote time. No self-escalation.
  SoD separation of duties: the approver may not be the change's operator (author).

Approval tokens (T1 #9 / #24): G2/G3 require an HMAC-SHA256 token (``AEGIS_APPROVE_KEY``)
bound to this bundle's sha256 + the approver identity + an expiry. v2 tokens also bind
the grounded-config hash and the target inventory fingerprint. A random non-empty string
is a deny, and so is every approval while the key is unset (fail closed, in any mode).
"""
from __future__ import annotations
from dataclasses import dataclass

from ...evidence.bundler import verify
from ..risk import Tier, authorize, load_max_authorized, requires_approval
from ..seal import verify_seal
from .tokens import Approval, config_digest, inventory_digest, verify_approval


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    approval_method: str = "none"
    token_sha256: str | None = None


def evaluate(bundle: dict, *, approver: str | None, approval_token: str | None,
             connector_is_live: bool, allow_live: bool,
             live_inventory_sha256: str | None = None,
             seal: dict | None = None, verifier=None, require_seal: bool = False,
             require_verified_approval: bool = False) -> GateDecision:
    if require_seal and not isinstance(seal, dict):                   # G0
        return GateDecision(False, "unsealed bundle — promotion requires a valid Ed25519 "
                                   "seal from this server (sha256 alone is not origin proof)")
    if isinstance(seal, dict) or require_seal:                         # G0
        if verifier is None:
            return GateDecision(False, "seal supplied but no pinned verifier — cannot "
                                       "authenticate (fail-closed)")
        sv = verify_seal(bundle, seal, verifier)
        if not sv.valid:
            return GateDecision(False, f"seal verification failed at {sv.gate}: {sv.reason}")

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
    if has_approval and require_verified_approval and approval.method != "hmac-sha256":
        has_approval = False
        approval = Approval(False, approval.method,
                            "production mode requires an HMAC-verified approval token",
                            approval.token_sha256)

    def _deny(reason: str) -> GateDecision:
        return GateDecision(False, reason, approval.method, approval.token_sha256)

    # The sealed authority tier is read here so HITL/HOTL can demand approval (G3) whatever
    # the risk tier says; a missing or unparsable record is still denied at G5, below.
    authority = bundle.get("change", {}).get("authority")
    required = None
    if isinstance(authority, dict):
        try:
            required = Tier[str(authority.get("required", "")).upper()]
        except KeyError:
            pass
    needs_human = required is not None and requires_approval(required)

    if decision == "blocked":                                         # G2
        return _deny("verdict is blocked — not promotable")
    if decision == "needs_approval" and not has_approval:             # G2
        return _deny(f"verdict needs_approval — {approval.reason}")
    if decision not in ("ship_ready", "needs_approval"):
        return _deny(f"unpromotable verdict '{decision}'")

    if tier in ("medium", "high") and not has_approval:               # G3
        return _deny(f"{tier}-risk change requires approver + verified approval token "
                     f"({approval.reason})")

    if needs_human and not has_approval:                              # G3
        return _deny(f"{required.name} authority requires approver + verified approval "
                     f"token, whatever the risk tier ({approval.reason})")

    operator = str(bundle.get("operator") or "").strip().lower()      # SoD
    needs = decision == "needs_approval" or tier in ("medium", "high") or needs_human
    if needs and operator and operator == str(approver or "").strip().lower():
        return _deny("separation of duties: the approver authored this change "
                     f"(operator {operator!r}) — a second person must approve")

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
