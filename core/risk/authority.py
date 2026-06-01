"""core/risk/authority.py — the deterministic per-risk-tier authority model (#5).

Two ORTHOGONAL axes, both pure and auditable:

  Severity (how bad if it goes wrong)     : NONE < LOW < MEDIUM < HIGH < CRITICAL
  Authority (how much autonomy is allowed): AUTO < HITL < HOTL < BLOCK

The product insight is that these are NOT the same axis. A LOW-severity change to a
fabric-identity construct (AS number, route-distinguisher / route-target) is still BLOCK,
and a spine/underlay touch is never fully automated no matter how clean the twin looked.
`required_authority` derives a base tier from severity, then applies hard-force overrides
from the change class, and returns the MOST RESTRICTIVE of the two.

`authorize` is the no-self-escalation ceiling: the computed `required` authority must be
<= a `max_authorized` ceiling, else the change is BLOCKED — an agent can never grant
itself more autonomy than its ceiling allows. (Binding `max_authorized` to a hardware-PIV
-signed, compiled-in value is the #5-ceiling / CROSS-3 follow-up; this module ships the
deterministic invariant that signature will protect — no crypto is claimed here.)

`unify_severity` reconciles AEGIS's two existing severity scorers — guards.risk_tier's
3-bucket scale and bundler._severity's 5-bucket scale — into one canonical 5-bucket scale.
The richer engine wins; tests/authority_test.py carries the differential vs both.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import IntEnum

from ..backends.base import GeneratedConfig


class Severity(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Tier(IntEnum):
    """Authority tier — how much autonomy a verified change is allowed. Ordered so a
    HIGHER value is MORE restrictive (less autonomy)."""

    AUTO = 0   # fully automated, no human
    HITL = 1   # human-in-the-loop: explicit approval before apply
    HOTL = 2   # human-on-the-loop: applied under monitoring, human can intervene/abort
    BLOCK = 3  # never auto-promotable


@dataclass(frozen=True)
class ChangeClass:
    """What fabric construct the change touches — drives the hard-force overrides.

    AS/RD/RT detection is regex over the candidate config and is reliable across vendors.
    The spine/underlay flags are a documented HEURISTIC (device-name + underlay-protocol
    patterns); a production deployment should back them with an authoritative topology
    role source (containerlab labels / NetBox device role). Until then they bias toward
    FAIL CLOSED — an IGP/underlay-looking change is treated as touching the underlay."""

    touches_asn: bool = False
    touches_rd_rt: bool = False
    touches_spine: bool = False
    touches_underlay: bool = False

    @property
    def is_fabric_identity(self) -> bool:
        """AS number / RD / RT — the identity of the fabric. Never auto-changed."""
        return self.touches_asn or self.touches_rd_rt


# ── change classification (regex, fail-closed) ──────────────────────────────────

_ASN_RE = re.compile(
    r"(?:autonomous-system|remote-as|peer-as|local-as)\s+\d+|router\s+bgp\s+\d+",
    re.IGNORECASE,
)
_RD_RT_RE = re.compile(
    r"route-(?:distinguisher|target)|\brd\s+\d+:\d+|\brt\s+\d+:\d+|target:\d+:\d+",
    re.IGNORECASE,
)
_UNDERLAY_CONFIG_RE = re.compile(r"\b(?:underlay|ospf|isis|is-is)\b", re.IGNORECASE)
_SPINE_NAME_RE = re.compile(r"\bspine\b", re.IGNORECASE)
_UNDERLAY_NAME_RE = re.compile(r"\b(?:underlay|super-?spine)\b", re.IGNORECASE)


def classify_change(configs: list[GeneratedConfig]) -> ChangeClass:
    """Classify candidate configs into fabric-construct flags (the hard-force triggers)."""
    text = "\n".join(c.get("config", "") for c in configs)
    names = " ".join(c.get("device", "") for c in configs)
    return ChangeClass(
        touches_asn=bool(_ASN_RE.search(text)),
        touches_rd_rt=bool(_RD_RT_RE.search(text)),
        touches_spine=bool(_SPINE_NAME_RE.search(names)),
        touches_underlay=bool(_UNDERLAY_NAME_RE.search(names) or _UNDERLAY_CONFIG_RE.search(text)),
    )


# ── canonical severity (reconciles guards.risk_tier + bundler._severity) ─────────

def unify_severity(*, batfish_errors: int, devices_affected: int,
                   sessions_dropped: int, converged: bool) -> Severity:
    """One canonical 5-bucket severity. Mirrors bundler._severity (the richer engine);
    the differential test shows where guards.risk_tier's 3-bucket scale collapses."""
    if not converged or batfish_errors > 0:
        return Severity.CRITICAL
    if sessions_dropped > 0:
        return Severity.HIGH
    if devices_affected >= 4:
        return Severity.HIGH
    if devices_affected >= 2:
        return Severity.MEDIUM
    if devices_affected >= 1:
        return Severity.LOW
    return Severity.NONE


# ── severity x change-class -> required authority ───────────────────────────────

_SEVERITY_BASE: dict[Severity, Tier] = {
    Severity.NONE: Tier.AUTO,
    Severity.LOW: Tier.AUTO,
    Severity.MEDIUM: Tier.HITL,
    Severity.HIGH: Tier.HOTL,
    Severity.CRITICAL: Tier.BLOCK,
}


def required_authority(severity: Severity, change_class: ChangeClass) -> Tier:
    """The minimum authority tier a change requires. Base tier from severity, then
    hard-force overrides from the change class; the result is the MOST RESTRICTIVE.

    Hard-force (regardless of how clean the twin looked):
      * AS number / RD / RT touch -> BLOCK   (fabric identity is never auto-changed)
      * spine or underlay touch    -> >= HOTL (never fully automated)
    """
    tier = _SEVERITY_BASE[severity]
    if change_class.is_fabric_identity:
        tier = max(tier, Tier.BLOCK)
    if change_class.touches_spine or change_class.touches_underlay:
        tier = max(tier, Tier.HOTL)
    return tier


@dataclass(frozen=True)
class AuthorityDecision:
    required: Tier
    max_authorized: Tier
    allowed: bool
    effective: Tier
    reason: str


def authorize(required: Tier, max_authorized: Tier) -> AuthorityDecision:
    """No-self-escalation ceiling: a change may proceed at `required` ONLY if
    required <= max_authorized; otherwise it is BLOCKED. An agent can never grant itself
    more autonomy than its ceiling allows.

    `max_authorized` is a plain input here. The #5-ceiling / CROSS-3 follow-up binds it to
    a hardware-PIV-signed, compiled-in value so the ceiling itself is tamper-proof; this
    function is the deterministic invariant that signature protects."""
    allowed = required <= max_authorized
    effective = required if allowed else Tier.BLOCK
    if allowed:
        reason = (f"required {required.name} <= ceiling {max_authorized.name}: "
                  f"allowed at {required.name}")
    else:
        reason = (f"NO-SELF-ESCALATION: required {required.name} exceeds ceiling "
                  f"{max_authorized.name} -> BLOCK")
    return AuthorityDecision(required=required, max_authorized=max_authorized,
                             allowed=allowed, effective=effective, reason=reason)


_DEFAULT_MAX_AUTHORIZED = Tier.HOTL


def load_max_authorized() -> Tier:
    """The deployment's autonomy ceiling. Env AEGIS_MAX_AUTHORIZED_TIER (AUTO|HITL|HOTL),
    default HOTL. BLOCK is rejected as a ceiling (it would authorize fabric-identity /
    critical changes). An invalid value RAISES (fail-closed, loud) rather than silently
    defaulting to something permissive.

    NOTE: env-configured today. The CROSS-3 follow-up binds it to a hardware-PIV signature +
    compiled-in public key so it cannot be raised by editing the environment — the
    tamper-proofing the no-self-escalation invariant ultimately needs. This ships the
    deterministic enforcement that signature will protect."""
    raw = os.environ.get("AEGIS_MAX_AUTHORIZED_TIER")
    if not raw:
        return _DEFAULT_MAX_AUTHORIZED
    try:
        tier = Tier[raw.strip().upper()]
    except KeyError:
        raise ValueError(f"AEGIS_MAX_AUTHORIZED_TIER must be one of AUTO|HITL|HOTL (got {raw!r})")
    if tier == Tier.BLOCK:
        raise ValueError("AEGIS_MAX_AUTHORIZED_TIER=BLOCK is invalid — a ceiling cannot "
                         "authorize BLOCK-tier (fabric-identity / critical) changes")
    return tier


def authority_record(severity: Severity, change_class: ChangeClass,
                     max_authorized: Tier) -> dict:
    """The sealed change.authority object: severity (how bad if it fails) + the required
    authority (how much autonomy), the ceiling it was checked against, and the
    no-self-escalation decision. Lowercase strings to match the bundle vocabulary."""
    required = required_authority(severity, change_class)
    decision = authorize(required, max_authorized)
    return {
        "severity": severity.name.lower(),
        "required": required.name.lower(),
        "max_authorized": max_authorized.name.lower(),
        "allowed": decision.allowed,
        "effective": decision.effective.name.lower(),
        "change_class": {
            "touches_asn": change_class.touches_asn,
            "touches_rd_rt": change_class.touches_rd_rt,
            "touches_spine": change_class.touches_spine,
            "touches_underlay": change_class.touches_underlay,
        },
    }
