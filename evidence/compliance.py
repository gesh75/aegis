"""Map a verified change -> control hits across frameworks.

Deterministic crosswalk. Each framework is a self-contained module under
`evidence/frameworks/` that the registry auto-discovers; this file just builds the shared
`ComplianceSignal` and dispatches the requested frameworks through it, preserving the
caller's framework order.

Adding a framework = one new file in `frameworks/` (no edit here). See
`frameworks/_base.py` for the module contract and the honesty rule (config-checked vs
process-mapped controls; never claim "certified").
"""
from __future__ import annotations
from ..core.backends.base import GeneratedConfig, BatfishResult
from .frameworks import REGISTRY
from .frameworks._base import ComplianceSignal


def map_controls(configs: list[GeneratedConfig], bf: BatfishResult,
                 frameworks: list[str], twin: dict | None = None,
                 diff: dict | None = None, intent: str = "",
                 source: str = "nl_intent") -> list[dict]:
    """Evaluate each requested framework against the change.

    Back-compatible: callers passing only (configs, bf, frameworks) still work; the twin/
    diff/intent/source signals let framework modules make richer, honest assertions.
    Unknown framework ids are skipped silently (the UI may offer more than is installed).
    """
    sig = ComplianceSignal(configs=configs, batfish=bf, twin=twin, diff=diff,
                           intent=intent, source=source)
    out: list[dict] = []
    for fw in frameworks:
        evaluate = REGISTRY.get(fw)
        if evaluate is None:
            continue
        out.extend(evaluate(sig))
    return out
