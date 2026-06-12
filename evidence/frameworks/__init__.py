"""Auto-discovering registry of compliance-framework modules.

Every sibling module that defines `FRAMEWORK` + `evaluate(sig)` is picked up
automatically — drop a new file in this package and it is live. A module that fails to
import is skipped (never takes down the whole compliance map), so one broken framework
can't block the others.
"""
from __future__ import annotations
import importlib
import pkgutil
import sys

from ._base import ComplianceSignal  # noqa: F401  (re-exported for framework modules)

REGISTRY: dict[str, callable] = {}

for _finder, _name, _ispkg in pkgutil.iter_modules(__path__):
    if _name.startswith("_"):
        continue
    try:
        _mod = importlib.import_module(f"{__name__}.{_name}")
        _fw = getattr(_mod, "FRAMEWORK", None)
        _ev = getattr(_mod, "evaluate", None)
        if _fw and callable(_ev):
            REGISTRY[_fw] = _ev
    except Exception as _e:  # noqa: BLE001 — a broken module must not break compliance
        print(f"[compliance] skipped framework module '{_name}': {_e}", file=sys.stderr)


def available() -> list[str]:
    """Framework ids currently registered (sorted for stable display)."""
    return sorted(REGISTRY)
