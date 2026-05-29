"""Production-push connectors for AEGIS Phase 2 (closed-loop change management).

SAFETY FIRST. AEGIS never mutates production on its own. The only connector shipped and
default-enabled is the DryRunConnector, which records what *would* be pushed and changes
nothing. A real live connector is an explicit, operator-wired extension point that is
inert unless the operator both implements it and opts in (env + approval gate). This
mirrors the product principle: the pipeline proposes and verifies; a human authorizes; the
push is deliberate, audited, and reversible.
"""
from __future__ import annotations
from typing import Protocol, runtime_checkable


@runtime_checkable
class ProdConnector(Protocol):
    live: bool                       # True only for a connector that touches real devices

    def push(self, device: str, vendor: str, config: str) -> dict:
        """Apply one device's validated config. Return {pushed, detail}."""
        ...


class DryRunConnector:
    """Default. Records intent, mutates nothing. Safe to run anywhere."""
    live = False

    def __init__(self):
        self.calls: list[dict] = []

    def push(self, device: str, vendor: str, config: str) -> dict:
        self.calls.append({"device": device, "vendor": vendor, "lines": len(config.splitlines())})
        return {"pushed": True, "detail": "dry-run — not applied to production"}


class DisabledLiveConnector:
    """Placeholder for a real SSH/NETCONF push. Inert by design: it refuses to run until
    an operator implements `_apply` AND explicitly enables live promotion. Shipping an
    auto-pushing connector would violate the 'human authorizes the push' invariant."""
    live = True

    def push(self, device: str, vendor: str, config: str) -> dict:
        raise RuntimeError(
            "live production push is not implemented/enabled in AEGIS — wire your own "
            "audited connector (SSH/NETCONF) and gate it behind change-management approval")


def get_connector(name: str) -> ProdConnector:
    if name == "dry_run":
        return DryRunConnector()
    if name == "live":
        return DisabledLiveConnector()
    raise ValueError(f"unknown connector '{name}' (use 'dry_run' or 'live')")
