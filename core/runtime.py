"""Deployment mode: ``community`` (default, demo-friendly) vs ``production`` (fail closed).

Community keeps every honesty-tier fallback so the offline demo and CI work with zero
setup. Production removes them:

  * refuses to start without AEGIS_API_KEY, AEGIS_APPROVE_KEY, AEGIS_SEAL_KEY,
    AEGIS_LEDGER_PATH, AEGIS_APPROVER_KEYS, AEGIS_SECRET_STORE and AEGIS_SECRET_KEY (no
    open API, no presence-only approvals, no ephemeral seals, no in-memory audit trail,
    no operator-minted approvals, no credential values in evidence bundles)
  * ``asserted-unverified`` approvals are a deny at the gate
  * promotion and evidence export require a valid Ed25519 seal
  * a preflight run must carry a change reference (e.g. a ServiceNow CHG number)
  * approval is granted only at promotion (HMAC token), never asserted at run time
"""
from __future__ import annotations

import os
import re

COMMUNITY = "community"
PRODUCTION = "production"

_REQUIRED_PRODUCTION_ENV = ("AEGIS_API_KEY", "AEGIS_APPROVE_KEY", "AEGIS_SEAL_KEY",
                            "AEGIS_LEDGER_PATH", "AEGIS_APPROVER_KEYS",
                            # D3: no credential value may sit in a production artifact
                            "AEGIS_SECRET_STORE", "AEGIS_SECRET_KEY")

# Change references: ServiceNow CHG0012345, Jira NETOPS-123, Remedy CRQ000000123456 ...
# Overridable so each org can pin its own ITSM numbering.
_DEFAULT_CHANGE_REF = r"^[A-Za-z][A-Za-z0-9]{1,15}[-_]?[0-9]{1,15}$"


def mode() -> str:
    raw = (os.environ.get("AEGIS_MODE") or COMMUNITY).strip().lower()
    if raw not in (COMMUNITY, PRODUCTION):
        raise SystemExit(f"[aegis.mode] AEGIS_MODE must be community|production (got {raw!r})")
    return raw


def is_production() -> bool:
    return mode() == PRODUCTION


def missing_production_env() -> list[str]:
    return [k for k in _REQUIRED_PRODUCTION_ENV if not (os.environ.get(k) or "").strip()]


def assert_startup_ok() -> None:
    """Called once at server start. Production with any control unset is fatal."""
    if is_production():
        missing = missing_production_env()
        if missing:
            raise SystemExit("[aegis.mode] AEGIS_MODE=production refuses to start; unset: "
                             + ", ".join(missing))


def change_ref_pattern() -> re.Pattern:
    raw = (os.environ.get("AEGIS_CHANGE_REF_PATTERN") or _DEFAULT_CHANGE_REF).strip()
    try:
        return re.compile(raw)
    except re.error as exc:
        raise SystemExit(f"[aegis.mode] AEGIS_CHANGE_REF_PATTERN invalid: {exc}") from exc


def valid_change_ref(ref: str | None) -> bool:
    return bool(ref) and len(ref) <= 64 and bool(change_ref_pattern().match(ref))
