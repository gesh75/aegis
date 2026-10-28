"""Approver identity registry (A2) — who may mint an approval token.

Without this, anyone holding the shared ``AEGIS_API_KEY`` (i.e. any operator) could mint
an HMAC approval token for any approver name, approving their own change. With
``AEGIS_APPROVER_KEYS`` set, ``/api/approve/mint`` requires the caller's personal
approver credential in ``X-Aegis-Approver-Key`` and takes the approver identity FROM that
credential — the request body cannot choose it.

Format (hashes only, so the environment never holds a usable credential)::

    AEGIS_APPROVER_KEYS="alice@corp:<sha256 hex of alice's key>,bob@corp:<sha256 hex>"

Generate an entry:  python -m aegis.core.promote.approvers alice@corp

The same credential identifies the AUTHOR of a run: ``/api/preflight/run`` records the
operator from ``X-Aegis-Approver-Key`` (never from the request body), which is what lets
separation of duties compare two identified people. A run without a credential is sealed
as ``unauthenticated`` and cannot be approved.

This is the bridge until SSO/OIDC (Entra ID) group-based roles land; the registry is the
same seam an OIDC adapter would fill.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sys

_NAME = re.compile(r"^[A-Za-z0-9._@/-]{1,128}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# What the server records as a bundle's operator when the run carried no personal
# credential. The other names are the library default and the pre-fix community default;
# none of them identifies a person, so none can stand in for "someone else approved it".
UNAUTHENTICATED = "unauthenticated"
_NO_IDENTITY = frozenset({"", "unknown", "unauthenticated", "community"})


def identified(operator) -> bool:
    """True only for an operator name that identifies a person. An empty, absent or
    placeholder operator is NOT an identity: separation of duties cannot be checked
    against it, so approval is denied (dgV9dC6J), never skipped."""
    return str(operator or "").strip().lower() not in _NO_IDENTITY


def load_registry() -> dict[str, str]:
    """name -> sha256(key) hex. Malformed entries are fatal (never silently skipped)."""
    raw = (os.environ.get("AEGIS_APPROVER_KEYS") or "").strip()
    reg: dict[str, str] = {}
    if not raw:
        return reg
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        name, _, digest = item.rpartition(":")
        digest = digest.strip().lower()
        if not _NAME.match(name.strip()) or not _HEX64.match(digest):
            raise SystemExit("[aegis.approvers] AEGIS_APPROVER_KEYS entry malformed "
                             "(want name:sha256hex); refusing to start")
        reg[name.strip()] = digest
    return reg


def registry_configured() -> bool:
    return bool(load_registry())


def resolve(presented_key: str | None) -> str | None:
    """Return the approver whose credential this is, or None. Constant-time per entry."""
    key = (presented_key or "").strip()
    if not key:
        return None
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    found = None
    for name, want in load_registry().items():
        if hmac.compare_digest(digest, want):
            found = name
    return found


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not _NAME.match(argv[1]):
        print("usage: python -m aegis.core.promote.approvers <approver-name>", file=sys.stderr)
        return 2
    key = secrets.token_urlsafe(32)
    print(f"# give this key to {argv[1]} ONLY (their X-Aegis-Approver-Key):\n{key}")
    print(f"# add this to AEGIS_APPROVER_KEYS on the server:\n"
          f"{argv[1]}:{hashlib.sha256(key.encode()).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
