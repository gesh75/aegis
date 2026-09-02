"""Compiled-in trust pins for the PIV hardware-signer path.

These are constants, not file-loaded config. Editing this module and rebuilding
is the rotation path. A runtime file must not be able to loosen the root.
"""
from __future__ import annotations

# SHA-256 of the DER encoding of "Yubico PIV Root CA Serial 263751"
# Source: https://developers.yubico.com/PKI/yubico-piv-ca-1.pem
# Verified 2026-08-30 against the published PEM (795-byte DER).
YUBICO_PIV_ROOT_CA_DER_SHA256 = (
    "63ece914e54dd87915f34033c85af4c0696ba1512f8add66ced738331207b546"
)

PIV_SERIAL_ALLOWLIST: frozenset[str] = frozenset()
PINNED_PIV_KEY_ID: str | None = None
