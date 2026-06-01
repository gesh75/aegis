"""core/seal/ — the CROSS-3 bounded-autonomy SEAL: a detached, offline-verifiable receipt
binding the model identity (#4 wedge) + the bounded authority (#5 ceiling) over a specific
evidence bundle, signed with a pinned key (a YubiKey PIV slot in production)."""
from __future__ import annotations

from .seal import (
    SEAL_VERSION,
    SealError,
    SealVerdict,
    build_claims,
    canonical_claims_bytes,
    seal_bundle,
    seal_response,
    verify_seal,
)
from .signing import Ed25519Signer, Ed25519Verifier, Signer, Verifier, key_id

__all__ = [
    "SEAL_VERSION",
    "SealError",
    "SealVerdict",
    "build_claims",
    "canonical_claims_bytes",
    "seal_bundle",
    "seal_response",
    "verify_seal",
    "Signer",
    "Verifier",
    "Ed25519Signer",
    "Ed25519Verifier",
    "key_id",
]
