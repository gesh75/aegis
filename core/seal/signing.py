"""core/seal/signing.py — detached-signature primitives for the CROSS-3 seal.

A `Signer` produces a detached signature over canonical claim bytes; a `Verifier` checks
one against a PINNED public key. The seal is verifiable OFFLINE with no secret — the
verifier holds only the public key.

Ed25519Signer/Verifier are the software implementation (real asymmetric crypto via the
`cryptography` library). The HARDWARE path — a YubiKey PIV slot via PKCS#11 C_Sign, with a
slot-9a attestation chain pinned to the Yubico PIV root CA — implements the SAME `Signer`
protocol and is the documented swap-in (it needs the physical token, so it is not built
here; this module ships the seal mechanics + offline verifier the hardware signer plugs
into). No hardware signer is stubbed-as-working — that would be a false-green crypto claim.
"""
from __future__ import annotations

import hashlib
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_ALG = "ed25519"


def key_id(public_raw: bytes) -> str:
    """Short, stable id of a public key — sha256(raw)[:16]. The verifier PINS this; a seal
    signed by any other key is rejected at gate G1."""
    return hashlib.sha256(public_raw).hexdigest()[:16]


@runtime_checkable
class Signer(Protocol):
    def alg(self) -> str: ...
    def key_id(self) -> str: ...
    def public_key_bytes(self) -> bytes: ...
    def sign(self, payload: bytes) -> bytes: ...


@runtime_checkable
class Verifier(Protocol):
    def alg(self) -> str: ...
    def key_id(self) -> str: ...
    def verify(self, payload: bytes, signature: bytes) -> bool: ...


class Ed25519Signer:
    """Software Ed25519 signer (real asymmetric crypto). Production replaces this with a
    PIV/PKCS#11 signer implementing the same protocol; the seal format is identical."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._sk = private_key
        self._pub = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "Ed25519Signer":
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    def alg(self) -> str:
        return _ALG

    def key_id(self) -> str:
        return key_id(self._pub)

    def public_key_bytes(self) -> bytes:
        return self._pub

    def sign(self, payload: bytes) -> bytes:
        return self._sk.sign(payload)

    def verifier(self) -> "Ed25519Verifier":
        """The matching offline verifier (public key only)."""
        return Ed25519Verifier.from_public_bytes(self._pub)


class Ed25519Verifier:
    """Offline verifier — holds only the PINNED public key (no secret material)."""

    def __init__(self, public_key: Ed25519PublicKey, public_raw: bytes) -> None:
        self._pk = public_key
        self._pub = public_raw

    @classmethod
    def from_public_bytes(cls, raw: bytes) -> "Ed25519Verifier":
        return cls(Ed25519PublicKey.from_public_bytes(raw), raw)

    def alg(self) -> str:
        return _ALG

    def key_id(self) -> str:
        return key_id(self._pub)

    def verify(self, payload: bytes, signature: bytes) -> bool:
        try:
            self._pk.verify(signature, payload)
            return True
        except InvalidSignature:
            return False
