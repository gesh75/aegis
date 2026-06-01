"""core/seal/seal.py — the CROSS-3 bounded-autonomy SEAL.

A DETACHED receipt that fuses, into one offline-verifiable object, three facts no
competitor binds together:
  (#4 wedge)    WHICH model produced the change  — provider + model + model-hash
  (#5 ceiling)  that it was BOUNDED               — required authority <= max_authorized
  (integrity)   over THIS exact evidence bundle   — bundle_sha256
signed with a pinned key (a YubiKey PIV slot in production).

The receipt is DETACHED — it does not mutate the bundle, so the bundle's own integrity
hash stays stable — and binds to the bundle by its sha256. VERIFY runs OFFLINE against
only the public key (no secret), and a VALID verdict is a portable cryptographic proof
that a named+hashed model produced this exact change AND that it was bounded by the ceiling
— the thing competitors assert but cannot hand an auditor offline.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from ...evidence.bundler import verify as verify_bundle
from ..risk import Tier
from .signing import Signer, Verifier

SEAL_VERSION = "1.0"


class SealError(Exception):
    """Refused to produce a seal (the bundle is unbounded or fails integrity)."""


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_claims_bytes(claims: dict) -> bytes:
    return _canonical(claims)


def build_claims(bundle: dict, sealed_at_utc: str) -> dict:
    """The exact claim set the seal signs — binds model + authority + the bundle hash."""
    mi = bundle["change"]["model_identity"]
    au = bundle["change"]["authority"]
    return {
        "seal_version": SEAL_VERSION,
        "bundle_sha256": bundle["integrity"]["sha256"],
        "model": {
            "provider": mi["provider"], "model": mi["model"],
            "model_hash": mi["model_hash"], "model_hash_kind": mi["model_hash_kind"],
        },
        "authority": {
            "required": au["required"], "max_authorized": au["max_authorized"],
            "allowed": au["allowed"], "effective": au["effective"],
        },
        "sealed_at_utc": sealed_at_utc,
    }


def _is_bounded(authority: dict) -> bool:
    if not authority.get("allowed") or authority.get("effective") == "block":
        return False
    try:
        return Tier[str(authority["required"]).upper()] <= Tier[str(authority["max_authorized"]).upper()]
    except KeyError:
        return False


def seal_bundle(bundle: dict, signer: Signer, *, sealed_at_utc: str) -> dict:
    """Produce a detached seal receipt for a BOUNDED, integrity-valid bundle. Refuses
    (SealError) to seal a tampered bundle or one whose change exceeds the autonomy ceiling
    — you never certify a self-escalation."""
    if not verify_bundle(bundle):
        raise SealError("refuse to seal: bundle fails its own integrity check")
    if not _is_bounded(bundle["change"]["authority"]):
        raise SealError("refuse to seal: change is not within the autonomy ceiling "
                        "(no-self-escalation) — nothing to certify")
    claims = build_claims(bundle, sealed_at_utc)
    sig = signer.sign(canonical_claims_bytes(claims))
    return {
        "seal_version": SEAL_VERSION,
        "claims": claims,
        "signature": {
            "alg": signer.alg(),
            "key_id": signer.key_id(),
            "value": base64.b64encode(sig).decode("ascii"),
        },
    }


@dataclass(frozen=True)
class SealVerdict:
    valid: bool
    gate: str   # the gate that decided (G0..G6) or "OK"
    reason: str


def verify_seal(bundle: dict, seal: dict, verifier: Verifier) -> SealVerdict:
    """Offline verification — uses ONLY the pinned public key. Runs gates G0..G6; the first
    failure decides."""
    # G0 — structure
    try:
        claims = seal["claims"]
        sig = seal["signature"]
        alg, kid, value = sig["alg"], sig["key_id"], sig["value"]
        b_sha, model, authority = claims["bundle_sha256"], claims["model"], claims["authority"]
    except (KeyError, TypeError):
        return SealVerdict(False, "G0", "malformed seal")

    # G1 — key pinning: only the pinned key + alg are trusted
    if alg != verifier.alg() or kid != verifier.key_id():
        return SealVerdict(False, "G1", f"unpinned key/alg ({alg}/{kid})")

    # G2 — signature over the canonical claims
    try:
        ok = verifier.verify(canonical_claims_bytes(claims), base64.b64decode(value))
    except Exception:  # noqa: BLE001 — malformed base64, etc.
        return SealVerdict(False, "G2", "signature decode error")
    if not ok:
        return SealVerdict(False, "G2", "signature does not verify against the pinned key")

    # G3 — the seal covers THIS bundle
    if b_sha != bundle.get("integrity", {}).get("sha256"):
        return SealVerdict(False, "G3", "seal bundle_sha256 does not match the bundle")

    # G4 — model identity bound + honest (an identity-claim never carries a faked weight hash)
    mi = bundle.get("change", {}).get("model_identity", {})
    if (model.get("provider") != mi.get("provider") or model.get("model") != mi.get("model")
            or model.get("model_hash") != mi.get("model_hash")
            or model.get("model_hash_kind") != mi.get("model_hash_kind")):
        return SealVerdict(False, "G4", "sealed model identity does not match the bundle")
    if model.get("model_hash_kind") == "identity-claim" and model.get("model_hash") is not None:
        return SealVerdict(False, "G4", "identity-claim must not carry a weight hash")

    # G5 — bounded autonomy: matches the bundle AND is within the ceiling
    au = bundle.get("change", {}).get("authority", {})
    if (authority.get("required") != au.get("required")
            or authority.get("max_authorized") != au.get("max_authorized")
            or authority.get("allowed") != au.get("allowed")
            or authority.get("effective") != au.get("effective")):
        return SealVerdict(False, "G5", "sealed authority does not match the bundle")
    if not _is_bounded(authority):
        return SealVerdict(False, "G5", "sealed change exceeds the autonomy ceiling")

    # G6 — the bundle itself integrity-verifies
    if not verify_bundle(bundle):
        return SealVerdict(False, "G6", "bundle fails its own integrity check")

    return SealVerdict(True, "OK", "named+hashed model and bounded authority sealed over "
                       "this bundle; signature valid against the pinned key")


def seal_response(bundle: dict, signer: Signer, sealed_at_utc: str) -> tuple[dict | None, str | None]:
    """Live-path convenience: returns (receipt, None) for a bounded, integrity-valid bundle,
    or (None, reason) when the change cannot be sealed (unbounded / tampered). The caller
    embeds the receipt under bundle['seal'] (excluded from the bundle hash) so a run emits
    its proof in one response."""
    try:
        return seal_bundle(bundle, signer, sealed_at_utc=sealed_at_utc), None
    except SealError as exc:
        return None, str(exc)
