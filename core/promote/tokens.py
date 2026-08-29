"""HMAC-signed approval tokens bound to a bundle hash.

Improvement plan T1 #9: any non-empty approver/token string used to pass G2/G3,
and the Ed25519 seal then attested to an approval nobody verified.

Token format (v1)::

    aegis1.<urlsafe-b64(payload)>.<urlsafe-b64(mac)>

``payload`` is canonical JSON (sorted keys, no whitespace)::

    {"a": "<approver>", "b": "<bundle sha256 hex>", "exp": <unix int>, "n": "<nonce>", "v": 1}

MAC is HMAC-SHA256 over the exact payload bytes using ``AEGIS_APPROVE_KEY``.

When the key is **unset**, ``verify_approval`` accepts any non-empty
approver+token pair and reports method ``asserted-unverified`` — the honesty
tier, not a backdoor. When the key **is** set, a token that does not verify
is a hard deny. Empty/missing always denies.

The raw token is never stored. Callers persist ``token_sha256`` only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_APPROVER = re.compile(r"^[A-Za-z0-9._@/-]{1,128}$")
_PREFIX = "aegis1"
_DEFAULT_TTL = 4 * 60 * 60
_MAX_TTL = 7 * 24 * 60 * 60
_MIN_KEY_BYTES = 16


class TokenError(ValueError):
    """Mint rejected — bad input or HMAC not configured."""


@dataclass(frozen=True)
class Approval:
    ok: bool
    method: str  # hmac-sha256 | asserted-unverified | none
    reason: str
    token_sha256: str | None = None


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def load_approve_key() -> bytes | None:
    """Return the HMAC key, or None if HMAC is not configured.

    ``AEGIS_APPROVE_KEY`` is either even-length hex (≥32 chars → 16 bytes) or
    a raw secret (≥16 UTF-8 bytes). A set-but-unusable value is fatal — silent
    fallback would mint tokens nobody can verify, the same class of bug as
    an invalid ``AEGIS_SEAL_KEY``.
    """
    raw = (os.environ.get("AEGIS_APPROVE_KEY") or "").strip()
    if not raw:
        return None
    if re.fullmatch(r"[0-9a-fA-F]+", raw) and len(raw) % 2 == 0:
        key = bytes.fromhex(raw)
    else:
        key = raw.encode("utf-8")
    if len(key) < _MIN_KEY_BYTES:
        raise SystemExit(
            f"[aegis.approve] AEGIS_APPROVE_KEY is too short ({len(key)} bytes); "
            f"need ≥{_MIN_KEY_BYTES}. Refusing to start."
        )
    return key


def hmac_configured() -> bool:
    return load_approve_key() is not None


def mint_token(approver: str, bundle_sha256: str, *, ttl_sec: int = _DEFAULT_TTL,
               now: int | None = None) -> str:
    key = load_approve_key()
    if key is None:
        raise TokenError("AEGIS_APPROVE_KEY is unset — HMAC minting refused")
    who = (approver or "").strip()
    digest = (bundle_sha256 or "").strip().lower()
    if not _APPROVER.match(who):
        raise TokenError("approver must be 1–128 chars of [A-Za-z0-9._@/-]")
    if not _HEX64.match(digest):
        raise TokenError("bundle_sha256 must be 64 lowercase hex chars")
    try:
        ttl = int(ttl_sec)
    except (TypeError, ValueError) as exc:
        raise TokenError("ttl_sec must be an integer") from exc
    if ttl < 60 or ttl > _MAX_TTL:
        raise TokenError(f"ttl_sec must be between 60 and {_MAX_TTL}")
    issued = int(now if now is not None else time.time())
    payload = {
        "a": who,
        "b": digest,
        "exp": issued + ttl,
        "n": secrets.token_hex(8),
        "v": 1,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    mac = hmac.new(key, raw, hashlib.sha256).digest()
    return f"{_PREFIX}.{_b64(raw)}.{_b64(mac)}"


def _parse_hmac(token: str, key: bytes, *, now: int) -> tuple[dict, str]:
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != _PREFIX:
        return {}, "token is not aegis1.payload.mac"
    try:
        raw = _unb64(parts[1])
        mac = _unb64(parts[2])
    except Exception:  # noqa: BLE001 — malformed b64 is a deny, not a crash
        return {}, "token encoding is invalid"
    expected = hmac.new(key, raw, hashlib.sha256).digest()
    if len(mac) != len(expected) or not hmac.compare_digest(mac, expected):
        return {}, "HMAC does not verify"
    try:
        payload = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}, "token payload is not JSON"
    if not isinstance(payload, dict) or payload.get("v") != 1:
        return {}, "unsupported token version"
    try:
        exp = int(payload.get("exp"))
    except (TypeError, ValueError):
        return {}, "token expiry missing"
    if exp < now:
        return {}, "token expired"
    if exp > now + _MAX_TTL + 60:
        return {}, "token expiry is implausibly far in the future"
    return payload, ""


def verify_approval(approver: str | None, token: str | None, bundle_sha256: str,
                    *, now: int | None = None) -> Approval:
    """Decide whether G2/G3 may treat this as a real approval."""
    who = (approver or "").strip()
    tok = (token or "").strip()
    digest = (bundle_sha256 or "").strip().lower()
    if not who or not tok:
        return Approval(False, "none", "approver and token required")
    hashed = _token_hash(tok)
    key = load_approve_key()
    if key is None:
        # Honesty tier: presence-only. Recorded as asserted, unverified.
        return Approval(True, "asserted-unverified",
                        "approval asserted, HMAC not configured", hashed)
    issued = int(now if now is not None else time.time())
    payload, err = _parse_hmac(tok, key, now=issued)
    if err:
        return Approval(False, "none", err, hashed)
    if payload.get("a") != who:
        return Approval(False, "none", "token approver does not match", hashed)
    if payload.get("b") != digest:
        return Approval(False, "none", "token is not bound to this bundle hash", hashed)
    return Approval(True, "hmac-sha256", "HMAC verified, bound to bundle hash", hashed)
