"""HMAC-signed approval tokens bound to a bundle hash.

Improvement plan T1 #9: any non-empty approver/token string used to pass G2/G3,
and the Ed25519 seal then attested to an approval nobody verified.

Token format::

    aegis1.<urlsafe-b64(payload)>.<urlsafe-b64(mac)>

``payload`` is canonical JSON (sorted keys, no whitespace).

v1 (legacy)::

    {"a": "<approver>", "b": "<bundle sha256 hex>", "exp": <unix int>,
     "n": "<nonce>", "v": 1}

v2 (config + inventory binding, #24)::

    {"a": "<approver>", "b": "<bundle sha256 hex>",
     "c": "<config sha256 hex>", "inv": "<inventory sha256 hex>",
     "exp": <unix int>, "n": "<nonce>", "v": 2}

``c`` is the SHA-256 of the canonical grounded configs.
``inv`` is the SHA-256 of the canonical target inventory (twin topology +
device list). A v2 token minted against inventory N dies if N+1 is supplied
at verify/promote time, even when the sealed bundle hash is unchanged.

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


def _canonical_hash(obj: object) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def config_digest(bundle: dict) -> str:
    """SHA-256 of canonical grounded configs (device + vendor + config)."""
    configs = ((bundle.get("change") or {}).get("generated_configs") or [])
    rows = []
    for item in configs:
        if not isinstance(item, dict):
            continue
        rows.append({
            "device": str(item.get("device") or ""),
            "vendor": str(item.get("vendor") or ""),
            "config": str(item.get("config") or ""),
        })
    rows.sort(key=lambda r: (r["device"], r["vendor"]))
    return _canonical_hash({"configs": rows})


def inventory_digest(bundle: dict) -> str:
    """SHA-256 of the target inventory fingerprint.

    Derived from the twin record + the device list in generated configs.
    Optional ``twin.inventory_rev`` is included when present so a source-of-truth
    revision becomes a first-class claim without a schema bump.
    """
    twin = bundle.get("twin") if isinstance(bundle.get("twin"), dict) else {}
    configs = ((bundle.get("change") or {}).get("generated_configs") or [])
    devices = sorted({
        str(item.get("device") or "")
        for item in configs
        if isinstance(item, dict) and item.get("device")
    })
    try:
        node_count = int(twin.get("node_count") or 0)
    except (TypeError, ValueError):
        node_count = 0
    payload = {
        "devices": devices,
        "engine": str(twin.get("engine") or ""),
        "inventory_rev": str(twin.get("inventory_rev") or twin.get("rev") or ""),
        "node_count": node_count,
        "topology": str(twin.get("topology") or ""),
    }
    return _canonical_hash(payload)


def digests_from_bundle(bundle: dict) -> tuple[str, str, str]:
    """Return (bundle_sha256, config_sha256, inventory_sha256)."""
    digest = str(((bundle.get("integrity") or {}).get("sha256") or "")).strip().lower()
    return digest, config_digest(bundle), inventory_digest(bundle)


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
               now: int | None = None, config_sha256: str | None = None,
               inventory_sha256: str | None = None, version: int | None = None) -> str:
    """Mint an HMAC token.

    v1 (default when config/inventory hashes are omitted): bound to approver +
    bundle hash + expiry. v2 when both ``config_sha256`` and ``inventory_sha256``
    are supplied, or ``version=2``.
    """
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

    cfg = (config_sha256 or "").strip().lower() or None
    inv = (inventory_sha256 or "").strip().lower() or None
    if version is None:
        version = 2 if (cfg or inv) else 1
    if version not in (1, 2):
        raise TokenError("token version must be 1 or 2")
    if version == 1 and (cfg or inv):
        raise TokenError("v1 tokens cannot carry config or inventory claims")
    if version == 2:
        if not cfg or not inv:
            raise TokenError("v2 tokens require config_sha256 and inventory_sha256")
        if not _HEX64.match(cfg):
            raise TokenError("config_sha256 must be 64 lowercase hex chars")
        if not _HEX64.match(inv):
            raise TokenError("inventory_sha256 must be 64 lowercase hex chars")

    issued = int(now if now is not None else time.time())
    payload: dict = {
        "a": who,
        "b": digest,
        "exp": issued + ttl,
        "n": secrets.token_hex(8),
        "v": version,
    }
    if version == 2:
        payload["c"] = cfg
        payload["inv"] = inv
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    mac = hmac.new(key, raw, hashlib.sha256).digest()
    return f"{_PREFIX}.{_b64(raw)}.{_b64(mac)}"


def mint_token_for_bundle(approver: str, bundle: dict, *, ttl_sec: int = _DEFAULT_TTL,
                          now: int | None = None) -> str:
    """Mint a v2 token bound to the bundle hash, config hash, and inventory fingerprint."""
    digest, cfg, inv = digests_from_bundle(bundle)
    return mint_token(approver, digest, ttl_sec=ttl_sec, now=now,
                      config_sha256=cfg, inventory_sha256=inv, version=2)


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
    if not isinstance(payload, dict) or payload.get("v") not in (1, 2):
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
                    *, now: int | None = None, config_sha256: str | None = None,
                    inventory_sha256: str | None = None) -> Approval:
    """Decide whether G2/G3 may treat this as a real approval.

    v1 tokens check approver + bundle hash + expiry.
    v2 tokens additionally require the supplied config and inventory hashes
    to match the claims in the payload. Missing live hashes on a v2 token
    is a deny — the point of v2 is that those claims are checked.
    """
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
    if payload.get("v") == 2:
        cfg = (config_sha256 or "").strip().lower()
        inv = (inventory_sha256 or "").strip().lower()
        if not cfg or not inv:
            return Approval(False, "none",
                            "v2 token requires config and inventory hashes", hashed)
        if payload.get("c") != cfg:
            return Approval(False, "none",
                            "token is not bound to this config hash", hashed)
        if payload.get("inv") != inv:
            return Approval(False, "none",
                            "token is not bound to this inventory", hashed)
    return Approval(True, "hmac-sha256", "HMAC verified, bound to bundle hash", hashed)
