"""Decision D3: secret references. No credential value leaves the pipeline in an artifact.

When a secret store is configured, every credential found in the candidate configuration
is replaced, in the evidence bundle, by a reference token::

    set protocols bgp group G authentication-key "AEGISREF-3f9c0d2e7a41b8c6d5e4f3a2"

The value goes to the store. The bundle, its seal, the PDF/CAB/OSCAL exports, ServiceNow
attachments and ledger entries carry only references. Covered: credentials in configs,
the rollback plan, intent text and any finding that quotes them.

  token  = "AEGISREF-" + HMAC-SHA256(ref_key, run_id || 0x00 || value)[:24 hex]   (96 bit)

The token is keyed, so it reveals nothing about the value: a bare hash of a weak password
is guessable offline, a keyed one is not. It binds to the run, so the same secret in two
runs gets two tokens and the run cannot be swapped. Resolution re-computes the token from
the stored value, so a value swapped in the store is detected and refused.

Scope (honest): validation (Batfish, the twin, compliance) runs INSIDE the perimeter on
the real configuration, before tokenization, so results are unchanged. The references
protect what leaves the pipeline. A device that stores keys reversibly (Junos $9$, Cisco
type 7) still does so; PCI 8.3.2 judges the device, and that row is unaffected by D3.

Stores, chosen by ``AEGIS_SECRET_STORE``:

  file:/var/lib/aegis/secrets   AES-256-GCM files (0600), for air-gapped pilots
  vault:https://vault.corp:8200/v1/secret/data/aegis   HashiCorp Vault / OpenBao KV v2
                                (token in AEGIS_VAULT_TOKEN; host must be in-perimeter)

``AEGIS_SECRET_KEY`` (64 hex) is the root key. HMAC-derived subkeys are used for token
ids and for file encryption, so one key is never used for two purposes.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile

from ..evidence import secrets as _patterns

REF_PREFIX = "AEGISREF-"
REF_RE = re.compile(r"AEGISREF-[0-9a-f]{24}")
_MIN_SCRUB = 4          # shorter values are tokenized in place but not hunted bundle-wide


class SecretStoreError(Exception):
    """The store is misconfigured, unreachable, or returned a value that does not match
    its reference. ``str()`` never contains a secret value."""


def _subkey(root: bytes, purpose: bytes) -> bytes:
    return hmac.new(root, b"aegis-d3:" + purpose, hashlib.sha256).digest()


def load_root_key() -> bytes:
    raw = (os.environ.get("AEGIS_SECRET_KEY") or "").strip()
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise SecretStoreError("AEGIS_SECRET_KEY must be 64 hex chars") from exc
    if len(key) != 32:
        raise SecretStoreError("AEGIS_SECRET_KEY must be 64 hex chars (32 bytes)")
    return key


class _Base:
    """Every store carries the derived id key so tokens are computed consistently."""
    name = "base"

    def __init__(self, root_key: bytes) -> None:
        self.ref_key = _subkey(root_key, b"ref-id")

    def ref_for(self, run_id: str, value: str) -> str:
        mac = hmac.new(self.ref_key, f"{run_id}\x00{value}".encode(), hashlib.sha256)
        return REF_PREFIX + mac.hexdigest()[:24]

    def put(self, ref: str, value: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def get(self, ref: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class MemoryStore(_Base):
    """Tests and the offline demo only. Values die with the process."""
    name = "memory"

    def __init__(self, root_key: bytes | None = None) -> None:
        super().__init__(root_key or os.urandom(32))
        self._data: dict[str, str] = {}

    def put(self, ref, value):
        self._data[ref] = value

    def get(self, ref):
        if ref not in self._data:
            raise SecretStoreError(f"{ref}: not in store")
        return self._data[ref]


class FileStore(_Base):
    """AES-256-GCM, one file per reference, AAD = the reference (a file renamed to another
    reference fails to decrypt). Directory 0700, files 0600, atomic writes."""
    name = "file"

    def __init__(self, root: str, root_key: bytes) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        super().__init__(root_key)
        self.root = root
        self._aead = AESGCM(_subkey(root_key, b"file-enc"))
        os.makedirs(root, mode=0o700, exist_ok=True)

    def _path(self, ref: str) -> str:
        if not REF_RE.fullmatch(ref):
            raise SecretStoreError("malformed reference")
        return os.path.join(self.root, ref + ".bin")

    def put(self, ref, value):
        nonce = os.urandom(12)
        blob = nonce + self._aead.encrypt(nonce, value.encode(), ref.encode())
        fd, tmp = tempfile.mkstemp(dir=self.root, prefix=".tmp-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
            os.replace(tmp, self._path(ref))
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def get(self, ref):
        from cryptography.exceptions import InvalidTag
        try:
            with open(self._path(ref), "rb") as fh:
                blob = fh.read()
        except FileNotFoundError as exc:
            raise SecretStoreError(f"{ref}: not in store") from exc
        try:
            return self._aead.decrypt(blob[:12], blob[12:], ref.encode()).decode()
        except (InvalidTag, ValueError) as exc:
            raise SecretStoreError(f"{ref}: stored value failed authentication") from exc


class VaultStore(_Base):
    """HashiCorp Vault / OpenBao KV v2. ``base`` is the data URL of a mount path, e.g.
    https://vault.corp:8200/v1/secret/data/aegis — each reference is one secret under it."""
    name = "vault"

    def __init__(self, base: str, token: str, root_key: bytes, transport=None) -> None:
        import httpx
        from .integrations import IntegrationError, assert_integration_url
        super().__init__(root_key)
        try:
            self.base = assert_integration_url("vault", base)
        except IntegrationError as exc:
            raise SecretStoreError(str(exc)) from exc
        if not (token or "").strip():
            raise SecretStoreError("vault: AEGIS_VAULT_TOKEN is not set")
        self._http = httpx.Client(timeout=httpx.Timeout(10.0, connect=5.0), transport=transport,
                                  trust_env=False, follow_redirects=False,
                                  headers={"X-Vault-Token": token.strip()})

    def _url(self, ref: str) -> str:
        if not REF_RE.fullmatch(ref):
            raise SecretStoreError("malformed reference")
        return f"{self.base}/{ref}"

    def _call(self, method: str, ref: str, **kw):
        import httpx
        try:
            r = self._http.request(method, self._url(ref), **kw)
        except httpx.HTTPError as exc:
            raise SecretStoreError(f"vault: {type(exc).__name__}") from exc
        if r.status_code == 404:
            raise SecretStoreError(f"{ref}: not in store")
        if r.status_code >= 400:
            raise SecretStoreError(f"vault: HTTP {r.status_code}")
        return r

    def put(self, ref, value):
        self._call("POST", ref, json={"data": {"value": value}})

    def get(self, ref):
        try:
            return str(self._call("GET", ref).json()["data"]["data"]["value"])
        except (ValueError, KeyError, TypeError) as exc:
            raise SecretStoreError(f"{ref}: unexpected vault response") from exc


def configured() -> bool:
    return bool((os.environ.get("AEGIS_SECRET_STORE") or "").strip())


def store_from_env(transport=None):
    """The configured store, or None when AEGIS_SECRET_STORE is unset. Misconfiguration
    raises SecretStoreError (callers treat it as fatal at startup)."""
    spec = (os.environ.get("AEGIS_SECRET_STORE") or "").strip()
    if not spec:
        return None
    key = load_root_key()
    kind, _, target = spec.partition(":")
    if kind == "file" and target.startswith("/"):
        return FileStore(target, key)
    if kind == "vault" and target:
        return VaultStore(target, os.environ.get("AEGIS_VAULT_TOKEN") or "", key,
                          transport=transport)
    raise SecretStoreError("AEGIS_SECRET_STORE must be file:/abs/path or vault:https://...")


# ── tokenization ────────────────────────────────────────────────────────────────

def _matchers():
    for label, rx in _patterns.REVERSIBLE_PATTERNS:
        yield "reversible", label, rx
    for label, rx in _patterns.PLAINTEXT_PATTERNS:
        yield "plaintext", label, rx
    for i, rx in enumerate(_patterns._HASH_PATTERNS):  # noqa: SLF001 — same module family
        yield "hash", f"hash-{i}", rx


def _spans(text: str) -> list[tuple[int, int, str, str]]:
    """Non-overlapping (start, end, kind, label) for every secret VALUE; first matcher wins."""
    found: list[tuple[int, int, str, str]] = []
    for kind, label, rx in _matchers():
        for m in rx.finditer(text):
            a, b = m.span("s")
            val = text[a:b]
            if not val or val.startswith(REF_PREFIX) or val == _patterns.REDACTED:
                continue
            if any(a < e and s < b for s, e, _k, _l in found):
                continue
            found.append((a, b, kind, label))
    return sorted(found)


def tokenize_text(text: str, *, run_id: str, store, device: str = ""
                  ) -> tuple[str, list[dict], dict[str, str]]:
    """(text with references, ref records, {value: ref}). Idempotent on its own output."""
    refs: list[dict] = []
    mapping: dict[str, str] = {}
    out = text or ""
    for a, b, kind, label in reversed(_spans(out)):
        value = out[a:b]
        ref = store.ref_for(run_id, value)
        if value not in mapping:
            store.put(ref, value)
            mapping[value] = ref
            refs.append({"ref": ref, "device": device, "kind": kind, "label": label})
        out = out[:a] + ref + out[b:]
    return out, list(reversed(refs)), mapping


def _scrub(obj, rx: re.Pattern | None, mapping: dict[str, str]):
    if rx is None:
        return obj
    if isinstance(obj, str):
        return rx.sub(lambda m: mapping[m.group(0)], obj)
    if isinstance(obj, list):
        return [_scrub(v, rx, mapping) for v in obj]
    if isinstance(obj, dict):
        return {k: _scrub(v, rx, mapping) for k, v in obj.items()}
    return obj


def _value_rx(values) -> re.Pattern | None:
    vals = sorted({v for v in values if len(v) >= _MIN_SCRUB}, key=len, reverse=True)
    if not vals:
        return None
    return re.compile(r"(?<![\w$-])(?:" + "|".join(re.escape(v) for v in vals) + r")(?![\w$-])")


def protect_bundle(bundle: dict, store) -> dict:
    """Tokenize every credential in an UNSEALED bundle, scrub any other occurrence of the
    values, record ``change.secret_refs``, re-hash. Fails closed (SecretStoreError) if a
    value would still be present afterwards. Returns a new dict."""
    from ..evidence.bundler import compute_sha256

    run_id = str(bundle.get("run_id") or "")
    out = json.loads(json.dumps(bundle))
    mapping: dict[str, str] = {}
    refs: list[dict] = []
    for c in out.get("change", {}).get("generated_configs") or []:
        text, recs, m = tokenize_text(c.get("config") or "", run_id=run_id, store=store,
                                      device=str(c.get("device") or ""))
        c["config"] = text
        mapping.update(m)
        seen = {(r["ref"], r["device"]) for r in refs}
        refs.extend(r for r in recs if (r["ref"], r["device"]) not in seen)
    # rollback steps, intent text and findings may quote the same lines
    rb = out.get("rollback") or {}
    if isinstance(rb.get("plan"), list):
        new_plan = []
        for step in rb["plan"]:
            text, recs, m = tokenize_text(str(step), run_id=run_id, store=store)
            mapping.update(m)
            new_plan.append(text)
        rb["plan"] = new_plan
    # compliance rows are AEGIS-authored from pattern LABELS, never values; leave them
    # verbatim (the sim's demo key is the word "plaintext", which those rows also use)
    validation = out.get("validation") or {}
    compliance = validation.pop("compliance", None)
    out = _scrub(out, _value_rx(mapping), mapping)
    out.setdefault("change", {})["secret_refs"] = refs
    blob = json.dumps(out)
    if compliance is not None:
        out["validation"]["compliance"] = compliance
    leaks = [v for v in mapping if len(v) >= _MIN_SCRUB and _value_rx([v]).search(blob)]
    if leaks:
        raise SecretStoreError(f"{len(leaks)} credential value(s) survived tokenization")
    out["integrity"]["sha256"] = ""
    out["integrity"]["sha256"] = compute_sha256(out)
    return out


def resolve_text(text: str, *, run_id: str, store) -> str:
    """Replace every reference by its value, verifying each value re-derives its token."""
    def repl(m: re.Match) -> str:
        ref = m.group(0)
        value = store.get(ref)
        if not hmac.compare_digest(store.ref_for(run_id, value), ref):
            raise SecretStoreError(f"{ref}: stored value does not match its reference")
        return value
    return REF_RE.sub(repl, text or "")


def has_refs(text: str) -> bool:
    return bool(REF_RE.search(text or ""))
