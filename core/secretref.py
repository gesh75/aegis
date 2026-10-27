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

    def delete(self, ref: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def prune(self, max_age_days: int) -> int:
        """Remove entries older than the retention window; returns the count removed."""
        return 0

    def check_key(self) -> None:
        """Raise if existing entries cannot be read with the configured key."""
        return None


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

    def delete(self, ref):
        self._data.pop(ref, None)


class FileStore(_Base):
    """AES-256-GCM, one file per reference, AAD = the reference (a file renamed to another
    reference fails to decrypt). Directory 0700 and owned by this process's user (an
    existing looser directory is tightened, or refused), files 0600, atomic and fsync'd
    writes so a crash cannot lose a value whose reference was already returned."""
    name = "file"

    def __init__(self, root: str, root_key: bytes) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        super().__init__(root_key)
        self.root = root
        self._aead = AESGCM(_subkey(root_key, b"file-enc"))
        os.makedirs(root, mode=0o700, exist_ok=True)
        st = os.stat(root)
        if st.st_uid != os.getuid():
            raise SecretStoreError(f"file store {root}: not owned by this user")
        if st.st_mode & 0o077:
            os.chmod(root, 0o700)
            if os.stat(root).st_mode & 0o077:
                raise SecretStoreError(f"file store {root}: permissions are not 0700")

    def _path(self, ref: str) -> str:
        if not REF_RE.fullmatch(ref):
            raise SecretStoreError("malformed reference")
        return os.path.join(self.root, ref + ".bin")

    def _fsync_dir(self) -> None:
        fd = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def put(self, ref, value):
        nonce = os.urandom(12)
        blob = nonce + self._aead.encrypt(nonce, value.encode(), ref.encode())
        fd, tmp = tempfile.mkstemp(dir=self.root, prefix=".tmp-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path(ref))
            self._fsync_dir()
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

    def delete(self, ref):
        try:
            os.unlink(self._path(ref))
        except FileNotFoundError:
            pass

    def _entries(self) -> list[tuple[float, str]]:
        out = []
        for name in os.listdir(self.root):
            if name.endswith(".bin") and REF_RE.fullmatch(name[:-4]):
                out.append((os.stat(os.path.join(self.root, name)).st_mtime, name[:-4]))
        return sorted(out)

    def prune(self, max_age_days):
        if max_age_days <= 0:
            return 0
        import time
        cutoff = time.time() - max_age_days * 86400
        gone = 0
        for mtime, ref in self._entries():
            if mtime < cutoff:
                self.delete(ref)
                gone += 1
        if gone:
            self._fsync_dir()
        return gone

    def check_key(self):
        """A rotated AEGIS_SECRET_KEY cannot decrypt earlier entries: refuse to start
        rather than discover it at the first promotion."""
        entries = self._entries()
        if entries:
            try:
                self.get(entries[-1][1])
            except SecretStoreError as exc:
                raise SecretStoreError("AEGIS_SECRET_KEY does not match the existing store "
                                       "entries (key rotated? migrate or prune first)") from exc


class VaultStore(_Base):
    """HashiCorp Vault / OpenBao KV v2. ``base`` is the data URL of a mount path, e.g.
    https://vault.corp:8200/v1/secret/data/aegis — each reference is one secret under it.
    Retention for Vault is a mount setting (``delete_version_after``), see the D3 doc."""
    name = "vault"

    def __init__(self, base: str, token: str, root_key: bytes, transport=None) -> None:
        from urllib.parse import urlparse

        import httpx
        from .integrations import IntegrationError, assert_integration_url
        super().__init__(root_key)
        u = urlparse((base or "").strip())
        if u.query or u.fragment or ";" in u.path:
            raise SecretStoreError("vault: the base URL must not carry a query or fragment")
        if "/data/" not in u.path:
            raise SecretStoreError("vault: base must be a KV v2 data path (/v1/<mount>/data/...)")
        try:
            self.base = assert_integration_url("vault", base)
        except IntegrationError as exc:
            raise SecretStoreError(str(exc)) from exc
        if not (token or "").strip():
            raise SecretStoreError("vault: AEGIS_VAULT_TOKEN is not set")
        self._meta = self.base.replace("/data/", "/metadata/", 1)
        self._http = httpx.Client(timeout=httpx.Timeout(10.0, connect=5.0), transport=transport,
                                  trust_env=False, follow_redirects=False,
                                  headers={"X-Vault-Token": token.strip()})

    def _url(self, ref: str, base: str | None = None) -> str:
        if not REF_RE.fullmatch(ref):
            raise SecretStoreError("malformed reference")
        return f"{base or self.base}/{ref}"

    def _call(self, method: str, url: str, ref: str, **kw):
        import httpx
        try:
            r = self._http.request(method, url, **kw)
        except httpx.HTTPError as exc:
            raise SecretStoreError(f"vault: {type(exc).__name__}") from exc
        if r.status_code == 404:
            raise SecretStoreError(f"{ref}: not in store")
        if r.status_code >= 400:
            raise SecretStoreError(f"vault: HTTP {r.status_code}")
        return r

    def put(self, ref, value):
        self._call("POST", self._url(ref), ref, json={"data": {"value": value}})

    def get(self, ref):
        try:
            return str(self._call("GET", self._url(ref), ref).json()["data"]["data"]["value"])
        except (ValueError, KeyError, TypeError) as exc:
            raise SecretStoreError(f"{ref}: unexpected vault response") from exc

    def delete(self, ref):
        """Metadata delete: removes every version, not a recoverable soft delete."""
        try:
            self._call("DELETE", self._url(ref, self._meta), ref)
        except SecretStoreError as exc:
            if "not in store" not in str(exc):
                raise


def configured() -> bool:
    return bool((os.environ.get("AEGIS_SECRET_STORE") or "").strip())


def retention_days() -> int:
    """AEGIS_SECRET_RETENTION_DAYS (default 30; 0 keeps forever). Approvals expire in
    hours, so a value older than the window can no longer be promoted; audit needs only
    the reference, never the value."""
    raw = (os.environ.get("AEGIS_SECRET_RETENTION_DAYS") or "30").strip()
    if not raw.isdigit():
        raise SecretStoreError("AEGIS_SECRET_RETENTION_DAYS must be a whole number of days")
    return int(raw)


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
    """Non-overlapping (start, end, kind, label) for every secret VALUE; first matcher wins.
    Only a well-formed reference is skipped: a credential that merely STARTS with the
    prefix, or is literally "<redacted>", is still a credential."""
    found: list[tuple[int, int, str, str]] = []
    for kind, label, rx in _matchers():
        for m in rx.finditer(text):
            a, b = m.span("s")
            if a == b or REF_RE.fullmatch(text[a:b]):
                continue
            if any(a < e and s < b for s, e, _k, _l in found):
                continue
            found.append((a, b, kind, label))
    return sorted(found)


def raw_secret_labels(text: str) -> list[str]:
    """Labels of credentials present in clear (not yet referenced) — empty = clean."""
    return sorted({label for _a, _b, _k, label in _spans(text or "")})


def tokenize_text(text: str, *, run_id: str, store, device: str = "",
                  written: list[str] | None = None) -> tuple[str, list[dict], dict[str, str]]:
    """(text with references, ref records, {value: ref}). Idempotent on its own output.
    ``written`` collects every reference stored, so a failed run can delete them."""
    refs: list[dict] = []
    mapping: dict[str, str] = {}
    out = text or ""
    for a, b, kind, label in reversed(_spans(out)):
        value = out[a:b]
        ref = store.ref_for(run_id, value)
        if value not in mapping:
            store.put(ref, value)
            if written is not None:
                written.append(ref)
            mapping[value] = ref
            refs.append({"ref": ref, "device": device, "kind": kind, "label": label})
        out = out[:a] + ref + out[b:]
    return out, list(reversed(refs)), mapping


# Free-text fields: anything that can quote operator input or config text. Structural
# fields (enums such as status/decision/risk_tier, ids, hashes, versions) are schema-
# controlled and never carry a credential; scrubbing them would corrupt the record.
FREE_TEXT_KEYS = frozenset({
    "intent", "config", "grounded_commands", "plan", "findings", "evidence", "examples",
    "reason", "issues", "routes_added", "routes_removed", "sessions_dropped", "description",
})
# Config-like free text: the credential PATTERNS run here. Prose (intent, evidence,
# reason, description) only gets value scrubbing: patterns over prose misfire ("password
# to ..." is not a credential), so a credential typed ONLY into prose and never into the
# configuration is not detected (documented limitation).
CONFIG_TEXT_KEYS = frozenset({"config", "grounded_commands", "plan", "findings", "examples"})


def _value_rx(values) -> re.Pattern | None:
    """Values ≥4 chars match anywhere (also inside a longer token, e.g. "pw-backup");
    shorter ones only as a whole token, so a 2-char key cannot shred ordinary words."""
    vals = sorted(set(v for v in values if v), key=len, reverse=True)
    if not vals:
        return None
    alts = [re.escape(v) if len(v) >= 4 else r"(?<![\w$-])" + re.escape(v) + r"(?![\w$-])"
            for v in vals]
    return re.compile("|".join(alts))


def _outside_refs(text: str, fn) -> str:
    """Apply ``fn`` to the text BETWEEN references, so a value can never be matched (or
    replaced) inside an AEGISREF token's hex."""
    parts = REF_RE.split(text)
    refs = REF_RE.findall(text)
    out = [fn(parts[0])]
    for ref, part in zip(refs, parts[1:]):
        out += [ref, fn(part)]
    return "".join(out)


def _walk_free_text(obj, fn, inside: bool = False, keys: frozenset = FREE_TEXT_KEYS):
    if isinstance(obj, str):
        return fn(obj) if inside else obj
    if isinstance(obj, list):
        return [_walk_free_text(v, fn, inside, keys) for v in obj]
    if isinstance(obj, dict):
        return {k: _walk_free_text(v, fn, inside or k in keys, keys) for k, v in obj.items()}
    return obj


def _scrub(obj, rx: re.Pattern | None, mapping: dict[str, str]):
    if rx is None:
        return obj
    return _walk_free_text(obj, lambda s: _outside_refs(
        s, lambda seg: rx.sub(lambda m: mapping[m.group(0)], seg)))


def leaked_values(obj, values) -> list[str]:
    """Values still present in any free-text field (outside references)."""
    hits: set[str] = set()
    rx = _value_rx(values)
    if rx is None:
        return []

    def seg_hits(seg: str) -> str:
        hits.update(m.group(0) for m in rx.finditer(seg))
        return seg

    def look(s: str) -> str:
        _outside_refs(s, seg_hits)
        return s
    _walk_free_text(obj, look)
    return sorted(hits)


def protect_bundle(bundle: dict, store) -> dict:
    """Tokenize every credential in an UNSEALED bundle, scrub any other occurrence of the
    values, record ``change.secret_refs``, re-hash. Fails closed (SecretStoreError) if a
    value would still be present afterwards, deleting what this run stored. Returns a
    new dict."""
    from ..evidence.bundler import compute_sha256

    run_id = str(bundle.get("run_id") or "")
    out = json.loads(json.dumps(bundle))
    mapping: dict[str, str] = {}
    refs: list[dict] = []
    written: list[str] = []

    def add(recs):
        seen = {(r["ref"], r["device"]) for r in refs}
        refs.extend(r for r in recs if (r["ref"], r["device"]) not in seen)

    try:
        for c in out.get("change", {}).get("generated_configs") or []:
            text, recs, m = tokenize_text(c.get("config") or "", run_id=run_id, store=store,
                                          device=str(c.get("device") or ""), written=written)
            c["config"] = text
            mapping.update(m)
            add(recs)

        # the other config-like text (rollback plan, findings, examples) gets the same
        # pattern-based tokenization; rollback entries are recorded with device "rollback"
        def tok_as(device: str):
            def tok(s: str) -> str:
                text, recs, m = tokenize_text(s, run_id=run_id, store=store, device=device,
                                              written=written)
                mapping.update(m)
                add(recs)
                return text
            return tok
        if isinstance(out.get("rollback"), dict):
            out["rollback"] = _walk_free_text(out["rollback"], tok_as("rollback"),
                                              keys=CONFIG_TEXT_KEYS)
        out = _walk_free_text(out, tok_as(""), keys=CONFIG_TEXT_KEYS)
        out = _scrub(out, _value_rx(mapping), mapping)
        leaks = leaked_values(out, mapping)
        if leaks:
            raise SecretStoreError(f"{len(leaks)} credential value(s) survived tokenization")
    except BaseException:
        for ref in written:
            try:
                store.delete(ref)
            except Exception:  # noqa: BLE001 — best effort; the original error matters more
                pass
        raise
    out.setdefault("change", {})["secret_refs"] = refs
    out["integrity"]["sha256"] = ""
    out["integrity"]["sha256"] = compute_sha256(out)
    return out


def resolve_text(text: str, *, run_id: str, store,
                 collect: dict[str, str] | None = None) -> str:
    """Replace every reference by its value, verifying each value re-derives its token.
    ``collect`` receives {value: ref}, so callers can scrub anything that echoes a value."""
    def repl(m: re.Match) -> str:
        ref = m.group(0)
        value = store.get(ref)
        if not hmac.compare_digest(store.ref_for(run_id, value), ref):
            raise SecretStoreError(f"{ref}: stored value does not match its reference")
        if collect is not None:
            collect[value] = ref
        return value
    return REF_RE.sub(repl, text or "")


def scrub_values(obj, mapping: dict[str, str]):
    """Replace resolved values with their references in ANY string of ``obj`` (used on
    connector output, which is not a schema-controlled record)."""
    rx = _value_rx(mapping)
    if rx is None:
        return obj
    if isinstance(obj, str):
        return _outside_refs(obj, lambda seg: rx.sub(lambda m: mapping[m.group(0)], seg))
    if isinstance(obj, list):
        return [scrub_values(v, mapping) for v in obj]
    if isinstance(obj, dict):
        return {k: scrub_values(v, mapping) for k, v in obj.items()}
    return obj


def has_refs(text: str) -> bool:
    return bool(REF_RE.search(text or ""))
