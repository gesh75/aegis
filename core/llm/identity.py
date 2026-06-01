"""aegis/core/llm/identity.py — model identity resolution (THE WEDGE, part 2).

Part of PR-1 (CROSS-1 shared LLM egress + #4 model-agnostic adapter).

LOCAL backend  => a REAL sha256 of the served weights file ("weights-sha256").
CLOUD backend  => an honest "identity-claim" with model_hash=None (a weight hash for a
                  hosted API is physically impossible; we NEVER fake one).

Multi-GB GGUF/safetensors files are hashed ONCE and cached by (path, mtime, size) so
generate_config() does not re-hash on every inference.

Import-safe, fully type-hinted, no network.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone

from .backends import ModelIdentity
from .config import BackendSpec, capabilities_for

# (path, mtime, size) -> sha256 hex. Auto-invalidates on file change.
_HASH_CACHE: dict[tuple[str, float, int], str] = {}

_LOCAL_PROVIDER = "openai-compatible-local"
_CHUNK = 1 << 20  # 1 MiB


def _hash_local_weights(path: str) -> str | None:
    """SHA-256 of the served weights file, cached by (path, mtime, size). Returns None
    if the path is empty/missing/unreadable — identity then downgrades to an honest
    'identity-claim' rather than failing the whole run."""
    if not path or not os.path.exists(path):
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (path, st.st_mtime, st.st_size)
    cached = _HASH_CACHE.get(key)
    if cached is not None:
        return cached
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(_CHUNK), b""):
                h.update(chunk)
    except OSError:
        return None
    digest = h.hexdigest()
    _HASH_CACHE[key] = digest
    return digest


def resolve_model_identity(spec: BackendSpec) -> ModelIdentity:
    """Local => real weights-sha256 attestation when the weights file is present.
    Cloud => identity-claim with model_hash=None (never faked)."""
    is_local = spec.provider == _LOCAL_PROVIDER
    weight_hash = _hash_local_weights(spec.weights_path or "") if is_local else None
    return ModelIdentity(
        provider=spec.provider,  # type: ignore[arg-type]
        model=spec.model,
        model_hash=weight_hash,
        model_hash_kind="weights-sha256" if weight_hash else "identity-claim",
        api_version=spec.api_version,
        capabilities=capabilities_for(spec.model),  # type: ignore[arg-type]
        resolved_at_utc=datetime.now(timezone.utc).isoformat(),
    )


def unknown_identity(created_utc: str) -> dict[str, object]:
    """_UNKNOWN_IDENTITY for config_import runs (no LLM touched the change).

    Keeps every bundle schema-valid (v1.1 requires change.model_identity) and honest —
    an operator-supplied config never claims a model produced it.
    """
    return {
        "provider": "none",
        "model": "operator-supplied",
        "model_hash": None,
        "model_hash_kind": "identity-claim",
        "api_version": None,
        "capabilities": [],
        "resolved_at_utc": created_utc,
    }


class IdentitySink:
    """Captures the ModelIdentity from the egress 'after_response' hook so the pipeline can
    seal WHICH model produced a change into the evidence bundle (#4 wedge).

    Wire-up:  egress.on("after_response", sink.capture)
    Read:     sink.last  /  sink.as_bundle_dict()  -> pass to run_preflight(model_identity=...)
    Process-local, last-write-wins (the egress makes one successful call per generate)."""

    def __init__(self) -> None:
        self._last: ModelIdentity | None = None

    @property
    def last(self) -> ModelIdentity | None:
        return self._last

    def capture(self, provider: str, identity: ModelIdentity) -> None:
        """after_response(provider, identity) observer — never raises into the egress."""
        self._last = identity

    def as_bundle_dict(self) -> dict[str, object] | None:
        return self._last.to_bundle_dict() if self._last is not None else None
