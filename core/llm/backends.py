"""aegis/core/llm/backends.py — backend Protocol + the two concrete backends.

Part of PR-1 (CROSS-1 shared LLM egress + #4 model-agnostic adapter).

Two backends, no more (NOT a 100+-provider router):
  - OpenAICompatLocalBackend : POST {base}/v1/chat/completions  (vLLM/Ollama/llama.cpp/LM Studio)
  - AnthropicCloudBackend    : POST {base}/v1/messages          (RAW httpx — NO SDK import)

Why raw httpx for the cloud path: importing the `anthropic` SDK would put it in
sys.modules and break the air-gap invariant (airgap.assert_no_cloud_sdk_imported). A raw
POST keeps the trust surface minimal and the air-gap claim provable.

The local backend's request body is BYTE-COMPATIBLE with what HttpBackend.generate_config()
posts today (http_backend.py:166-177): {"model","messages":[system,user],"temperature",
"stream":false} (+ max_tokens, which OpenAI-compat runtimes accept).

All data structures (LLMResult / ModelIdentity / LLMAttempt) are frozen/immutable. The
backends accept an optional httpx transport so tests drive them with httpx.MockTransport
(no sockets).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

import httpx

from .config import BackendSpec
from .errors import AdapterError, classify

if TYPE_CHECKING:  # avoid importing for runtime; type hints only
    pass

Provider = Literal["openai-compatible-local", "anthropic-cloud"]
Capability = Literal["chat", "json", "tools"]
HashKind = Literal["weights-sha256", "identity-claim"]
Tier = Literal["cheap", "deep"]


@dataclass(frozen=True)
class ModelIdentity:
    """Goes verbatim into change.model_identity in the sealed bundle (THE WEDGE).

    LOCAL backend: model_hash is a real SHA-256 of the served weights file
    (model_hash_kind="weights-sha256"). CLOUD backend: model_hash is None with
    kind="identity-claim" — NEVER a faked weight hash for a hosted API.
    """

    provider: Provider
    model: str
    model_hash: str | None
    model_hash_kind: HashKind
    api_version: str | None
    capabilities: tuple[Capability, ...]  # tuple => immutable + hashable
    resolved_at_utc: str  # ISO-8601

    def to_bundle_dict(self) -> dict[str, object]:
        """Exact shape sealed into bundle['change']['model_identity'] (schema v1.1)."""
        return {
            "provider": self.provider,
            "model": self.model,
            "model_hash": self.model_hash,
            "model_hash_kind": self.model_hash_kind,
            "api_version": self.api_version,
            "capabilities": list(self.capabilities),
            "resolved_at_utc": self.resolved_at_utc,
        }


@dataclass(frozen=True)
class LLMAttempt:
    """One try in the fallback chain — recorded for the optional audit trail."""

    provider: Provider
    model: str
    ok: bool
    status: int | None
    error_kind: str | None  # name of the typed error, if any
    latency_ms: int


@dataclass(frozen=True)
class LLMResult:
    text: str
    identity: ModelIdentity
    attempts: tuple[LLMAttempt, ...]
    total_latency_ms: int


@runtime_checkable
class LLMBackend(Protocol):
    """The minimal surface the egress needs from any backend."""

    provider: Provider

    async def complete(
        self, *, system: str, user: str, max_tokens: int, temperature: float = 0.1
    ) -> tuple[str, ModelIdentity]:
        """Single non-streamed completion. Raises a typed AdapterError on failure."""
        ...

    def identity(self) -> ModelIdentity:
        """Resolve identity WITHOUT making a request (used for air-gap pre-checks)."""
        ...


def _retry_after_seconds(resp: httpx.Response) -> float | None:
    """Prefer the HTTP Retry-After header (seconds form)."""
    raw = resp.headers.get("retry-after")
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


class OpenAICompatLocalBackend:
    """POST {base}/v1/chat/completions — the universal local contract.

    Construction runs the air-gap pre-check (loopback enforced when AEGIS_AIRGAP=1).
    """

    provider: Provider = "openai-compatible-local"

    def __init__(
        self,
        spec: BackendSpec,
        timeout_s: float = 60.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        from .airgap import assert_airgap_ok

        if os.environ.get("AEGIS_AIRGAP", "") == "1":
            assert_airgap_ok(self.provider, spec.base_url)
        self._spec = spec
        self._timeout_s = timeout_s
        self._transport = transport  # injected only in tests (httpx.MockTransport)

    def identity(self) -> ModelIdentity:
        from .identity import resolve_model_identity

        return resolve_model_identity(self._spec)

    async def complete(
        self, *, system: str, user: str, max_tokens: int, temperature: float = 0.1
    ) -> tuple[str, ModelIdentity]:
        body = {
            "model": self._spec.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "stream": False,
            "max_tokens": max_tokens,
        }
        url = f"{self._spec.base_url}/v1/chat/completions"
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=self._timeout_s
            ) as client:
                resp = await client.post(url, json=body)
        except httpx.RequestError as exc:  # conn reset / DNS / timeout -> Transient
            raise classify(None, str(exc), self.provider) from exc

        if resp.status_code >= 400:
            err = classify(resp.status_code, resp.text, self.provider)
            from .errors import RateLimited

            if isinstance(err, RateLimited) and err.retry_after_s is None:
                hdr = _retry_after_seconds(resp)
                if hdr is not None:
                    err = RateLimited(
                        message=err.message,
                        provider=err.provider,
                        status=err.status,
                        retry_after_s=hdr,
                    )
            raise err

        try:
            text = resp.json()["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError) as exc:
            from .errors import Permanent

            raise Permanent(
                message="malformed OpenAI-compat completion response",
                provider=self.provider,
                status=resp.status_code,
            ) from exc
        return text, self.identity()


class AnthropicCloudBackend:
    """POST {base}/v1/messages via RAW httpx — air-gap forbidden, no SDK import.

    Reads ANTHROPIC_API_KEY at call time; the key is NEVER stored or logged.
    """

    provider: Provider = "anthropic-cloud"

    def __init__(
        self,
        spec: BackendSpec,
        timeout_s: float = 60.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        from .airgap import assert_airgap_ok

        # In air-gap mode this RAISES — the cloud backend must never construct.
        if os.environ.get("AEGIS_AIRGAP", "") == "1":
            assert_airgap_ok(self.provider, spec.base_url)
        self._spec = spec
        self._timeout_s = timeout_s
        self._transport = transport

    def identity(self) -> ModelIdentity:
        from .identity import resolve_model_identity

        return resolve_model_identity(self._spec)

    async def complete(
        self, *, system: str, user: str, max_tokens: int, temperature: float = 0.1
    ) -> tuple[str, ModelIdentity]:
        from .errors import AuthError, Permanent

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise AuthError(
                message="ANTHROPIC_API_KEY is not set", provider=self.provider, status=401
            )
        headers = {
            "x-api-key": api_key,
            "anthropic-version": self._spec.api_version or "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": self._spec.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        url = f"{self._spec.base_url}/v1/messages"
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=self._timeout_s
            ) as client:
                resp = await client.post(url, json=body, headers=headers)
        except httpx.RequestError as exc:
            raise classify(None, str(exc), self.provider) from exc

        if resp.status_code >= 400:
            err = classify(resp.status_code, resp.text, self.provider)
            from .errors import RateLimited

            if isinstance(err, RateLimited) and err.retry_after_s is None:
                hdr = _retry_after_seconds(resp)
                if hdr is not None:
                    err = RateLimited(
                        message=err.message,
                        provider=err.provider,
                        status=err.status,
                        retry_after_s=hdr,
                    )
            raise err

        try:
            text = resp.json()["content"][0]["text"]
        except (KeyError, IndexError, ValueError) as exc:
            raise Permanent(
                message="malformed Anthropic messages response",
                provider=self.provider,
                status=resp.status_code,
            ) from exc
        return text, self.identity()


def build_backend(
    spec: BackendSpec,
    timeout_s: float = 60.0,
    transport: httpx.BaseTransport | None = None,
) -> LLMBackend:
    """Factory: construct the right backend for a spec (air-gap checks fire here)."""
    if spec.provider == "openai-compatible-local":
        return OpenAICompatLocalBackend(spec, timeout_s=timeout_s, transport=transport)
    if spec.provider == "anthropic-cloud":
        return AnthropicCloudBackend(spec, timeout_s=timeout_s, transport=transport)
    raise AdapterError(message=f"unknown provider {spec.provider!r}", provider=spec.provider)
