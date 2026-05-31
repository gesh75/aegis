"""aegis/core/llm/ — the single shared LLM egress (CROSS-1) + model-agnostic adapter (#4).

The ONLY import surface other modules should use. The single-egress test asserts that no
module outside aegis/core/llm/ imports `anthropic` or POSTs to an LLM completion URL — so
everyone consumes the egress through these exports.
"""
from __future__ import annotations

from .adapter import LLMAdapter
from .backends import (
    AnthropicCloudBackend,
    Capability,
    HashKind,
    LLMAttempt,
    LLMBackend,
    LLMResult,
    ModelIdentity,
    OpenAICompatLocalBackend,
    Provider,
    Tier,
    build_backend,
)
from .config import AdapterConfig, BackendSpec, capabilities_for
from .egress import HookBus, LLMEgress, LLMRequest
from .errors import (
    AdapterError,
    AuthError,
    ContextExceeded,
    Permanent,
    RateLimited,
    Transient,
    classify,
    is_retryable,
)
from .identity import resolve_model_identity, unknown_identity

__all__ = [
    # egress (CROSS-1)
    "LLMEgress",
    "LLMRequest",
    "HookBus",
    # adapter façade
    "LLMAdapter",
    # backends
    "LLMBackend",
    "OpenAICompatLocalBackend",
    "AnthropicCloudBackend",
    "build_backend",
    # data structures
    "LLMResult",
    "LLMAttempt",
    "ModelIdentity",
    "Provider",
    "Capability",
    "HashKind",
    "Tier",
    # config
    "AdapterConfig",
    "BackendSpec",
    "capabilities_for",
    # errors
    "AdapterError",
    "AuthError",
    "RateLimited",
    "ContextExceeded",
    "Transient",
    "Permanent",
    "classify",
    "is_retryable",
    # identity
    "resolve_model_identity",
    "unknown_identity",
]
