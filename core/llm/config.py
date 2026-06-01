"""aegis/core/llm/config.py — immutable, env-driven adapter configuration.

Part of PR-1 (CROSS-1 shared LLM egress + #4 model-agnostic adapter).

Cost-aware defaults: the fallback chain is LOCAL-FIRST. Cloud is fallback only, and is
DROPPED from the chain entirely in air-gap mode (defense in depth — also refused at
construction by airgap.py).

Env vars read:
  AEGIS_AIRGAP        "1" => air-gap mode (drop cloud, refuse non-loopback)
  AEGIS_LLM_URL       local OpenAI-compat base (default http://localhost:11434)
  AEGIS_LLM_MODEL     local model id          (default ai/qwen3:latest)
  AEGIS_LLM_WEIGHTS   path to local weights file for sha256 attestation (optional)
  MODEL_RUNNER_URL    alt local base (Docker Model Runner :12434), optional
  ANTHROPIC_API_KEY   presence enables the cloud fallback (NEVER logged/echoed)
  ANTHROPIC_MODEL     cloud model id          (default claude-haiku-4-5-20251001)
  ANTHROPIC_VERSION   cloud api version       (default 2023-06-01)

Import-safe, fully type-hinted. `from_env()` is side-effect-free (reads env, builds frozen
specs). NO secret material is stored on the config — only a derived "cloud available" bool.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

# Static capability map keyed by model string. Manual refresh only — auto-probing a model
# would risk egress in air-gap mode. Conservative default ('chat',) for unknown models.
_CAPABILITIES: dict[str, tuple[str, ...]] = {
    "ai/qwen3:latest": ("chat", "json"),
    "gemma4:latest": ("chat",),
    "claude-haiku-4-5-20251001": ("chat", "json", "tools"),
}

_DEFAULT_LOCAL_URL = "http://localhost:11434"
_DEFAULT_LOCAL_MODEL = "ai/qwen3:latest"
_DEFAULT_CLOUD_MODEL = "claude-haiku-4-5-20251001"
_DEFAULT_CLOUD_VERSION = "2023-06-01"
_CLOUD_BASE_URL = "https://api.anthropic.com"


@dataclass(frozen=True)
class BackendSpec:
    """One ordered link in the fallback chain. Immutable."""

    provider: str  # "openai-compatible-local" | "anthropic-cloud"
    base_url: str
    model: str
    api_version: str | None = None
    weights_path: str | None = None  # local only; enables weights-sha256 attestation


@dataclass(frozen=True)
class AdapterConfig:
    """Immutable adapter configuration. Carries NO secret material."""

    chain: tuple[BackendSpec, ...]  # ordered fallback: local first (cost-aware)
    airgap: bool
    cloud_available: bool  # derived from ANTHROPIC_API_KEY presence; never the key itself
    max_retries: int = 2
    base_backoff_s: float = 0.5
    cooldown_s: float = 60.0  # LiteLLM's failing-provider cooldown idea
    timeout_s: float = 60.0

    @staticmethod
    def from_env() -> "AdapterConfig":
        """Build an immutable config from the environment.

        In air-gap mode the anthropic-cloud spec is DROPPED from the chain here (defense
        in depth) and ALSO refused at construction by airgap.assert_airgap_ok().
        """
        airgap = os.environ.get("AEGIS_AIRGAP", "") == "1"

        local_url = (
            os.environ.get("AEGIS_LLM_URL")
            or os.environ.get("MODEL_RUNNER_URL")
            or _DEFAULT_LOCAL_URL
        )
        local_model = os.environ.get("AEGIS_LLM_MODEL", _DEFAULT_LOCAL_MODEL)
        weights_path = os.environ.get("AEGIS_LLM_WEIGHTS") or None

        local_spec = BackendSpec(
            provider="openai-compatible-local",
            base_url=local_url.rstrip("/"),
            model=local_model,
            api_version=None,
            weights_path=weights_path,
        )

        chain: list[BackendSpec] = [local_spec]

        # presence-only check — the key is NEVER stored on the config object
        cloud_available = bool(os.environ.get("ANTHROPIC_API_KEY"))
        if cloud_available and not airgap:
            chain.append(
                BackendSpec(
                    provider="anthropic-cloud",
                    base_url=_CLOUD_BASE_URL,
                    model=os.environ.get("ANTHROPIC_MODEL", _DEFAULT_CLOUD_MODEL),
                    api_version=os.environ.get("ANTHROPIC_VERSION", _DEFAULT_CLOUD_VERSION),
                    weights_path=None,
                )
            )

        return AdapterConfig(
            chain=tuple(chain),
            airgap=airgap,
            cloud_available=cloud_available,
        )


def capabilities_for(model: str) -> tuple[str, ...]:
    """Conservative default ('chat',) for any model not in the static map."""
    return _CAPABILITIES.get(model, ("chat",))
