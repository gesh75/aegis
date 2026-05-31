"""aegis/core/llm/adapter.py — back-compat façade over the single egress.

Part of PR-1 (CROSS-1 shared LLM egress + #4 model-agnostic adapter).

The fallback-chain logic lives in ONE place — egress.py (LLMEgress). LLMAdapter is a thin
keyword-args façade preserving the signature the legacy sync callers expect
(HttpBackend.generate_config, multivendor _llm_query), so there is exactly one chain
implementation to audit — not two. This is the anti-fragmentation invariant the whole
proposal set exists to enforce.
"""
from __future__ import annotations

from .backends import LLMResult, Tier
from .egress import HookBus, LLMEgress, LLMRequest


class LLMAdapter:
    """Keyword-args façade. Delegates the chain + retry/cooldown to LLMEgress."""

    def __init__(self, egress: LLMEgress) -> None:
        self._egress = egress

    @classmethod
    def from_env(cls, hooks: HookBus | None = None) -> "LLMAdapter":
        """Build config + backends from env (air-gap checks fire at backend construction)."""
        return cls(LLMEgress.from_env(hooks=hooks))

    async def complete(
        self,
        *,
        system: str,
        user: str,
        max_tokens: int = 500,
        temperature: float = 0.1,
        tier: Tier = "cheap",
    ) -> LLMResult:
        return await self._egress.complete(
            LLMRequest(
                system=system,
                user=user,
                max_tokens=max_tokens,
                temperature=temperature,
                tier=tier,
            )
        )

    def complete_sync(
        self,
        *,
        system: str,
        user: str,
        max_tokens: int = 500,
        temperature: float = 0.1,
        tier: Tier = "cheap",
    ) -> LLMResult:
        return self._egress.complete_sync(
            LLMRequest(
                system=system,
                user=user,
                max_tokens=max_tokens,
                temperature=temperature,
                tier=tier,
            )
        )
