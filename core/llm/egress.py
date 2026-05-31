"""aegis/core/llm/egress.py — the single shared LLM egress + hook bus (CROSS-1).

ONE place every LLM call leaves the process. An ordered fallback chain (local-first,
cost-aware) with retry / exponential backoff / per-provider cooldown — LiteLLM's decision
*logic* with none of its dependency tree — wrapped in a 4-event hook bus so #2
(cache_control), #4 (model-identity), and #1 (Reflexion) attach WITHOUT forking the egress.

The core knows nothing about caching, identity schemas, or reflexion — it only emits events.
This is the load-bearing decoupling: the chain stays small and auditable; features are tenants.

Immutability: LLMRequest / LLMResult / ModelIdentity / LLMAttempt are all frozen. The ONE
mutable bit is the per-provider cooldown map (process-local, never part of a returned result).
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Literal

from .backends import LLMAttempt, LLMBackend, LLMResult, ModelIdentity, build_backend
from .config import AdapterConfig
from .errors import AdapterError, RateLimited, is_retryable

Tier = Literal["cheap", "deep"]
HookEvent = Literal["before_request", "build_payload", "after_response", "on_result"]

_log = logging.getLogger("aegis.llm.egress")


@dataclass(frozen=True)
class LLMRequest:
    """Immutable call envelope. trace_id lets #1 correlate generate→verify→repair."""

    system: str
    user: str
    max_tokens: int = 500
    temperature: float = 0.1
    tier: Tier = "cheap"
    trace_id: str | None = None
    # opaque per-call hints (e.g. #2's prefix_kind); the core never interprets these.
    hints: Mapping[str, object] = field(default_factory=dict)


class HookBus:
    """Deterministic, in-process, synchronous hook dispatch — the ENTIRE extension surface.

    Transform hooks (before_request / build_payload) may return a replacement value;
    observe hooks (after_response / on_result) return None. A hook that raises is ISOLATED:
    the egress logs and continues. A broken cache/identity hook must NEVER break an LLM call.
    """

    def __init__(self) -> None:
        self._hooks: dict[HookEvent, list[Callable]] = defaultdict(list)

    def register(self, event: HookEvent, fn: Callable) -> None:
        self._hooks[event].append(fn)

    def transform(self, event: HookEvent, value, *args):
        for fn in self._hooks[event]:
            try:
                out = fn(value, *args)
                if out is not None:
                    value = out
            except Exception as exc:  # noqa: BLE001 — isolation is the point
                _log_hook_error(event, fn, exc)
        return value

    def observe(self, event: HookEvent, *args) -> None:
        for fn in self._hooks[event]:
            try:
                fn(*args)
            except Exception as exc:  # noqa: BLE001
                _log_hook_error(event, fn, exc)


class LLMEgress:
    """The single egress. Ordered fallback chain + retry/cooldown + hook bus."""

    def __init__(
        self,
        config: AdapterConfig,
        backends: tuple[LLMBackend, ...],
        hooks: HookBus | None = None,
    ) -> None:
        self._cfg = config
        self._backends = backends  # already air-gap-checked at construction
        self._hooks = hooks or HookBus()
        self._cooldown_until: dict[str, float] = {}  # the ONE mutable bit (process-local)

    @classmethod
    def from_env(cls, hooks: HookBus | None = None) -> "LLMEgress":
        cfg = AdapterConfig.from_env()  # drops the cloud backend when AEGIS_AIRGAP=1
        backends = tuple(build_backend(s, timeout_s=cfg.timeout_s) for s in cfg.chain)
        return cls(cfg, backends, hooks)

    def on(self, event: HookEvent, fn: Callable) -> "LLMEgress":
        """Register a hook. #2/#4/#1 call this once at wire-up. Fluent for chaining.

        NOTE: ``build_payload`` is registerable today and is fired by #2 once the backends
        accept a payload hook; PR-1 fires before_request / after_response / on_result.
        """
        self._hooks.register(event, fn)
        return self

    async def complete(self, req: LLMRequest) -> LLMResult:
        req = self._hooks.transform("before_request", req)  # ← #2 / #1 hook point
        ordered = self._ordered_backends(req.tier)
        attempts: list[LLMAttempt] = []
        run_t0 = time.perf_counter()

        for backend in ordered:
            if self._is_cooled_down(backend.provider):
                continue
            outcome = await self._try_backend(backend, req, attempts)
            if outcome is not None:
                text, identity = outcome
                self._hooks.observe("after_response", backend.provider, identity)  # ← #4
                total_ms = int((time.perf_counter() - run_t0) * 1000)
                result = LLMResult(
                    text=text,
                    identity=identity,
                    attempts=tuple(attempts),
                    total_latency_ms=total_ms,
                )
                self._hooks.observe("on_result", result)  # ← #1 / #4 hook point
                return result

        total_ms = int((time.perf_counter() - run_t0) * 1000)
        raise AdapterError(
            message=f"all backends failed ({len(attempts)} attempts, {total_ms}ms)",
            provider="egress",
            status=None,
        )

    def complete_sync(self, req: LLMRequest) -> LLMResult:
        """Sync bridge for legacy callers. Loop-safe: if already inside an event loop
        (Flask under an async server) offload to a worker thread instead of asyncio.run
        (which would raise 'event loop already running')."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.complete(req))
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(lambda: asyncio.run(self.complete(req))).result()

    # ── internals ────────────────────────────────────────────────────────
    def _ordered_backends(self, tier: Tier) -> tuple[LLMBackend, ...]:
        """Cost-aware ordering. 'cheap' => chain order (local first). 'deep' => prefer a
        cloud backend first when present + not air-gapped (in air-gap 'deep' stays local)."""
        if tier == "deep" and not self._cfg.airgap:
            cloud = tuple(b for b in self._backends if b.provider == "anthropic-cloud")
            rest = tuple(b for b in self._backends if b.provider != "anthropic-cloud")
            return cloud + rest
        return self._backends

    def _is_cooled_down(self, provider: str) -> bool:
        until = self._cooldown_until.get(provider)
        return until is not None and time.monotonic() < until

    def _cool_down(self, provider: str) -> None:
        self._cooldown_until[provider] = time.monotonic() + self._cfg.cooldown_s

    async def _try_backend(
        self, backend: LLMBackend, req: LLMRequest, attempts: list[LLMAttempt]
    ) -> tuple[str, ModelIdentity] | None:
        """Retry one backend ≤ max_retries. Append an LLMAttempt per try. Returns
        (text, identity) on success, else None (skip to the next backend in the chain)."""
        for attempt in range(self._cfg.max_retries + 1):
            t0 = time.perf_counter()
            try:
                text, identity = await backend.complete(
                    system=req.system,
                    user=req.user,
                    max_tokens=req.max_tokens,
                    temperature=req.temperature,
                )
                attempts.append(
                    LLMAttempt(
                        provider=backend.provider,
                        model=identity.model,
                        ok=True,
                        status=200,
                        error_kind=None,
                        latency_ms=int((time.perf_counter() - t0) * 1000),
                    )
                )
                return text, identity
            except AdapterError as err:
                attempts.append(
                    LLMAttempt(
                        provider=backend.provider,
                        model="unknown",
                        ok=False,
                        status=err.status,
                        error_kind=type(err).__name__,
                        latency_ms=int((time.perf_counter() - t0) * 1000),
                    )
                )
                if not is_retryable(err) or attempt >= self._cfg.max_retries:
                    if isinstance(err, RateLimited):
                        self._cool_down(backend.provider)
                    return None
                await asyncio.sleep(self._backoff_s(attempt, err))
        return None

    def _backoff_s(self, attempt: int, err: AdapterError) -> float:
        """Exponential backoff; honor Retry-After on 429 when present."""
        if isinstance(err, RateLimited) and err.retry_after_s is not None:
            return err.retry_after_s
        return self._cfg.base_backoff_s * (2**attempt)


def _log_hook_error(event: HookEvent, fn: Callable, exc: Exception) -> None:
    _log.warning(
        "hook %s on %s failed (isolated, call continues): %s",
        getattr(fn, "__name__", fn),
        event,
        exc,
    )
