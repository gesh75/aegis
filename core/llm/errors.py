"""aegis/core/llm/errors.py — typed error taxonomy + retry decision-logic.

Part of PR-1 (CROSS-1 shared LLM egress + #4 model-agnostic adapter).

We port LiteLLM's *ideas* — a small typed exception hierarchy, an is-retryable
predicate, and Retry-After honoring — WITHOUT its 100+-provider dependency tree.
Scoped to exactly the two backends AEGIS ships: anthropic-cloud + openai-compat-local.

Import-safe, fully type-hinted, no network. `classify()` is real so the taxonomy is
unit-testable on day one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AdapterError(Exception):
    """Base typed error. Shape mirrors LiteLLM's exception (message/provider/status)
    minus the dependency. Frozen => immutable per coding-style rule."""

    message: str
    provider: str
    status: int | None = None

    def __str__(self) -> str:  # keep secrets out of logs — only structural fields
        return f"{type(self).__name__}[{self.provider} status={self.status}]: {self.message}"


@dataclass(frozen=True)
class AuthError(AdapterError):
    """401 / 403 — bad or missing key. NEVER retried. Skip to next backend."""


@dataclass(frozen=True)
class RateLimited(AdapterError):
    """429 — back off, honor Retry-After, then cool the provider."""

    retry_after_s: float | None = None


@dataclass(frozen=True)
class ContextExceeded(AdapterError):
    """400 / 413 with context-window phrasing. NEVER retried (same prompt = same fail)."""


@dataclass(frozen=True)
class Transient(AdapterError):
    """408 / 5xx / connection reset / timeout. RETRYABLE with backoff."""


@dataclass(frozen=True)
class Permanent(AdapterError):
    """400 / 404 / 422 (non-context). NEVER retried."""


# Phrases that mark a 4xx body as a context-window failure. Deliberately small —
# scoped to the two runtimes we ship (Anthropic + OpenAI-compat), NOT a cross-provider
# string zoo.
_CONTEXT_PHRASES: tuple[str, ...] = (
    "context window",
    "maximum context length",
    "too many tokens",
    "context_length_exceeded",
    "prompt is too long",
)


def classify(status: int | None, body: str, provider: str) -> AdapterError:
    """Map a raw HTTP status + response body into the small internal taxonomy.

    Fail-safe: an unknown 5xx / connection error is treated as retryable Transient.
      401/403                    -> AuthError       (never retry)
      429                        -> RateLimited     (retry, honor Retry-After)
      400/413 + context phrasing -> ContextExceeded (never retry)
      other 4xx                  -> Permanent       (never retry)
      408/5xx/None(conn error)   -> Transient       (retry)
    """
    low = (body or "").lower()

    if status in (401, 403):
        return AuthError(message="authentication failed", provider=provider, status=status)

    if status == 429:
        return RateLimited(
            message="rate limited",
            provider=provider,
            status=status,
            retry_after_s=_parse_retry_after(body),
        )

    if status in (400, 413) and any(p in low for p in _CONTEXT_PHRASES):
        return ContextExceeded(
            message="context window exceeded", provider=provider, status=status
        )

    if status is not None and 400 <= status < 500:
        return Permanent(
            message=f"permanent client error {status}", provider=provider, status=status
        )

    # status is None (connection reset / DNS / timeout) OR a 5xx OR 408 -> retryable.
    return Transient(
        message=f"transient error {status if status is not None else 'conn'}",
        provider=provider,
        status=status,
    )


def is_retryable(err: AdapterError) -> bool:
    """5-line decision: retry Transient + RateLimited; never the rest."""
    return isinstance(err, (Transient, RateLimited))


def _parse_retry_after(body: str) -> float | None:
    """Best-effort Retry-After extraction from a JSON-ish error body.

    NOTE: prefer the HTTP ``Retry-After`` *header* when the backend surfaces it; the
    backends pass it in via the body fallback only when the header is absent.
    """
    m = re.search(r'retry[_-]?after["\s:=]+(\d+(?:\.\d+)?)', (body or "").lower())
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None
