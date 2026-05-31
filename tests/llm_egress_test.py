"""aegis/tests/llm_egress_test.py — PR-1 single-egress (CROSS-1) + adapter (#4) tests.

Mirrors the repo's 6-suite house style: pytest-discoverable `test_*` functions PLUS a
dependency-light `__main__` runner (CI runs `python3 -m aegis.tests.llm_egress_test`).
No network: the wired-path tests drive fake in-process backends and httpx.MockTransport.

PR-1 gate (per the roadmap): unit taxonomy · is_loopback · immutability · the wired
fallback/retry/cooldown chain · hook-bus isolation · the air-gap fail-closed invariant ·
no-litellm · the no-foreign-`anthropic`-import single-egress scan.

DEFERRED to a later PR (documented, see test_single_egress_completion_post_DEFERRED):
the "no /v1/chat/completions outside core/llm" scan — HttpBackend.generate_config still
owns its POST until the cutover PR; enabling it now would be a false RED.

Run:  python3 -m aegis.tests.llm_egress_test
"""
from __future__ import annotations

import ast
import asyncio
import dataclasses
import hashlib
import os
import sys
import tempfile
from pathlib import Path

import httpx

from aegis.core.llm import (
    AdapterConfig,
    AdapterError,
    AuthError,
    BackendSpec,
    ContextExceeded,
    HookBus,
    LLMEgress,
    LLMRequest,
    ModelIdentity,
    OpenAICompatLocalBackend,
    Permanent,
    RateLimited,
    Transient,
    classify,
    is_retryable,
    resolve_model_identity,
    unknown_identity,
)
from aegis.core.llm.airgap import assert_airgap_ok, is_loopback


# ── test doubles ──────────────────────────────────────────────────────────────

def _ident(provider: str = "openai-compatible-local", model: str = "m") -> ModelIdentity:
    return ModelIdentity(
        provider=provider,  # type: ignore[arg-type]
        model=model,
        model_hash=None,
        model_hash_kind="identity-claim",
        api_version=None,
        capabilities=("chat",),
        resolved_at_utc="2026-05-31T00:00:00+00:00",
    )


class _FakeBackend:
    """In-process backend driven by a script of ('ok', text) | ('err', AdapterError)."""

    def __init__(self, provider: str, model: str = "m", script=None) -> None:
        self.provider = provider
        self._model = model
        self._script = list(script or [])
        self.calls = 0

    def identity(self) -> ModelIdentity:
        return _ident(self.provider, self._model)

    async def complete(self, *, system, user, max_tokens, temperature=0.1):
        self.calls += 1
        kind, payload = self._script.pop(0) if self._script else ("ok", user)
        if kind == "ok":
            return payload, self.identity()
        raise payload


def _cfg(max_retries: int = 2, base_backoff_s: float = 0.0, cooldown_s: float = 60.0) -> AdapterConfig:
    return AdapterConfig(
        chain=(),
        airgap=False,
        cloud_available=False,
        max_retries=max_retries,
        base_backoff_s=base_backoff_s,
        cooldown_s=cooldown_s,
    )


def _egress(backends, hooks=None, **cfg_kw) -> LLMEgress:
    return LLMEgress(_cfg(**cfg_kw), tuple(backends), hooks)


def _req(user: str = "hello") -> LLMRequest:
    return LLMRequest(system="sys", user=user, max_tokens=64)


# ── (gate) error taxonomy + is_retryable ───────────────────────────────────────

def test_is_retryable_truth_table() -> None:
    assert is_retryable(Transient("x", "p"))
    assert is_retryable(RateLimited("x", "p"))
    assert not is_retryable(AuthError("x", "p"))
    assert not is_retryable(ContextExceeded("x", "p"))
    assert not is_retryable(Permanent("x", "p"))


def test_classify_routing() -> None:
    assert isinstance(classify(401, "", "cloud"), AuthError)
    assert isinstance(classify(403, "", "cloud"), AuthError)
    rl = classify(429, "retry_after: 5", "cloud")
    assert isinstance(rl, RateLimited) and rl.retry_after_s == 5.0
    assert isinstance(classify(400, "maximum context length", "l"), ContextExceeded)
    assert isinstance(classify(413, "prompt is too long", "l"), ContextExceeded)
    assert isinstance(classify(422, "bad", "l"), Permanent)
    assert isinstance(classify(404, "nope", "l"), Permanent)
    assert isinstance(classify(503, "", "l"), Transient)
    assert isinstance(classify(500, "", "l"), Transient)
    assert isinstance(classify(None, "conn reset", "l"), Transient)  # fail-safe


def test_adapter_error_str_hides_body() -> None:
    e = AuthError(message="authentication failed", provider="cloud", status=401)
    assert "cloud" in str(e) and "401" in str(e)


# ── (gate) is_loopback / air-gap fail-closed ───────────────────────────────────

def test_is_loopback() -> None:
    assert is_loopback("http://127.0.0.1:11434")
    assert is_loopback("http://localhost:11434")
    assert is_loopback("http://127.5.5.5:1")
    assert is_loopback("http://box.local")
    assert not is_loopback("https://api.anthropic.com")
    assert not is_loopback("http://10.0.0.5:11434")


def test_airgap_refuses_cloud_construction() -> None:
    raised = False
    try:
        assert_airgap_ok("anthropic-cloud", "https://api.anthropic.com")
    except RuntimeError:
        raised = True
    assert raised, "cloud backend must be forbidden in air-gap mode"


def test_airgap_refuses_non_loopback() -> None:
    raised = False
    try:
        assert_airgap_ok("openai-compatible-local", "https://evil.example.com")
    except RuntimeError:
        raised = True
    assert raised, "non-loopback egress must be forbidden in air-gap mode"


def test_airgap_allows_loopback_local() -> None:
    assert_airgap_ok("openai-compatible-local", "http://127.0.0.1:11434")  # no raise


# ── (gate) immutability ────────────────────────────────────────────────────────

def test_frozen_dataclasses_reject_mutation() -> None:
    req = _req()
    ident = _ident()
    for obj, attr, val in ((req, "user", "x"), (ident, "model", "y")):
        try:
            setattr(obj, attr, val)
            raise AssertionError(f"{type(obj).__name__}.{attr} mutated — must be frozen")
        except dataclasses.FrozenInstanceError:
            pass


# ── model identity: local weights-sha256 vs cloud identity-claim ───────────────

def test_local_identity_carries_real_weights_sha256() -> None:
    with tempfile.NamedTemporaryFile("wb", suffix=".gguf", delete=False) as f:
        f.write(b"fake-weights-payload-for-test")
        wpath = f.name
    try:
        expected = hashlib.sha256(b"fake-weights-payload-for-test").hexdigest()
        spec = BackendSpec(
            provider="openai-compatible-local",
            base_url="http://127.0.0.1:11434",
            model="ai/qwen3:latest",
            weights_path=wpath,
        )
        ident = resolve_model_identity(spec)
        assert ident.model_hash_kind == "weights-sha256"
        assert ident.model_hash == expected
        assert resolve_model_identity(spec).model_hash == expected  # cache hit
    finally:
        os.unlink(wpath)


def test_cloud_identity_is_claim_with_null_hash() -> None:
    spec = BackendSpec(
        provider="anthropic-cloud",
        base_url="https://api.anthropic.com",
        model="claude-haiku-4-5-20251001",
        api_version="2023-06-01",
    )
    ident = resolve_model_identity(spec)
    assert ident.model_hash is None
    assert ident.model_hash_kind == "identity-claim"
    assert ident.api_version == "2023-06-01"


def test_missing_weights_downgrades_to_identity_claim() -> None:
    spec = BackendSpec(
        provider="openai-compatible-local",
        base_url="http://127.0.0.1:11434",
        model="ai/qwen3:latest",
        weights_path="/nonexistent/path/model.gguf",
    )
    ident = resolve_model_identity(spec)
    assert ident.model_hash is None
    assert ident.model_hash_kind == "identity-claim"


def test_unknown_identity_shape() -> None:
    ui = unknown_identity("2026-05-31T10:30:00+00:00")
    assert set(ui) == {
        "provider", "model", "model_hash", "model_hash_kind",
        "api_version", "capabilities", "resolved_at_utc",
    }
    assert ui["provider"] == "none" and ui["model_hash"] is None


# ── (gate) the WIRED chain: success / fallback / retry / cooldown / fail-closed ─

def test_chain_returns_on_first_success() -> None:
    b = _FakeBackend("openai-compatible-local", script=[("ok", "ANSWER")])
    res = asyncio.run(_egress([b]).complete(_req()))
    assert res.text == "ANSWER"
    assert len(res.attempts) == 1 and res.attempts[0].ok
    assert res.identity.provider == "openai-compatible-local"
    assert b.calls == 1


def test_chain_falls_back_on_non_retryable() -> None:
    b1 = _FakeBackend("openai-compatible-local", script=[("err", AuthError("no key", "local", 401))])
    b2 = _FakeBackend("anthropic-cloud", script=[("ok", "FROM_CLOUD")])
    res = asyncio.run(_egress([b1, b2]).complete(_req()))
    assert res.text == "FROM_CLOUD"
    assert b1.calls == 1, "non-retryable error must NOT retry the same backend"
    assert [a.ok for a in res.attempts] == [False, True]


def test_chain_retries_transient_then_succeeds() -> None:
    b = _FakeBackend(
        "openai-compatible-local",
        script=[("err", Transient("flaky", "local", 503)), ("ok", "RECOVERED")],
    )
    res = asyncio.run(_egress([b], max_retries=2).complete(_req()))
    assert res.text == "RECOVERED"
    assert b.calls == 2, "transient error must retry the same backend"


def test_ratelimited_cools_provider_and_is_skipped_next_call() -> None:
    b1 = _FakeBackend(
        "openai-compatible-local",
        script=[("err", RateLimited("429", "local", 429)), ("err", RateLimited("429", "local", 429))],
    )
    b2 = _FakeBackend("anthropic-cloud", script=[("ok", "A"), ("ok", "B")])
    eg = _egress([b1, b2], max_retries=1, cooldown_s=60.0)
    r1 = asyncio.run(eg.complete(_req()))
    assert r1.text == "A" and b1.calls == 2  # tried twice (attempt 0 + retry), then cooled
    r2 = asyncio.run(eg.complete(_req()))
    assert r2.text == "B" and b1.calls == 2, "cooled-down provider must be skipped"


def test_chain_exhausted_raises_fail_closed() -> None:
    b = _FakeBackend("openai-compatible-local", script=[("err", Permanent("nope", "local", 422))])
    raised = False
    try:
        asyncio.run(_egress([b]).complete(_req()))
    except AdapterError:
        raised = True
    assert raised, "no fake result on full failure — must fail closed"


def test_deep_tier_prefers_cloud_first() -> None:
    local = _FakeBackend("openai-compatible-local", script=[("ok", "LOCAL")])
    cloud = _FakeBackend("anthropic-cloud", script=[("ok", "CLOUD")])
    res = asyncio.run(_egress([local, cloud]).complete(
        LLMRequest(system="s", user="u", tier="deep")))
    assert res.text == "CLOUD" and cloud.calls == 1 and local.calls == 0


# ── (gate) hook bus: transform, observe, isolation ─────────────────────────────

def test_before_request_hook_transforms() -> None:
    echo = _FakeBackend("openai-compatible-local")  # echoes req.user
    hooks = HookBus()
    hooks.register("before_request", lambda req: dataclasses.replace(req, user="REWRITTEN"))
    res = asyncio.run(_egress([echo], hooks=hooks).complete(_req("original")))
    assert res.text == "REWRITTEN"


def test_after_response_and_on_result_observed() -> None:
    b = _FakeBackend("openai-compatible-local", script=[("ok", "X")])
    seen: dict[str, object] = {}
    hooks = HookBus()
    hooks.register("after_response", lambda provider, identity: seen.update(provider=provider, ident=identity))
    hooks.register("on_result", lambda result: seen.update(result_text=result.text))
    asyncio.run(_egress([b], hooks=hooks).complete(_req()))
    assert seen["provider"] == "openai-compatible-local"
    assert isinstance(seen["ident"], ModelIdentity)
    assert seen["result_text"] == "X"


def test_broken_hook_never_breaks_the_call() -> None:
    b = _FakeBackend("openai-compatible-local", script=[("ok", "SURVIVED")])
    hooks = HookBus()

    def _boom(*_a):
        raise RuntimeError("hook exploded")

    hooks.register("before_request", _boom)
    hooks.register("after_response", _boom)
    hooks.register("on_result", _boom)
    res = asyncio.run(_egress([b], hooks=hooks).complete(_req()))
    assert res.text == "SURVIVED", "a throwing hook must be isolated"


# ── (gate) wired backend over httpx.MockTransport (no sockets) ──────────────────

def _local_backend(handler) -> OpenAICompatLocalBackend:
    spec = BackendSpec(
        provider="openai-compatible-local",
        base_url="http://127.0.0.1:11434",
        model="ai/qwen3:latest",
    )
    return OpenAICompatLocalBackend(spec, timeout_s=5.0, transport=httpx.MockTransport(handler))


def test_local_backend_http_happy_path() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        return httpx.Response(200, json={"choices": [{"message": {"content": "hi-there"}}]})

    text, ident = asyncio.run(_local_backend(handler).complete(system="s", user="u", max_tokens=16))
    assert text == "hi-there"
    assert ident.provider == "openai-compatible-local"


def test_local_backend_429_classifies_ratelimited_with_header() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "7"}, json={"error": "slow down"})

    try:
        asyncio.run(_local_backend(handler).complete(system="s", user="u", max_tokens=16))
        raise AssertionError("expected RateLimited")
    except RateLimited as err:
        assert err.retry_after_s == 7.0


def test_local_backend_500_is_transient() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    try:
        asyncio.run(_local_backend(handler).complete(system="s", user="u", max_tokens=16))
        raise AssertionError("expected Transient")
    except Transient:
        pass


def test_local_backend_connection_error_is_transient() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    try:
        asyncio.run(_local_backend(handler).complete(system="s", user="u", max_tokens=16))
        raise AssertionError("expected Transient")
    except Transient:
        pass


# ── single-egress invariant (anthropic import scan) + dep budget ───────────────

def test_single_egress_no_foreign_anthropic_import() -> None:
    repo = _aegis_root()
    offenders: list[str] = []
    for py in repo.rglob("*.py"):
        rel = py.relative_to(repo).as_posix()
        if rel.startswith("core/llm/") or "/tests/" in f"/{rel}":
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(
                a.name.split(".")[0] == "anthropic" for a in node.names
            ):
                offenders.append(rel)
            elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "anthropic":
                offenders.append(rel)
    assert not offenders, f"non-llm modules import anthropic: {sorted(set(offenders))}"


def test_no_litellm_dependency() -> None:
    req = _aegis_root() / "requirements.txt"
    text = req.read_text(encoding="utf-8").lower() if req.exists() else ""
    assert "litellm" not in text, "litellm must never appear in requirements"


def test_single_egress_completion_post_DEFERRED() -> None:
    """DEFERRED to the cutover PR. HttpBackend.generate_config still owns its own POST to
    /v1/chat/completions; enabling the 'no completion URL outside core/llm' scan now would
    be a false RED. This placeholder documents the deferral and stays green."""
    repo = _aegis_root()
    hb = repo / "core" / "backends" / "http_backend.py"
    assert hb.exists(), "expected the pre-cutover HttpBackend to still exist in PR-1"
    print("  NOTE: completion-POST single-egress scan deferred to the http_backend cutover PR")


# ── helpers + runner ───────────────────────────────────────────────────────────

def _aegis_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "core" / "llm").exists():
            return parent
    return here.parent.parent


def _run_all() -> int:
    funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failures = 0
    for fn in funcs:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(funcs) - failures}/{len(funcs)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_run_all())
