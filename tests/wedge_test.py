"""aegis/tests/wedge_test.py — #4 model-identity wedge: seal WHICH model made the change.

House style: pytest-discoverable test_* + a dep-light __main__ runner
(CI: python3 -m aegis.tests.wedge_test). Tests run against the REAL bundle produced by
run_preflight + the REAL evidence_bundle schema. jsonschema-based asserts self-skip if
jsonschema is absent; the seal/verify/round-trip asserts always run.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from aegis.core.backends.simulator import SimulatorBackend
from aegis.core.llm import (
    AdapterConfig,
    BackendSpec,
    HookBus,
    IdentitySink,
    LLMEgress,
    LLMRequest,
    ModelIdentity,
    resolve_model_identity,
)
from aegis.core.orchestrator.pipeline import run_preflight
from aegis.evidence.bundler import verify

try:
    import jsonschema
    _HAVE_JSONSCHEMA = True
except Exception:  # noqa: BLE001
    _HAVE_JSONSCHEMA = False

_INTENT = "add vlan 10 to leaf-1"


def _schema() -> dict:
    return json.loads((_aegis_root() / "evidence" / "schema" / "evidence_bundle.schema.json").read_text("utf-8"))


def _validate(bundle: dict) -> None:
    if _HAVE_JSONSCHEMA:
        jsonschema.validate(bundle, _schema())


def _bundle(**kw) -> dict:
    return run_preflight(_INTENT, backend=SimulatorBackend(), lab="clos-evpn", **kw)


def _local_identity_dict() -> dict:
    return {
        "provider": "openai-compatible-local",
        "model": "ai/qwen3:latest",
        "model_hash": "a" * 64,
        "model_hash_kind": "weights-sha256",
        "api_version": None,
        "capabilities": ["chat", "json"],
        "resolved_at_utc": "2026-06-01T10:30:00+00:00",
    }


# ── real pipeline bundles now carry + seal model_identity at v1.1 ────────────────

def test_nl_intent_seals_simulator_identity_v11() -> None:
    b = _bundle()
    assert b["bundle_version"] == "1.1"
    mi = b["change"]["model_identity"]
    assert mi["provider"] == "simulator" and mi["model"] == "deterministic-sim-v1"
    assert verify(b)
    _validate(b)


def test_config_import_seals_unknown_identity() -> None:
    b = run_preflight("", backend=SimulatorBackend(), lab="single", source="config_import",
                      imported_configs=[{"device": "r1", "vendor": "frr", "config": "router bgp 65000"}])
    mi = b["change"]["model_identity"]
    assert mi["provider"] == "none" and mi["model"] == "operator-supplied"
    assert mi["model_hash"] is None and mi["model_hash_kind"] == "identity-claim"
    assert verify(b)
    _validate(b)


def test_explicit_model_identity_passthrough() -> None:
    b = _bundle(model_identity=_local_identity_dict())
    mi = b["change"]["model_identity"]
    assert mi["provider"] == "openai-compatible-local"
    assert mi["model_hash"] == "a" * 64 and mi["model_hash_kind"] == "weights-sha256"
    assert verify(b)
    _validate(b)


def test_model_identity_is_under_the_seal_tamper_detected() -> None:
    b = _bundle(model_identity=_local_identity_dict())
    assert verify(b)
    b["change"]["model_identity"]["model"] = "evil-swapped-model"
    assert not verify(b), "swapping the attested model must break the integrity seal"


def test_cloud_identity_claim_is_never_a_faked_weight_hash() -> None:
    spec = BackendSpec(provider="anthropic-cloud", base_url="https://api.anthropic.com",
                       model="claude-haiku-4-5-20251001", api_version="2023-06-01")
    mi = resolve_model_identity(spec).to_bundle_dict()
    assert mi["model_hash"] is None and mi["model_hash_kind"] == "identity-claim"
    b = _bundle(model_identity=mi)
    assert b["change"]["model_identity"]["provider"] == "anthropic-cloud"
    assert verify(b)
    _validate(b)


# ── schema: v1.1 requires model_identity; bundle_version pinned to 1.1 ───────────

def test_v11_requires_model_identity() -> None:
    if not _HAVE_JSONSCHEMA:
        print("  SKIP test_v11_requires_model_identity (jsonschema absent)")
        return
    b = _bundle()
    del b["change"]["model_identity"]
    try:
        jsonschema.validate(b, _schema())
        raise AssertionError("a v1.1 bundle without model_identity must fail validation")
    except jsonschema.ValidationError:
        pass


def test_schema_pins_bundle_version_to_11() -> None:
    if not _HAVE_JSONSCHEMA:
        print("  SKIP test_schema_pins_bundle_version_to_11 (jsonschema absent)")
        return
    b = _bundle()
    b["bundle_version"] = "1.0"
    try:
        jsonschema.validate(b, _schema())
        raise AssertionError("schema must pin bundle_version to 1.1")
    except jsonschema.ValidationError:
        pass


# ── the WEDGE round-trip: egress after_response -> IdentitySink -> sealed bundle ─

class _FakeGenBackend:
    """A generating backend whose model the egress attests; the sink hands it to the seal."""

    provider = "openai-compatible-local"

    def identity(self) -> ModelIdentity:
        return ModelIdentity(
            provider=self.provider, model="ai/qwen3:latest", model_hash="b" * 64,
            model_hash_kind="weights-sha256", api_version=None,
            capabilities=("chat",), resolved_at_utc="2026-06-01T10:30:00+00:00",
        )

    async def complete(self, *, system, user, max_tokens, temperature=0.1):
        return "router bgp 65000", self.identity()


def test_egress_after_response_sink_into_sealed_bundle() -> None:
    import asyncio

    sink = IdentitySink()
    hooks = HookBus()
    hooks.register("after_response", sink.capture)
    cfg = AdapterConfig(chain=(), airgap=False, cloud_available=False,
                        max_retries=0, base_backoff_s=0.0)
    egress = LLMEgress(cfg, (_FakeGenBackend(),), hooks)
    asyncio.run(egress.complete(LLMRequest(system="s", user=_INTENT, max_tokens=64)))

    assert sink.last is not None and sink.last.model == "ai/qwen3:latest"
    b = _bundle(model_identity=sink.as_bundle_dict())
    mi = b["change"]["model_identity"]
    assert mi["model"] == "ai/qwen3:latest" and mi["model_hash_kind"] == "weights-sha256"
    assert verify(b)
    _validate(b)


class _NoAttestBackend:
    """A generating backend (nl_intent) that does NOT attest a model identity --
    e.g. the live HttpBackend before the generate-path cutover."""
    def __init__(self) -> None:
        self._inner = SimulatorBackend()
    def generate_config(self, intent, lab):
        return self._inner.generate_config(intent, lab)
    def batfish_check(self, configs):
        return self._inner.batfish_check(configs)
    def spawn_twin(self, lab):
        return self._inner.spawn_twin(lab)
    def apply_and_converge(self, twin_id, configs):
        return self._inner.apply_and_converge(twin_id, configs)
    def state_diff(self, twin_id):
        return self._inner.state_diff(twin_id)
    def teardown_twin(self, twin_id):
        return self._inner.teardown_twin(twin_id)


def test_nl_intent_without_attestation_is_unattested_not_operator() -> None:
    b = run_preflight(_INTENT, backend=_NoAttestBackend(), lab="clos-evpn")
    mi = b["change"]["model_identity"]
    assert mi["provider"] == "unknown" and mi["model"] == "unattested"
    # MUST NOT be confused with a config_import operator-supplied identity:
    assert (mi["provider"], mi["model"]) != ("none", "operator-supplied")
    assert verify(b)
    _validate(b)


def test_empty_sink_yields_none() -> None:
    assert IdentitySink().as_bundle_dict() is None


# ── helpers + runner ────────────────────────────────────────────────────────────

def _aegis_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "evidence" / "schema").exists():
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
