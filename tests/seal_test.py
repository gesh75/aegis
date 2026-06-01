"""aegis/tests/seal_test.py — CROSS-3 bounded-autonomy SEAL: detached receipt, offline
verify, gates G0..G6.

House style: pytest-discoverable test_* + a dep-light __main__ runner
(CI: python3 -m aegis.tests.seal_test). Uses real Ed25519 (cryptography). The schema test
self-skips if jsonschema is absent.
"""
from __future__ import annotations

import base64
import json
import random
import sys
from pathlib import Path

from aegis.core.backends.simulator import SimulatorBackend
from aegis.core.orchestrator.pipeline import run_preflight
from aegis.core.seal import (
    Ed25519Signer,
    Ed25519Verifier,
    SealError,
    build_claims,
    canonical_claims_bytes,
    seal_bundle,
    verify_seal,
)
from aegis.evidence.bundler import compute_sha256

try:
    import jsonschema
    _HAVE = True
except Exception:  # noqa: BLE001
    _HAVE = False

_AT = "2026-06-01T12:00:00+00:00"


def _root() -> Path:
    here = Path(__file__).resolve()
    for p in here.parents:
        if (p / "core" / "seal").exists():
            return p
    return here.parent.parent


def _seal_schema() -> dict:
    return json.loads((_root() / "core" / "seal" / "schema" / "seal.schema.json").read_text("utf-8"))


def _reseal(b: dict) -> dict:
    b["integrity"]["sha256"] = ""
    b["integrity"]["sha256"] = compute_sha256(b)
    return b


def _bounded_bundle(required: str = "hitl", max_auth: str = "hotl") -> dict:
    b = run_preflight("add vlan 10 to leaf-1", backend=SimulatorBackend(), lab="clos-evpn")
    b["change"]["authority"] = {
        "severity": "low", "required": required, "max_authorized": max_auth,
        "allowed": True, "effective": required,
        "change_class": {"touches_asn": False, "touches_rd_rt": False,
                         "touches_spine": False, "touches_underlay": False},
    }
    return _reseal(b)


def _unbounded_bundle() -> dict:
    b = _bounded_bundle()
    b["change"]["authority"].update(required="block", effective="block", allowed=False)
    return _reseal(b)


def _signed_seal(bundle: dict, signer: Ed25519Signer, claims: dict) -> dict:
    return {
        "seal_version": "1.0", "claims": claims,
        "signature": {"alg": signer.alg(), "key_id": signer.key_id(),
                      "value": base64.b64encode(signer.sign(canonical_claims_bytes(claims))).decode("ascii")},
    }


# ── claims binding ───────────────────────────────────────────────────────────────

def test_build_claims_binds_model_authority_and_hash() -> None:
    b = _bounded_bundle()
    c = build_claims(b, _AT)
    assert c["bundle_sha256"] == b["integrity"]["sha256"]
    assert c["model"]["provider"] == b["change"]["model_identity"]["provider"]
    assert c["authority"]["required"] == "hitl"


# ── round-trip + offline verify ──────────────────────────────────────────────────

def test_seal_then_verify_is_valid() -> None:
    b = _bounded_bundle()
    s = Ed25519Signer.generate()
    seal = seal_bundle(b, s, sealed_at_utc=_AT)
    v = verify_seal(b, seal, s.verifier())
    assert v.valid and v.gate == "OK", v.reason


def test_offline_verify_with_public_key_only() -> None:
    b = _bounded_bundle()
    s = Ed25519Signer.generate()
    seal = seal_bundle(b, s, sealed_at_utc=_AT)
    pub_only = Ed25519Verifier.from_public_bytes(s.public_key_bytes())  # no secret
    assert verify_seal(b, seal, pub_only).valid


# ── G1/G2 — wrong key, forged signature ──────────────────────────────────────────

def test_wrong_key_rejected() -> None:
    b = _bounded_bundle()
    s = Ed25519Signer.generate()
    other = Ed25519Signer.generate()
    seal = seal_bundle(b, s, sealed_at_utc=_AT)
    v = verify_seal(b, seal, other.verifier())   # not the pinned key
    assert not v.valid and v.gate in ("G1", "G2")


def test_forged_signature_rejected_g2() -> None:
    b = _bounded_bundle()
    s = Ed25519Signer.generate()
    seal = seal_bundle(b, s, sealed_at_utc=_AT)
    seal["signature"]["value"] = "AAAA" + seal["signature"]["value"][4:]  # corrupt the sig
    v = verify_seal(b, seal, s.verifier())
    assert not v.valid and v.gate == "G2"


# ── G3/G6 — bundle binding + integrity ───────────────────────────────────────────

def test_tampered_bundle_reseal_breaks_g3() -> None:
    b = _bounded_bundle()
    s = Ed25519Signer.generate()
    seal = seal_bundle(b, s, sealed_at_utc=_AT)
    b["change"]["generated_configs"][0]["config"] += "\n# injected"
    _reseal(b)  # new integrity hash != the seal's claimed bundle_sha256
    v = verify_seal(b, seal, s.verifier())
    assert not v.valid and v.gate == "G3"


def test_tampered_bundle_no_reseal_breaks_g6() -> None:
    b = _bounded_bundle()
    s = Ed25519Signer.generate()
    seal = seal_bundle(b, s, sealed_at_utc=_AT)
    b["change"]["generated_configs"][0]["config"] += "\n# injected"  # no re-seal
    v = verify_seal(b, seal, s.verifier())
    assert not v.valid and v.gate in ("G3", "G6")


# ── G4 — model swap (re-signed with the right key to get past G2) ─────────────────

def test_swapped_model_in_claims_rejected_g4() -> None:
    b = _bounded_bundle()
    s = Ed25519Signer.generate()
    claims = build_claims(b, _AT)
    claims["model"]["model"] = "evil/other-model"
    seal = _signed_seal(b, s, claims)
    v = verify_seal(b, seal, s.verifier())
    assert not v.valid and v.gate == "G4"


# ── G5 — no self-escalation: never seal / never accept an unbounded change ────────

def test_refuse_to_seal_unbounded() -> None:
    b = _unbounded_bundle()
    s = Ed25519Signer.generate()
    try:
        seal_bundle(b, s, sealed_at_utc=_AT)
        raise AssertionError("must refuse to seal an unbounded change")
    except SealError:
        pass


def test_verify_rejects_unbounded_seal_g5() -> None:
    b = _unbounded_bundle()
    s = Ed25519Signer.generate()
    seal = _signed_seal(b, s, build_claims(b, _AT))  # bypass seal_bundle's refusal
    v = verify_seal(b, seal, s.verifier())
    assert not v.valid and v.gate == "G5"


# ── 0-violation property: every valid seal certifies a bounded change ─────────────

def test_every_valid_seal_is_bounded_property() -> None:
    s = Ed25519Signer.generate()
    ver = s.verifier()
    rng = random.Random(11)
    sealed = 0
    for _ in range(120):
        b = _bounded_bundle(required=rng.choice(["auto", "hitl", "hotl"]), max_auth="hotl")
        seal = seal_bundle(b, s, sealed_at_utc=_AT)
        v = verify_seal(b, seal, ver)
        assert v.valid, v.reason
        a = seal["claims"]["authority"]
        assert a["allowed"] and a["effective"] != "block"
        sealed += 1
    assert sealed == 120


# ── schema ────────────────────────────────────────────────────────────────────────

def test_seal_matches_schema() -> None:
    if not _HAVE:
        print("  SKIP test_seal_matches_schema (jsonschema absent)")
        return
    b = _bounded_bundle()
    s = Ed25519Signer.generate()
    jsonschema.validate(seal_bundle(b, s, sealed_at_utc=_AT), _seal_schema())


# ── runner ───────────────────────────────────────────────────────────────────────

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
