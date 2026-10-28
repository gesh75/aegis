"""HMAC approval-token contract (Improvement plan T1 #9).

Run: python3 -m aegis.tests.tokens_test
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time

from ..core.promote.tokens import (
    TokenError, mint_token, mint_token_for_bundle, verify_approval,
    load_approve_key, config_digest, inventory_digest, digests_from_bundle,
)

FAILS: list[str] = []
CHECKS = 0
KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
BUNDLE = "ab" * 32


def check(name: str, cond: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(f"{name}: {detail}")


def _with_key(fn):
    prev = os.environ.get("AEGIS_APPROVE_KEY")
    os.environ["AEGIS_APPROVE_KEY"] = KEY
    try:
        return fn()
    finally:
        if prev is None:
            os.environ.pop("AEGIS_APPROVE_KEY", None)
        else:
            os.environ["AEGIS_APPROVE_KEY"] = prev


def main() -> int:
    os.environ.pop("AEGIS_APPROVE_KEY", None)

    # 1 — unset key: mint refuses
    try:
        mint_token("noc-lead", BUNDLE)
        check("mint.unset.raises", False, "mint succeeded without a key")
    except TokenError as e:
        check("mint.unset.raises", "unset" in str(e).lower(), str(e))

    # 2 — unset key: no free-text pair is an approval (iPvAwZKJ: fail closed, say how to fix it)
    a = verify_approval("noc-lead", "tok-123", BUNDLE)
    check("assert.denied", not a.ok, a.reason)
    check("assert.method", a.method == "none", a.method)
    check("assert.reason_names_key", "AEGIS_APPROVE_KEY" in a.reason and "HMAC" in a.reason,
          a.reason)
    check("assert.hash", isinstance(a.token_sha256, str) and len(a.token_sha256) == 64, str(a.token_sha256))
    # ... even a structurally perfect token from another process (key unknown here)
    foreign = _with_key(lambda: mint_token("noc-lead", BUNDLE, ttl_sec=600))
    f = verify_approval("noc-lead", foreign, BUNDLE)
    check("assert.foreign_token_denied", not f.ok and f.method == "none", f.reason)

    # 3 — empty denies
    empty = verify_approval("", "", BUNDLE)
    check("empty.deny", not empty.ok and empty.method == "none", empty.reason)

    def _hmac_suite():
        tok = mint_token("noc-lead", BUNDLE, ttl_sec=600)
        check("mint.shape", tok.startswith("aegis1.") and tok.count(".") == 2, tok[:40])
        good = verify_approval("noc-lead", tok, BUNDLE)
        check("hmac.ok", good.ok, good.reason)
        check("hmac.method", good.method == "hmac-sha256", good.method)

        wrong_who = verify_approval("other", tok, BUNDLE)
        check("hmac.wrong_approver", not wrong_who.ok, wrong_who.reason)

        other = "cd" * 32
        wrong_b = verify_approval("noc-lead", tok, other)
        check("hmac.wrong_bundle", not wrong_b.ok, wrong_b.reason)

        junk = verify_approval("noc-lead", "tok-123", BUNDLE)
        check("hmac.random_string", not junk.ok, junk.reason)

        parts = tok.split(".")
        tampered = parts[0] + "." + parts[1] + "." + ("A" * len(parts[2]))
        bad_mac = verify_approval("noc-lead", tampered, BUNDLE)
        check("hmac.tampered_mac", not bad_mac.ok, bad_mac.reason)

        expired = mint_token("noc-lead", BUNDLE, ttl_sec=60, now=int(time.time()) - 120)
        stale = verify_approval("noc-lead", expired, BUNDLE)
        check("hmac.expired", not stale.ok, stale.reason)

        try:
            mint_token("has space", BUNDLE)
            check("mint.bad_approver", False, "accepted whitespace approver")
        except TokenError:
            check("mint.bad_approver", True)

        try:
            mint_token("noc-lead", "not-a-hash")
            check("mint.bad_hash", False, "accepted non-hex bundle hash")
        except TokenError:
            check("mint.bad_hash", True)

        k = load_approve_key()
        check("key.loaded", isinstance(k, bytes) and len(k) >= 16, str(type(k)))

        sample = {
            "integrity": {"sha256": BUNDLE},
            "change": {"generated_configs": [
                {"device": "leaf-1", "vendor": "frr", "config": "vlan 10\n"},
            ]},
            "twin": {"topology": "clos-evpn", "engine": "containerlab",
                     "node_count": 2, "inventory_rev": "N"},
        }
        digest, cfg, inv = digests_from_bundle(sample)
        check("digest.bundle", digest == BUNDLE, digest)
        check("digest.cfg", len(cfg) == 64 and cfg == config_digest(sample), cfg)
        check("digest.inv", len(inv) == 64 and inv == inventory_digest(sample), inv)

        v2 = mint_token_for_bundle("noc-lead", sample, ttl_sec=600)
        check("v2.shape", v2.startswith("aegis1.") and v2.count(".") == 2, v2[:40])
        raw = v2.split(".")[1]
        pad = "=" * (-len(raw) % 4)
        payload = json.loads(base64.urlsafe_b64decode(raw + pad))
        check("v2.payload.v", payload.get("v") == 2, str(payload.get("v")))
        check("v2.payload.c", payload.get("c") == cfg, str(payload.get("c")))
        check("v2.payload.inv", payload.get("inv") == inv, str(payload.get("inv")))

        good_v2 = verify_approval("noc-lead", v2, digest,
                                  config_sha256=cfg, inventory_sha256=inv)
        check("v2.ok", good_v2.ok, good_v2.reason)
        check("v2.method", good_v2.method == "hmac-sha256", good_v2.method)
        check("v2.reason", "inventory" in good_v2.reason, good_v2.reason)

        other_cfg = hashlib.sha256(b"other-config").hexdigest()
        wrong_cfg = verify_approval("noc-lead", v2, digest,
                                    config_sha256=other_cfg, inventory_sha256=inv)
        check("v2.wrong_config", not wrong_cfg.ok
              and "config hash" in wrong_cfg.reason, wrong_cfg.reason)

        other_inv = hashlib.sha256(b"inventory-N+1").hexdigest()
        wrong_inv = verify_approval("noc-lead", v2, digest,
                                    config_sha256=cfg, inventory_sha256=other_inv)
        check("v2.wrong_inventory", not wrong_inv.ok
              and "inventory" in wrong_inv.reason, wrong_inv.reason)

        missing = verify_approval("noc-lead", v2, digest)
        check("v2.missing_live_hashes", not missing.ok
              and "requires config and inventory" in missing.reason, missing.reason)

        try:
            mint_token("noc-lead", BUNDLE, version=2)
            check("v2.mint.missing_claims", False, "accepted v2 without hashes")
        except TokenError as e:
            check("v2.mint.missing_claims", "require" in str(e).lower(), str(e))

        v1 = mint_token("noc-lead", BUNDLE, ttl_sec=600)
        still_v1 = verify_approval("noc-lead", v1, BUNDLE,
                                   config_sha256=cfg, inventory_sha256=inv)
        check("v1.ignores_extra_hashes", still_v1.ok, still_v1.reason)

        def _b64(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

        raw_v3 = json.dumps({
            "a": "noc-lead", "b": BUNDLE, "exp": int(time.time()) + 600,
            "n": "00" * 8, "v": 3,
        }, sort_keys=True, separators=(",", ":")).encode("ascii")
        mac = hmac.new(k, raw_v3, hashlib.sha256).digest()
        unknown = f"aegis1.{_b64(raw_v3)}.{_b64(mac)}"
        bad_ver = verify_approval("noc-lead", unknown, BUNDLE)
        check("hmac.unknown_version", not bad_ver.ok
              and "version" in bad_ver.reason, bad_ver.reason)

        # Ujf5v6Mr — one payload+MAC has exactly ONE accepted wire string. The replay id is
        # sha256(wire string), so any alternative encoding that still verified would be a
        # fresh single-use token. Padding, junk, whitespace, the standard alphabet and
        # unused trailing bits are all denies; leading/trailing whitespace is stripped to
        # the same string (same hash).
        def _b64_alphabet() -> str:
            return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

        def _flip_unused_bits(part: str) -> str | None:
            """Same decoded bytes, different last char (only when the length leaves unused bits)."""
            unused = {2: 4, 3: 2}.get(len(part) % 4)
            if unused is None:
                return None
            alpha = _b64_alphabet()
            idx = alpha.index(part[-1])
            alt = idx ^ 1 if unused >= 1 else idx
            return part[:-1] + alpha[alt]

        canon = mint_token("noc-lead", BUNDLE, ttl_sec=600)
        for _ in range(200):  # find a token with '-' or '_' so the std-alphabet variant differs
            if "-" in canon or "_" in canon:
                break
            canon = mint_token("noc-lead", BUNDLE, ttl_sec=600)
        c_hash = verify_approval("noc-lead", canon, BUNDLE).token_sha256
        pre, pay, mac_part = canon.split(".")
        variants = {
            "pad1": canon + "=",
            "pad2": canon + "==",
            "pad_payload": f"{pre}.{pay}=.{mac_part}",
            "junk4": canon + "!!!!",
            "junk_inner": f"{pre}.{pay}.{mac_part[:10]}!!!!{mac_part[10:]}",
            "space_inner": f"{pre}.{pay}.{mac_part[:10]}    {mac_part[10:]}",
            "newline_inner": f"{pre}.{pay[:8]}\n\n\n\n{pay[8:]}.{mac_part}",
            "std_alphabet": f"{pre}.{pay.replace('-', '+').replace('_', '/')}."
                            f"{mac_part.replace('-', '+').replace('_', '/')}",
            "mac_trailing_bits": f"{pre}.{pay}.{_flip_unused_bits(mac_part)}",
            "payload_trailing_bits": f"{pre}.{_flip_unused_bits(pay)}.{mac_part}",
        }
        check("canon.verifies", verify_approval("noc-lead", canon, BUNDLE).ok)
        check("canon.has_urlsafe_char", "-" in canon or "_" in canon,
              "no '-'/'_' in 200 tokens (std-alphabet variant would equal canonical)")
        for vname, vtok in variants.items():
            if vtok == canon:
                continue
            res = verify_approval("noc-lead", vtok, BUNDLE)
            check(f"malleable.{vname}.denied", not res.ok, f"re-encoding accepted: {res.reason}")
        check("malleable.mac_bits_variant_built", _flip_unused_bits(mac_part) not in (None, mac_part))
        for vname in ("leading_ws", "trailing_ws"):
            ws = (" \t" + canon) if vname == "leading_ws" else (canon + "\n ")
            res = verify_approval("noc-lead", ws, BUNDLE)
            check(f"malleable.{vname}.same_hash", res.ok and res.token_sha256 == c_hash,
                  f"{res.ok} {res.token_sha256} vs {c_hash}")
        check("malleable.hash_is_wire_string",
              c_hash == hashlib.sha256(canon.encode("utf-8")).hexdigest(), str(c_hash))
        # v2 tokens take the same decoder
        v2c = mint_token_for_bundle("noc-lead", sample, ttl_sec=600)
        check("malleable.v2.pad_denied", not verify_approval(
            "noc-lead", v2c + "=", digest, config_sha256=cfg, inventory_sha256=inv).ok)

        moved = dict(sample)
        moved["twin"] = dict(sample["twin"], inventory_rev="N+1")
        drift = inventory_digest(moved)
        check("inv.drift_changes_digest", drift != inv, drift)
        # W17qDJe8: promotion re-derives the digest from the source of truth's CURRENT rev
        check("inv.live_rev_same_as_sealed", inventory_digest(sample, inventory_rev="N") == inv)
        check("inv.live_rev_override_equals_moved", inventory_digest(sample, inventory_rev="N+1") == drift)
        check("inv.live_empty_rev_is_not_a_fallback",
              inventory_digest(sample, inventory_rev="") != inv)

    _with_key(_hmac_suite)

    # 4 — after popping the key we are back in deny-everything mode
    a2 = verify_approval("noc-lead", "tok-123", BUNDLE)
    check("assert.restored", not a2.ok and a2.method == "none", a2.method)

    if FAILS:
        print("\n=== APPROVAL TOKEN TEST: FAIL ===")
        for f in FAILS:
            print("  -", f)
        return 1
    print(f"\n=== APPROVAL TOKEN TEST: PASS ({CHECKS} checks) ===")
    return 0


def test_tokens():
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())
