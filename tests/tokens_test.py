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

    # 2 — unset key: any non-empty pair is asserted-unverified
    a = verify_approval("noc-lead", "tok-123", BUNDLE)
    check("assert.ok", a.ok, a.reason)
    check("assert.method", a.method == "asserted-unverified", a.method)
    check("assert.hash", isinstance(a.token_sha256, str) and len(a.token_sha256) == 64, str(a.token_sha256))

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

        moved = dict(sample)
        moved["twin"] = dict(sample["twin"], inventory_rev="N+1")
        drift = inventory_digest(moved)
        check("inv.drift_changes_digest", drift != inv, drift)

    _with_key(_hmac_suite)

    # 4 — after popping the key we are back in asserted mode
    a2 = verify_approval("noc-lead", "tok-123", BUNDLE)
    check("assert.restored", a2.ok and a2.method == "asserted-unverified", a2.method)

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
