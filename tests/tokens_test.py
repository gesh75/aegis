"""HMAC approval-token contract (Improvement plan T1 #9).

Run: python3 -m aegis.tests.tokens_test
"""
from __future__ import annotations

import os
import sys
import time

from ..core.promote.tokens import (
    TokenError, mint_token, verify_approval, load_approve_key,
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
