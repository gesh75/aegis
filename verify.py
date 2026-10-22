"""Offline auditor verifier — no server, no network, no secret.

An examiner receives a bundle (with its detached seal) and the deployment's PUBLIC key,
then runs:

    python -m aegis.verify --bundle run.json --pubkey pubkey.json
    python -m aegis.verify --bundle run.json --seal seal.json --pubkey <base64|hex>
    python -m aegis.verify --ledger /var/lib/aegis/ledger.jsonl

``--pubkey`` accepts the JSON from ``GET /api/seal/pubkey``, a file holding base64/hex,
or the base64/hex string itself. Pin it out-of-band (key ceremony record), never from the
same channel as the bundle.

Exit codes: 0 = every requested check passed · 1 = a check failed · 2 = usage / IO error.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys

from .core.seal import Ed25519Verifier, verify_seal
from .evidence.bundler import verify as verify_integrity
from .evidence.ledger import verify_chain


def _load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _load_pubkey(arg: str) -> Ed25519Verifier:
    raw = arg
    if os.path.exists(arg):
        raw = open(arg, encoding="utf-8").read().strip()
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            raw = obj.get("public_key_b64") or ""
    except ValueError:
        pass
    raw = raw.strip()
    if len(raw) == 64 and all(c in "0123456789abcdefABCDEF" for c in raw):
        key = bytes.fromhex(raw)
    else:
        key = base64.b64decode(raw, validate=True)
    if len(key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return Ed25519Verifier.from_public_bytes(key)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.verify", description=__doc__.split("\n")[0])
    ap.add_argument("--bundle", help="evidence bundle JSON (may embed the seal under 'seal')")
    ap.add_argument("--seal", help="detached seal JSON (default: bundle['seal'])")
    ap.add_argument("--pubkey", help="pinned Ed25519 public key (JSON/base64/hex or file)")
    ap.add_argument("--ledger", help="hash-chained ledger JSONL to re-walk")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)
    if not args.bundle and not args.ledger:
        ap.print_usage(sys.stderr)
        return 2

    report: dict = {}
    ok = True
    try:
        if args.bundle:
            bundle = _load_json(args.bundle)
            integ = verify_integrity(bundle)
            report["integrity"] = {"valid": integ, "sha256": bundle["integrity"]["sha256"],
                                   "meaning": "self-consistency only (anyone can recompute)"}
            ok = ok and integ
            seal = _load_json(args.seal) if args.seal else bundle.get("seal")
            if args.pubkey:
                if not isinstance(seal, dict):
                    report["seal"] = {"valid": False, "gate": "G0", "reason": "no seal present"}
                    ok = False
                else:
                    v = verify_seal(bundle, seal, _load_pubkey(args.pubkey))
                    report["seal"] = {"valid": v.valid, "gate": v.gate, "reason": v.reason}
                    ok = ok and v.valid
            else:
                report["seal"] = {"valid": None, "reason": "no --pubkey: authenticity NOT checked"}
            ch = bundle.get("change") or {}
            report["summary"] = {
                "run_id": bundle.get("run_id"), "operator": bundle.get("operator"),
                "change_ref": ch.get("change_ref"),
                "decision": (bundle.get("verdict") or {}).get("decision"),
                "risk_tier": ch.get("risk_tier"),
                "authority": (ch.get("authority") or {}).get("effective"),
                "model": (ch.get("model_identity") or {}).get("model"),
                "rollback_verification": (bundle.get("rollback") or {}).get("verification",
                                                                             "unspecified (<1.3)"),
            }
        if args.ledger:
            lok, n, why = verify_chain(args.ledger)
            report["ledger"] = {"valid": lok, "entries_checked": n, "reason": why}
            ok = ok and lok
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"ok": ok, **report}, indent=2))
    else:
        for section, body in report.items():
            print(f"[{section}]")
            for k, v in body.items():
                print(f"  {k:22} {v}")
        print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
