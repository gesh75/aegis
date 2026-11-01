"""Post-change verification: did what was approved actually land, and do the intents hold?

Input: the SEALED bundle and each device's running config, collected after the push.

  1. Applied check, per device. Every effective line of the sealed candidate must be present
     in the running config, and every removal must be absent:
       * Junos  ``set X``    → ``set X`` present (hierarchical running config is flattened)
                ``delete X`` → no running line starts with ``set X``
       * others  a line     → present after whitespace normalization
                ``no X``    → ``X`` absent
     This checks line presence, not position: it proves the change landed, not that the
     device's running config equals a golden config.
  2. Intent re-check (optional). The given intents are evaluated against the running
     configs as full device files (no merge), so the "after" is what is really running.

status: ``verified`` (all lines applied, intents pass) | ``partial`` (all lines landed,
but some referenced key VALUES could not be verified, e.g. Junos re-encrypts to $9$) |
``drift`` (lines missing, present that must be gone, or a key value that differs) |
``failed`` (an intent fails or cannot be evaluated) | ``unverifiable`` (nothing
checkable). It is never "verified" by default.

D3 references: a referenced key is compared with its resolved value when that is
trustworthy (clear text, or Cisco type 7 which is reversible); a Junos $9$ or a hashed
running value is reported as unverifiable, never as verified.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from ..evidence import junos
from .secretref import REF_RE, SecretStoreError, resolve_text

_SKIP = re.compile(r"^(?:!|#|end$|exit$|exit-address-family$|configure(?: terminal)?$|"
                   r"conf t$|commit(?: .*)?$|top$|quit$)", re.IGNORECASE)
_MAX_LIST = 20


def _norm(line: str) -> str:
    return " ".join(line.strip().split())


def _effective(text: str) -> list[str]:
    return [n for n in (_norm(ln) for ln in (text or "").splitlines()) if n and not _SKIP.match(n)]


_XLAT7 = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"
_TYPE_BEFORE = re.compile(r"(?:^|\s)[0-9]\s+$")
_SLOT = r'(?:(?P<t{i}>[0-9])\s+)?(?:"(?P<q{i}>[^"]*)"|(?P<u{i}>[^\s";]+))'


def cisco7_decode(value: str) -> str:
    """Cisco type 7 is reversible obfuscation (a fixed XOR table), so a running-config
    value can be compared with the intended key without any device help."""
    if len(value) < 4 or len(value) % 2 or not value[:2].isdigit():
        raise ValueError("not a type 7 string")
    seed = int(value[:2])
    return "".join(chr(int(value[i:i + 2], 16) ^ ord(_XLAT7[(seed + (i - 2) // 2) % len(_XLAT7)]))
                   for i in range(2, len(value), 2))


def _pattern(ln: str) -> re.Pattern:
    """Literal line with each reference replaced by a value slot. A Cisco type digit
    right before the slot ("password 0 <ref>") is folded into the slot, because the
    device may store it as "password 7 <obfuscated>" (service password-encryption)."""
    parts = REF_RE.split(ln)
    out = []
    for i, part in enumerate(parts):
        if i < len(parts) - 1:
            m = _TYPE_BEFORE.search(part)
            if m:
                part = part[:m.start()] + (" " if m.group(0)[0].isspace() else "")
            out.append(re.escape(part) + _SLOT.format(i=i))
        else:
            out.append(re.escape(part))
    return re.compile("^" + "".join(out) + "$")


def _compare(expected: str | None, got: str, typ: str | None) -> str:
    if expected is None:
        return "unverifiable"            # no store, or the reference does not resolve
    if got == expected:
        return "match"
    if typ == "7":
        try:
            return "match" if cisco7_decode(got) == expected else "mismatch"
        except ValueError:
            return "mismatch"
    if got.startswith("$") or typ in ("5", "8", "9"):
        return "unverifiable"            # device re-encrypted/hashed it ($9$, $6$, type 5/8/9)
    return "mismatch"                    # both in clear and different


def _present(ln: str, have: set[str], resolve=None) -> tuple[bool, list[tuple[str, str]]]:
    """(line present, [(ref, match|mismatch|unverifiable)]). A line carrying D3
    references matches a running line of the same structure; each value is then judged
    by ``_compare``. Structure alone never counts as a verified key."""
    if ln in have:
        return True, []
    refs = REF_RE.findall(ln)
    if not refs:
        return False, []
    pat = _pattern(ln)
    best: list[tuple[str, str]] | None = None
    for h in sorted(have):
        m = pat.match(h)
        if not m:
            continue
        res = []
        for i, ref in enumerate(refs):
            got = m.group(f"q{i}") if m.group(f"q{i}") is not None else m.group(f"u{i}")
            res.append((ref, _compare(resolve(ref) if resolve else None, got, m.group(f"t{i}"))))
        if best is None or sum(r == "match" for _, r in res) > sum(r == "match" for _, r in best):
            best = res
    return best is not None, best or []


def _device_check(device: str, vendor: str, candidate: str, running: str | None,
                  resolve=None) -> dict:
    lines = _effective(candidate)
    row: dict = {"device": device, "vendor": vendor, "expected_lines": len(lines),
                 "missing": [], "still_present": [],
                 "secrets": {"match": 0, "mismatch": [], "unverifiable": []}}

    def check(ln: str, have: set[str]) -> None:
        found, results = _present(ln, have, resolve)
        if not found:
            row["missing"].append(ln)
        for ref, verdict in results:
            if verdict == "match":
                row["secrets"]["match"] += 1
            else:
                row["secrets"][verdict].append(ref)
    if running is None:
        row["status"] = "no_running_config"
        return row
    if not lines:
        row["status"] = "nothing_to_check"
        return row
    if vendor == "junos":
        flat = junos.to_set(running) if junos.looks_hierarchical(running) else running
        have = set(_effective(flat))
        for ln in lines:
            if ln.startswith("delete "):
                path = "set " + ln[len("delete "):]
                if any(h == path or h.startswith(path + " ") for h in have):
                    row["still_present"].append(ln)
            elif ln.startswith(("deactivate ", "activate ")):
                continue  # state flags are not visible in display-set output
            else:
                check(ln, have)
    else:
        have = set(_effective(running))
        for ln in lines:
            if ln.lower().startswith("no "):
                if _norm(ln[3:]) in have:
                    row["still_present"].append(ln)
            else:
                check(ln, have)
    bad = row["missing"] or row["still_present"] or row["secrets"]["mismatch"]
    row["status"] = "drift" if bad else "applied"
    row["missing"] = row["missing"][:_MAX_LIST]
    row["still_present"] = row["still_present"][:_MAX_LIST]
    return row


def verify_postchange(bundle: dict, running: list[dict], intents: list[dict] | None = None,
                      intent_runner=None, secret_store=None) -> dict:
    """``running``: [{device, vendor?, config}]. ``intent_runner(intents, configs)`` defaults to
    the Batfish runner in full-replace mode."""
    run_by_dev = {str(r.get("device") or ""): r for r in running if isinstance(r, dict)}
    run_id = str(bundle.get("run_id") or "")

    def resolve(ref: str) -> str | None:
        if secret_store is None:
            return None
        try:
            return resolve_text(ref, run_id=run_id, store=secret_store)
        except SecretStoreError:
            return None
    configs = ((bundle.get("change") or {}).get("generated_configs") or [])
    devices = []
    for c in configs:
        dev = str(c.get("device") or "")
        r = run_by_dev.get(dev)
        devices.append(_device_check(dev, str(c.get("vendor") or ""), str(c.get("config") or ""),
                                     None if r is None else str(r.get("config") or ""),
                                     resolve))
    intent_record = None
    if intents:
        if intent_runner is None:
            from .intents.runner import run_intents

            def intent_runner(i, cfgs):
                return run_intents(i, cfgs, replace=True)
        intent_record = intent_runner(intents, [
            {"device": d, "vendor": str(r.get("vendor") or ""), "config": str(r.get("config") or "")}
            for d, r in run_by_dev.items()])

    drift = any(d["status"] in ("drift", "no_running_config") for d in devices)
    checked = any(d["status"] == "applied" for d in devices)
    intents_bad = bool(intent_record and (intent_record["failed"] or intent_record["errors"]))
    if intents_bad:
        status = "failed"
    elif drift:
        status = "drift"
    elif any(d["secrets"]["unverifiable"] for d in devices):
        status = "partial"               # structure landed; some key values unverifiable
    elif checked or intent_record:
        status = "verified"
    else:
        status = "unverifiable"
    rec = {
        "kind": "aegis-postchange",
        "run_id": bundle.get("run_id"),
        "change_ref": (bundle.get("change") or {}).get("change_ref"),
        "bundle_sha256": (bundle.get("integrity") or {}).get("sha256"),
        "verified_utc": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "devices": devices,
        "intents": intent_record,
    }
    rec["record_sha256"] = hashlib.sha256(
        json.dumps(rec, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    return rec
