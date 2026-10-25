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

status: ``verified`` (all lines applied, intents pass) | ``drift`` (lines missing or
present that must be gone) | ``failed`` (an intent fails or cannot be evaluated) |
``unverifiable`` (nothing checkable: no effective lines and no intents). It is never
"verified" by default.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from ..evidence import junos

_SKIP = re.compile(r"^(?:!|#|end$|exit$|exit-address-family$|configure(?: terminal)?$|"
                   r"conf t$|commit(?: .*)?$|top$|quit$)", re.IGNORECASE)
_MAX_LIST = 20


def _norm(line: str) -> str:
    return " ".join(line.strip().split())


def _effective(text: str) -> list[str]:
    return [n for n in (_norm(ln) for ln in (text or "").splitlines()) if n and not _SKIP.match(n)]


def _device_check(device: str, vendor: str, candidate: str, running: str | None) -> dict:
    lines = _effective(candidate)
    row: dict = {"device": device, "vendor": vendor, "expected_lines": len(lines),
                 "missing": [], "still_present": []}
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
            elif ln not in have:
                row["missing"].append(ln)
    else:
        have = set(_effective(running))
        for ln in lines:
            if ln.lower().startswith("no "):
                if _norm(ln[3:]) in have:
                    row["still_present"].append(ln)
            elif ln not in have:
                row["missing"].append(ln)
    row["status"] = "applied" if not (row["missing"] or row["still_present"]) else "drift"
    row["missing"] = row["missing"][:_MAX_LIST]
    row["still_present"] = row["still_present"][:_MAX_LIST]
    return row


def verify_postchange(bundle: dict, running: list[dict], intents: list[dict] | None = None,
                      intent_runner=None) -> dict:
    """``running``: [{device, vendor?, config}]. ``intent_runner(intents, configs)`` defaults to
    the Batfish runner in full-replace mode."""
    run_by_dev = {str(r.get("device") or ""): r for r in running if isinstance(r, dict)}
    configs = ((bundle.get("change") or {}).get("generated_configs") or [])
    devices = []
    for c in configs:
        dev = str(c.get("device") or "")
        r = run_by_dev.get(dev)
        devices.append(_device_check(dev, str(c.get("vendor") or ""), str(c.get("config") or ""),
                                     None if r is None else str(r.get("config") or "")))
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
