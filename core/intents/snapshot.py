"""Build the reference (before) and candidate (after) snapshots for the intent oracle.

Reference = the device configs in ``base_dir`` (``AEGIS_BATFISH_SNAPSHOT_DIR``, e.g. the
nightly config backup), laid out as Batfish expects (``<dir>/configs/<device>.cfg``, or
files directly in ``<dir>``).

Candidate = reference + this change, per device:

  * ``junos-set-merge`` — vendor junos, candidate is ``set``/``delete`` lines and a base file
    exists: the base (flattened to set form when hierarchical) + the candidate lines. Junos
    applies set lines in order, so this is the real post-change config.
  * ``replace`` — any other vendor with a base file: the candidate must be the FULL device
    config (config_import of a running-config). A partial Cisco/EOS snippet cannot be merged
    safely (mode context is positional), so it replaces the file and Batfish's parse-fidelity
    check will expose a truncated config.
  * ``new`` — no base file for that device: the candidate becomes a new file.

Pure: returns {relative_path: text}; the oracle writes them. Never reads outside base_dir.
"""
from __future__ import annotations

import os
import re

from ...evidence import junos

_SAFE = re.compile(r"[^A-Za-z0-9._-]")
_JUNOS_HEADER = "#RANCID-CONTENT-TYPE: juniper"
_MAX_FILE_BYTES = 5 * 1024 * 1024


def _fname(device: str) -> str:
    return (_SAFE.sub("_", device or "device").strip("._") or "device")[:100] + ".cfg"


def read_base(base_dir: str | None) -> dict[str, str]:
    """{device_stem_lower: text} from base_dir/configs (preferred) or base_dir."""
    if not base_dir:
        return {}
    root = os.path.join(base_dir, "configs")
    if not os.path.isdir(root):
        root = base_dir
    if not os.path.isdir(root):
        raise FileNotFoundError(f"snapshot dir not found: {base_dir}")
    out: dict[str, str] = {}
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if not os.path.isfile(path) or os.path.islink(path) or name.startswith("."):
            continue
        if os.path.getsize(path) > _MAX_FILE_BYTES:
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            out[os.path.splitext(name)[0].lower()] = fh.read()
    return out


def _is_set_delta(text: str) -> bool:
    lines = [ln.strip() for ln in (text or "").splitlines()
             if ln.strip() and not ln.strip().startswith("#")]
    return bool(lines) and all(ln.startswith(("set ", "delete ", "deactivate ", "activate "))
                               for ln in lines)


def materialize(configs: list[dict], base: dict[str, str], replace: bool = False
                ) -> tuple[dict[str, str] | None, dict[str, str], list[dict]]:
    """(reference_files | None, candidate_files, merge_log). ``replace`` forces full-file
    replacement (post-change: the configs ARE the running configs)."""
    reference = {f"configs/{_fname(k)}": v for k, v in base.items()} if base else None
    candidate = dict(reference or {})
    log: list[dict] = []
    for c in configs:
        device = str(c.get("device") or "device")
        vendor = str(c.get("vendor") or "")
        text = str(c.get("config") or "")
        path = f"configs/{_fname(device)}"
        base_text = base.get(os.path.splitext(_fname(device))[0].lower())
        if (not replace and vendor == "junos" and base_text is not None
                and _is_set_delta(text)):
            flat = junos.to_set(base_text) if junos.looks_hierarchical(base_text) else base_text
            body = flat.rstrip("\n") + "\n" + text.strip("\n") + "\n"
            if not body.lstrip().startswith(_JUNOS_HEADER):
                body = _JUNOS_HEADER + "\n" + body
            candidate[path] = body
            mode = "junos-set-merge"
        elif base_text is not None:
            if vendor == "junos" and _is_set_delta(text) and _JUNOS_HEADER not in text:
                text = _JUNOS_HEADER + "\n" + text   # display-set running config
            candidate[path] = text
            mode = "replace"
        else:
            if vendor == "junos" and _is_set_delta(text) and _JUNOS_HEADER not in text:
                text = _JUNOS_HEADER + "\n" + text
            candidate[path] = text
            mode = "new"
        log.append({"device": device, "vendor": vendor, "mode": mode, "file": path})
    return reference, candidate, log
