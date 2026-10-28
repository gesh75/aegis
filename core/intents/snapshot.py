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
    safely (mode context is positional), and Batfish's parse-fidelity check cannot see a
    truncated config (a well-formed partial file parses). So the candidate replaces the file
    only when it is shown complete against the base (``_incomplete``: no dropped block, no net
    loss of lines); otherwise ``SnapshotError`` and every intent is an error row.
  * ``new`` — no base file for that device: the candidate becomes a new file.

One device is one snapshot file: two entries that normalize to the same file raise
``SnapshotError`` rather than letting the last one silently stand in for both.

Pure: returns {relative_path: text}; the oracle writes them. Never reads outside base_dir.
"""
from __future__ import annotations

import os
import re

from ...evidence import junos

_SAFE = re.compile(r"[^A-Za-z0-9._-]")
_JUNOS_HEADER = "#RANCID-CONTENT-TYPE: juniper"
_MAX_FILE_BYTES = 5 * 1024 * 1024
# lines that differ on every ``show running-config`` and say nothing about the device
_NOISE = ("building configuration", "current configuration", "using ")


class SnapshotError(ValueError):
    """The change cannot be turned into a trustworthy candidate snapshot (a device appears
    twice, or a config is not shown to be complete). Fail closed: the runner turns it into an
    error row for every intent, so the verdict blocks. The message names the device."""


def _fname(device: str) -> str:
    return (_SAFE.sub("_", device or "device").strip("._") or "device")[:100] + ".cfg"


def _device_key(device: str) -> str:
    """The key a device is looked up by in ``base`` (and deduplicated by): the snapshot file
    stem, lower-cased."""
    return os.path.splitext(_fname(device))[0].lower()


def _shown(device: str) -> str:
    return repr(device[:60] + ("..." if len(device) > 60 else ""))


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


def _outline(text: str, flatten: bool) -> dict[str, set[str]]:
    """{top-level line: {its indented lines}} — comments, blanks, ``end`` and volatile header
    lines ignored. ``flatten`` first turns Junos ``{ }`` into ``set`` lines (all top level)."""
    if flatten:
        text = junos.to_set(text)
    out: dict[str, set[str]] = {}
    cur: str | None = None
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if (not stripped or stripped[0] in "!#" or stripped == "end"
                or stripped.lower().startswith(_NOISE)):
            continue
        if line[0] in " \t" and cur is not None:
            out[cur].add(stripped)
        else:
            cur = stripped
            out.setdefault(cur, set())
    return out


def _incomplete(base_text: str, text: str, flatten: bool) -> list[str]:
    """Why ``text`` cannot be shown to be a complete replacement for ``base_text`` ([] = it
    can). A truncated snippet is the dangerous case: omitted interfaces, routes and ACLs
    leave every ``deny`` intent trivially true (flows end NO_ROUTE) and a partial file still
    parses, so the config is only trusted when it keeps every block of the base and loses no
    lines overall. Editing a line (drop one, add one) is fine; removing blocks or lines
    without a counterpart is not, because a truncation looks exactly like that. A merge would
    hide such removals, so the change is rejected instead. This is a heuristic against
    truncation, not proof against a deliberately padded config."""
    base, cand = _outline(base_text, flatten), _outline(text, flatten)
    issues: list[str] = []
    for header, body in base.items():
        if header not in cand:
            if body:
                issues.append(f"drops block {header[:60]!r}")
        elif len(body - cand[header]) > len(cand[header] - body):
            issues.append(f"loses lines of {header[:60]!r}")
    gone = [h for h, b in base.items() if not b and h not in cand]
    added = [h for h, b in cand.items() if not b and h not in base]
    if len(gone) > len(added):
        issues.append(f"drops {len(gone) - len(added)} net top-level line(s), "
                      f"e.g. {gone[0][:60]!r}")
    return issues


def materialize(configs: list[dict], base: dict[str, str], replace: bool = False
                ) -> tuple[dict[str, str] | None, dict[str, str], list[dict]]:
    """(reference_files | None, candidate_files, merge_log). ``replace`` forces full-file
    replacement (post-change: the configs ARE the running configs, so no completeness check).
    Raises ``SnapshotError`` for a duplicate device or a config not shown complete."""
    reference = {f"configs/{_fname(k)}": v for k, v in base.items()} if base else None
    candidate = dict(reference or {})
    log: list[dict] = []
    seen: dict[str, str] = {}
    for c in configs:
        device = str(c.get("device") or "device")
        vendor = str(c.get("vendor") or "")
        text = str(c.get("config") or "")
        key = _device_key(device)
        if key in seen:
            raise SnapshotError(f"device {_shown(device)} appears twice in one change "
                                f"(also {_shown(seen[key])}): one config per device")
        seen[key] = device
        base_text = base.get(key)
        # an existing device overwrites ITS reference file, whatever the case of its name
        path = f"configs/{_fname(key if base_text is not None else device)}"
        if (not replace and vendor == "junos" and base_text is not None
                and _is_set_delta(text)):
            flat = junos.to_set(base_text) if junos.looks_hierarchical(base_text) else base_text
            body = flat.rstrip("\n") + "\n" + text.strip("\n") + "\n"
            if not body.lstrip().startswith(_JUNOS_HEADER):
                body = _JUNOS_HEADER + "\n" + body
            candidate[path] = body
            mode = "junos-set-merge"
        elif base_text is not None:
            if not replace:
                issues = _incomplete(base_text, text, vendor == "junos")
                if issues:
                    raise SnapshotError(
                        f"config for {_shown(device)} is not shown to be the complete device "
                        f"config ({'; '.join(issues[:3])}"
                        f"{'; ...' if len(issues) > 3 else ''}): submit the full running "
                        "config (or, for Junos, set/delete lines)")
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
