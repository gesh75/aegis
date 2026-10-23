"""Junos hierarchical ``{ }`` config -> flat ``set`` lines.

Compliance checks are line-oriented regexes. Junos operators paste either
``show configuration | display set`` (already flat) or the default curly-brace form;
without normalization every Junos BGP peer in curly form is invisible to the
DISA/PCI checks and fails (or passes) for the wrong reason.

Handles: nested blocks, ``;`` statements, quoted strings, ``[ a b ]`` lists,
``/* */`` and ``#`` comments, and the ``protect:`` / ``replace:`` prefixes.
``inactive:`` statements and blocks are DROPPED — they are not in effect on the
device, so an inactive ``authentication-key`` must not count as authentication.
Pure, no I/O; never raises (unbalanced input degrades to best effort).
"""
from __future__ import annotations

import re

_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|/\*.*?\*/|#[^\n]*|[{};\[\]]|[^\s{};\[\]"#]+', re.S)


def looks_hierarchical(text: str) -> bool:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        return False
    if sum(1 for ln in lines if ln.startswith(("set ", "delete ", "deactivate "))) > len(lines) / 2:
        return False
    return "{" in text and "}" in text


def to_set(text: str) -> str:
    """Return the config as ``set`` lines (input returned unchanged if already flat)."""
    if not looks_hierarchical(text):
        return text or ""
    out: list[str] = []
    stack: list[tuple[list[str], bool]] = []   # (path words, inactive)
    cur: list[str] = []
    cur_inactive = False
    in_list = False

    def inactive_ctx() -> bool:
        return any(flag for _, flag in stack)

    def emit() -> None:
        if cur and not (cur_inactive or inactive_ctx()):
            path = [w for words, _ in stack for w in words]
            out.append("set " + " ".join(path + cur))

    for tok in _TOKEN.findall(text):
        if tok.startswith("/*") or tok.startswith("#"):
            continue
        if tok == "[":
            in_list = True
            cur.append("[")
            continue
        if tok == "]":
            in_list = False
            cur.append("]")
            continue
        if tok == "{":
            stack.append((cur, cur_inactive))
            cur, cur_inactive = [], False
            continue
        if tok == ";":
            emit()
            cur, cur_inactive = [], False
            continue
        if tok == "}":
            emit()                      # tolerate a missing trailing ';'
            cur, cur_inactive = [], False
            if stack:
                stack.pop()
            continue
        if not cur and not in_list and tok in ("inactive:", "protect:", "replace:"):
            cur_inactive = cur_inactive or tok == "inactive:"
            continue
        cur.append(tok)
    emit()
    return "\n".join(out)
