"""Rollback-plan generation. Every preflight run emits a reversal plan.

The plan is a PLAN: AEGIS does not execute it in the twin yet, and the bundle says so
(`rollback.tested_in_twin=false`, `verification="plan-only"`). It is vendor-aware so the
steps are actually runnable by an engineer:

  junos              set X        -> delete X
                     delete X     -> restore X from `show system rollback 1` (prior value
                                     is not in the candidate, so we never guess it)
                     + a device-level step: apply with `commit confirmed`, revert with
                     `rollback 1` + `commit` — the native, state-complete rollback
  ios/ceos/frr       X            -> no X        (inside its parent mode, e.g.
                                                   `router bgp 65010 → no neighbor ...`)
                     no X         -> X           (prior value flagged for review)
  srlinux / panos    set X        -> delete X
  simulator markers  "# add X"    -> remove X ;  "# set X" -> delete X
"""
from __future__ import annotations
from ..backends.base import GeneratedConfig

_CISCO_LIKE = {"ios", "ceos", "frr"}
_SKIP = {"!", "end", "exit", "exit-address-family", "configure", "configure terminal",
         "conf t", "commit", "quit"}


def _step(c: GeneratedConfig, text: str) -> str:
    return f"{c['device']} [{c['vendor']}]: {text}"


def _plan_for(c: GeneratedConfig) -> list[str]:
    vendor = c.get("vendor") or ""
    out: list[str] = []
    parent: str | None = None
    is_junos_set = vendor == "junos"
    if is_junos_set:
        out.append(_step(c, "apply with `commit confirmed 5`; to revert run `rollback 1` + "
                            "`commit` (state-complete, preferred over line-by-line)"))
    for raw in (c.get("config") or "").splitlines():
        indented = raw[:1] in (" ", "\t")
        line = raw.strip()
        if line.startswith("#"):                           # simulator/demo markers
            line = line.lstrip("# ").strip()
            if not line or line.startswith("("):
                continue
            if line.startswith("add "):
                out.append(_step(c, f"remove {line[4:]}"))
            elif line.startswith("set "):
                out.append(_step(c, f"delete {line[4:]}"))
            else:
                out.append(_step(c, f"revert -> {line}"))
            continue
        if not line or line.lower() in _SKIP:
            continue
        if line.startswith("set "):
            out.append(_step(c, f"delete {line[4:]}"))
        elif line.startswith("delete ") and (is_junos_set or vendor in ("srlinux", "panos")):
            out.append(_step(c, f"restore `{line[7:]}` from the pre-change config "
                                "(`show system rollback 1` on Junos) — prior value not in "
                                "the candidate"))
        elif vendor in _CISCO_LIKE:
            ctx = f"{parent} → " if (indented and parent) else ""
            if line.startswith("no "):
                out.append(_step(c, f"{ctx}re-add `{line[3:]}` (verify prior value)"))
            elif indented:
                out.append(_step(c, f"{ctx}no {line}"))
            else:
                parent = line
                out.append(_step(c, f"no {line}  (only if this mode was created by the change)"))
        else:
            out.append(_step(c, f"revert -> {line}"))
    return out


def build_rollback_plan(configs: list[GeneratedConfig]) -> list[str]:
    """Produce a human-readable reversal plan per device."""
    plan: list[str] = []
    for c in configs:
        plan.extend(_plan_for(c))
    if not plan:
        plan.append("no-op change: nothing to roll back")
    return plan
