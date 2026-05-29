"""Rollback-plan generation. Every preflight run emits a reversal plan, and in the
twin we can actually test that the reversal restores the pre-change session count.
"""
from __future__ import annotations
from ..backends.base import GeneratedConfig


def build_rollback_plan(configs: list[GeneratedConfig]) -> list[str]:
    """Produce a human-readable reversal step per generated config line.

    Real backend negates each directive (no/delete/set ... to prior value). Here we
    emit the inverse intent so the bundle always carries a defensible rollback.
    """
    plan: list[str] = []
    for c in configs:
        for line in c["config"].splitlines():
            line = line.strip().lstrip("# ").strip()
            if not line or line.startswith("("):
                continue
            if line.startswith("add "):
                plan.append(f"{c['device']} [{c['vendor']}]: remove {line[4:]}")
            elif line.startswith("set "):
                plan.append(f"{c['device']} [{c['vendor']}]: delete {line[4:]}")
            else:
                plan.append(f"{c['device']} [{c['vendor']}]: revert -> {line}")
    if not plan:
        plan.append("no-op change: nothing to roll back")
    return plan
