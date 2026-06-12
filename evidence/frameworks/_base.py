"""Shared contract for AEGIS compliance-framework modules.

Each framework lives in its own module `frameworks/<name>.py` and exposes:

    FRAMEWORK = "disa_stig"                  # the id used in the bundle + UI
    def evaluate(sig: ComplianceSignal) -> list[dict]: ...

`evaluate` returns a list of control results built with `control(...)`. The registry
(frameworks/__init__.py) auto-discovers every such module, so adding a framework is a
single new file — no central edit, no merge conflict.

A control result is:
    {framework, control, status, evidence, kind}
  status: PASS | FAIL | NA
  kind:   "config-checked"   -> actively verified against the proposed config / Batfish
          "process-mapped"   -> satisfied by the AEGIS process itself (twin-tested,
                                 deterministic verification, sealed evidence, gated push)

HONESTY RULE: "config-checked" controls assert something we can actually see in the
config or static analysis. "process-mapped" controls only claim what the pipeline
structurally guarantees for THIS run (it was validated in a twin before deployment) —
never that the org is "certified". Keep evidence strings specific and truthful.
"""
from __future__ import annotations
from dataclasses import dataclass

from ...core.backends.base import GeneratedConfig, BatfishResult, TwinResult, DiffResult  # noqa: F401

PASS = "pass"
FAIL = "fail"
NA = "not_applicable"
CONFIG_CHECKED = "config-checked"
PROCESS_MAPPED = "process-mapped"


@dataclass(frozen=True)
class ComplianceSignal:
    """Everything a framework module may inspect for one change.

    Built once by `map_controls` and shared (read-only) across every framework, so the
    per-framework checks stay pure and deterministic.
    """
    configs: list  # list[GeneratedConfig]
    batfish: dict  # BatfishResult
    twin: dict | None = None   # TwinResult (None for static-only contexts)
    diff: dict | None = None   # DiffResult
    intent: str = ""
    source: str = "nl_intent"  # nl_intent | config_import

    # ---- derived, reusable predicates -----------------------------------
    def text(self) -> str:
        """All proposed config concatenated + lowercased (cheap to recompute)."""
        return "\n".join(c["config"].lower() for c in self.configs)

    def findings(self) -> list[str]:
        return [str(f) for f in (self.batfish.get("findings") or [])]

    def has_token(self, *tokens: str) -> bool:
        t = self.text()
        return any(tok.lower() in t for tok in tokens)

    def has_bgp(self) -> bool:
        return self.has_token("bgp", "neighbor", "remote-as") or \
            any("bgp" in f.lower() for f in self.findings())

    def has_routing_proto(self) -> bool:
        return self.has_bgp() or self.has_token("ospf", "isis", "rip")

    def has_plaintext_secret(self) -> bool:
        return self.has_token("plaintext", "abc123", "password 0 ", "key 0 ")

    def missing_export_policy(self) -> bool:
        return any("without export policy" in f for f in self.findings())

    def batfish_errors(self) -> int:
        return int(self.batfish.get("errors", 0))

    def batfish_clean(self) -> bool:
        return self.batfish_errors() == 0

    def twin_tested(self) -> bool:
        return self.twin is not None

    def twin_converged(self) -> bool:
        return bool(self.twin and self.twin.get("converged"))

    def sessions_dropped(self) -> bool:
        return bool(self.diff and len(self.diff.get("sessions_dropped") or []) > 0)

    def is_config_import(self) -> bool:
        return self.source == "config_import"


def control(framework: str, control_id: str, status: str, evidence: str,
            kind: str = PROCESS_MAPPED) -> dict:
    """Build one control-result row (the shape the bundle/PDF/UI consume)."""
    return {"framework": framework, "control": control_id,
            "status": status, "evidence": evidence, "kind": kind}
