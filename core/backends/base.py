"""Backend protocol for AEGIS.

The orchestrator is deterministic and backend-agnostic. Each backend implements
the same surface, so the identical pipeline runs against:

  - SimulatorBackend : in-process, no external deps -> CI, dev, stress tests
  - HttpBackend      : your existing DCN_Network_Tool :5757 endpoints (air-gapped)

This is the "guarded agentic" boundary: the backend's generate_config() is the only
step where an LLM is involved. Everything after it is verification, not generation.
"""
from __future__ import annotations
from typing import Protocol, TypedDict, runtime_checkable


class GeneratedConfig(TypedDict):
    device: str
    vendor: str            # srlinux | ceos | frr | junos | ios | panos
    config: str
    grounded_commands: list[str]


class BatfishResult(TypedDict):
    errors: int
    warnings: int
    passed: int
    findings: list[str]


class TwinResult(TypedDict):
    topology: str
    node_count: int
    converged: bool
    convergence_sec: float
    bgp_before: int
    bgp_after: int


class DiffResult(TypedDict):
    routes_added: list[str]
    routes_removed: list[str]
    sessions_dropped: list[str]
    devices_affected: int


@runtime_checkable
class Backend(Protocol):
    """Everything the deterministic pipeline needs from the environment."""

    def generate_config(self, intent: str, lab: str) -> list[GeneratedConfig]:
        """LLM step: NL intent -> per-device config, grounded on the 52k corpus."""
        ...

    def batfish_check(self, configs: list[GeneratedConfig]) -> BatfishResult:
        """Static config analysis before anything is applied to the twin."""
        ...

    def spawn_twin(self, lab: str) -> str:
        """Clone a throwaway namespaced copy of a topology slice. Returns twin id."""
        ...

    def apply_and_converge(self, twin_id: str,
                           configs: list[GeneratedConfig]) -> TwinResult:
        """Push config into the twin and wait for BGP/EVPN to (try to) converge."""
        ...

    def state_diff(self, twin_id: str) -> DiffResult:
        """Before/after routing + session diff captured from the twin."""
        ...

    def teardown_twin(self, twin_id: str) -> None:
        """Always called in a finally — throwaway twins must not leak."""
        ...
