"""In-process simulator backend.

Models the *behaviour* of the real stack (Qwen3 config-gen, Batfish, containerlab
convergence, Nornir diff) deterministically enough to exercise every branch of the
pipeline and adversarial enough to stress it. No network, no external deps.

Determinism: every method is seeded off the intent string, so a given intent always
produces the same bundle -> reproducible evidence, testable invariants.
"""
from __future__ import annotations
import hashlib
import random
import re
from .base import GeneratedConfig, BatfishResult, TwinResult, DiffResult

# A tiny slice of the 52k-command corpus, used for grounding provenance.
_CORPUS = {
    "srlinux": ["set / network-instance default protocols bgp",
                "set / interface ethernet-1/1 subinterface 0 vlan",
                "set / network-instance default protocols bgp neighbor"],
    "ceos":    ["router bgp", "vlan", "interface Ethernet1", "ip routing"],
    "frr":     ["router bgp", "network", "neighbor remote-as", "vlan"],
    "junos":   ["set protocols bgp group", "set vlans", "set interfaces"],
    "ios":     ["router bgp", "vlan", "interface", "neighbor"],
    "panos":   ["set network virtual-router", "set zone", "set rulebase security"],
}

_LAB_NODES = {"clos-evpn": 9, "dcn-10node": 10, "edge-slice": 4, "single": 1}

# Vendors present per reference lab (drives multi-vendor config-gen).
_LAB_VENDORS = {
    "clos-evpn":  ["srlinux", "ceos", "frr"],
    "dcn-10node": ["frr"],
    "edge-slice": ["junos", "ios"],
    "single":     ["frr"],
}


def _seed(intent: str) -> random.Random:
    h = hashlib.sha256(intent.encode("utf-8", "replace")).hexdigest()
    return random.Random(int(h[:16], 16))


class SimulatorBackend:
    """Deterministic, branch-covering simulator."""

    # tuneable failure-injection rates (0..1) — stress harness flips these
    def __init__(self, converge_fail_rate: float = 0.08,
                 batfish_error_rate: float = 0.15):
        self.converge_fail_rate = converge_fail_rate
        self.batfish_error_rate = batfish_error_rate

    # --- LLM step ---------------------------------------------------------
    def generate_config(self, intent: str, lab: str) -> list[GeneratedConfig]:
        rng = _seed(intent + "|gen")
        vendors = _LAB_VENDORS.get(lab, ["frr"])
        # Pull a target device count from the intent if it mentions one, else 1-3.
        m = re.search(r"\b(\d{1,2})\b", intent)
        n = max(1, min(int(m.group(1)) if m else rng.randint(1, 3), 6))
        configs: list[GeneratedConfig] = []
        low = intent.lower()
        for i in range(n):
            vendor = vendors[i % len(vendors)]
            lines = []
            grounded = []
            if "vlan" in low:
                vid = (re.search(r"vlan\s*(\d+)", low) or [None, "100"])[1]
                lines.append(f"# add vlan {vid}")
                grounded.append(_CORPUS[vendor][min(1, len(_CORPUS[vendor]) - 1)])
            if "bgp" in low or "peer" in low or "neighbor" in low:
                lines.append("# bgp neighbor 10.0.0.1 remote-as 65010")
                grounded.append(_CORPUS[vendor][0])
            if "ospf" in low:
                lines.append("# ip ospf area 0")
                grounded.append(_CORPUS[vendor][0])
            # An adversarial intent can coax a plaintext secret into the config.
            if "auth" in low or "key" in low or "password" in low:
                lines.append("# set bgp authentication-key plaintext abc123")
                grounded.append(_CORPUS[vendor][0])
            if not lines:
                lines.append("# (no actionable directive parsed)")
                grounded.append(_CORPUS[vendor][0])
            configs.append(GeneratedConfig(
                device=f"{lab}-node-{i+1}",
                vendor=vendor,
                config="\n".join(lines),
                grounded_commands=sorted(set(grounded)),
            ))
        return configs

    # --- static analysis --------------------------------------------------
    def batfish_check(self, configs: list[GeneratedConfig]) -> BatfishResult:
        errors = warnings = passed = 0
        findings: list[str] = []
        for c in configs:
            txt = c["config"].lower()
            if "plaintext" in txt or "abc123" in txt:
                errors += 1
                findings.append(f"{c['device']}: plaintext BGP auth-key (PCI 8.3.1 fail)")
            if "bgp" in txt and "export" not in txt and "policy" not in txt:
                warnings += 1
                findings.append(f"{c['device']}: BGP neighbor without export policy")
            if "(no actionable directive parsed)" in txt:
                warnings += 1
                findings.append(f"{c['device']}: empty/uninterpretable change")
            passed += 1
        return BatfishResult(errors=errors, warnings=warnings,
                             passed=passed, findings=findings)

    # --- twin lifecycle ---------------------------------------------------
    def spawn_twin(self, lab: str) -> str:
        rng = _seed(lab + "|spawn")
        return f"twin-{lab}-{rng.randint(10000, 99999)}"

    def apply_and_converge(self, twin_id: str,
                           configs: list[GeneratedConfig]) -> TwinResult:
        lab = "-".join(twin_id.split("-")[1:-1]) or "single"
        nodes = _LAB_NODES.get(lab, 4)
        rng = _seed(twin_id + "|conv")
        bgp_before = max(0, nodes * 4 + rng.randint(-2, 2))
        fails = rng.random() < self.converge_fail_rate
        # A change that drops a session also drops BGP-after below before.
        drop = rng.randint(1, 3) if (fails or any("plaintext" in c["config"]
                                                  for c in configs)) else 0
        bgp_after = max(0, bgp_before - drop)
        return TwinResult(
            topology=lab,
            node_count=nodes,
            converged=not fails,
            convergence_sec=round(rng.uniform(1.2, 6.5), 2),
            bgp_before=bgp_before,
            bgp_after=bgp_after,
        )

    def state_diff(self, twin_id: str) -> DiffResult:
        rng = _seed(twin_id + "|diff")
        added = [f"10.40.{i}.0/24" for i in range(rng.randint(0, 3))]
        removed = [f"10.99.{i}.0/24" for i in range(rng.randint(0, 2))]
        dropped = [f"sess-{i}" for i in range(rng.randint(0, 2))]
        affected = len(added) + len(removed) + len(dropped)
        return DiffResult(routes_added=added, routes_removed=removed,
                          sessions_dropped=dropped, devices_affected=affected)

    def teardown_twin(self, twin_id: str) -> None:
        # simulator: nothing to free. real backend: clab destroy + ns cleanup.
        return None

    # --- model identity (the #4 wedge) ------------------------------------
    def model_identity(self) -> dict:
        """Deterministic attestation of the simulated generator. Fixed fields keep the
        sealed bundle reproducible (stress INV-3). The real local/cloud backends attest a
        weights-sha256 / identity-claim at the generate-path cutover."""
        return {
            "provider": "simulator",
            "model": "deterministic-sim-v1",
            "model_hash": None,
            "model_hash_kind": "identity-claim",
            "api_version": None,
            "capabilities": [],
            "resolved_at_utc": "1970-01-01T00:00:00+00:00",
        }
