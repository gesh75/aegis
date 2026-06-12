"""Self-test driver for every AEGIS compliance-framework module + a full-pipeline check.

Two layers, both deterministic:

  L1  Per-framework SELF_TEST — every module under evidence/frameworks/ ships a
      SELF_TEST list of (signal_kwargs, control_id, expected_status). For each case we
      build a ComplianceSignal, run that module's evaluate(), find the row whose
      `control` == control_id, and assert its `status` == expected_status. Every such
      assertion is counted. This proves each framework's own checks behave as authored.

  L2  Full pipeline once with ALL registered frameworks — run_preflight() on a
      SimulatorBackend, then assert every compliance row carries the bundle shape
      (framework/control/status/evidence/kind), status is one of {pass,fail,
      not_applicable}, and the WHOLE bundle validates against the JSON schema.

Run: python3 -m aegis.tests.compliance_test
"""
from __future__ import annotations
import importlib
import json
import pkgutil
import sys
import time
from pathlib import Path

import jsonschema

from ..evidence.frameworks import REGISTRY, available
from ..evidence.frameworks._base import ComplianceSignal
from ..core.orchestrator.pipeline import run_preflight
from ..core.backends.simulator import SimulatorBackend

_VALID_STATUS = {"pass", "fail", "not_applicable"}
_SCHEMA_PATH = (Path(__file__).resolve().parents[1]
                / "evidence" / "schema" / "evidence_bundle.schema.json")


def _framework_modules() -> dict[str, object]:
    """Map each registered framework id -> its module (so we can reach SELF_TEST).

    The framework id (FRAMEWORK) does not always equal the module filename
    (e.g. id 'nist_800-171' lives in nist_800_171.py), so we discover every
    sibling module in the package and key it by its declared FRAMEWORK.
    """
    pkg = importlib.import_module("aegis.evidence.frameworks")
    mods: dict[str, object] = {}
    for _finder, name, _ispkg in pkgutil.iter_modules(pkg.__path__):
        if name.startswith("_"):
            continue
        mod = importlib.import_module(f"{pkg.__name__}.{name}")
        fw = getattr(mod, "FRAMEWORK", None)
        if fw and callable(getattr(mod, "evaluate", None)):
            mods[fw] = mod
    # only return frameworks that are actually registered/available
    return {fw: mods[fw] for fw in available() if fw in mods}


def run() -> dict:
    res = {"frameworks": 0, "selftest_checks": 0, "pipeline_rows": 0}
    fails: list[str] = []

    # ---- L1: per-framework SELF_TEST -----------------------------------
    mods = _framework_modules()
    for fw, mod in mods.items():
        res["frameworks"] += 1
        evaluate = getattr(mod, "evaluate", None)
        self_test = getattr(mod, "SELF_TEST", None)
        if evaluate is None or self_test is None:
            fails.append(f"{fw}: missing evaluate/SELF_TEST")
            continue
        # sanity: registry must point at this module's evaluate
        if REGISTRY.get(fw) is not evaluate:
            fails.append(f"{fw}: REGISTRY evaluate mismatch")

        for i, (kwargs, control_id, expected) in enumerate(self_test):
            sig = ComplianceSignal(**kwargs)
            rows = evaluate(sig)
            match = [r for r in rows if r["control"] == control_id]
            if not match:
                fails.append(f"{fw}[{i}]: control {control_id} not emitted")
                continue
            actual = match[0]["status"]
            res["selftest_checks"] += 1
            if actual != expected:
                fails.append(
                    f"{fw}[{i}]: {control_id} status {actual!r} != {expected!r}")

    # ---- L2: full pipeline with ALL frameworks -------------------------
    bundle = run_preflight(
        backend=SimulatorBackend(),
        intent="add a BGP neighbor with authentication password secret123",
        lab="clos-evpn",
        frameworks=available(),
    )
    rows = bundle["validation"]["compliance"]
    for r in rows:
        res["pipeline_rows"] += 1
        for key in ("framework", "control", "status", "evidence", "kind"):
            if key not in r:
                fails.append(f"pipeline row missing key {key!r}: {r}")
        if r.get("status") not in _VALID_STATUS:
            fails.append(f"pipeline row bad status {r.get('status')!r}: {r}")

    # schema-validate the whole sealed bundle
    schema = json.loads(_SCHEMA_PATH.read_text())
    try:
        jsonschema.validate(instance=bundle, schema=schema)
    except jsonschema.ValidationError as e:
        fails.append(f"bundle failed schema validation: {e.message}")

    return {"results": res, "sample_failures": fails[:10]}


def passed(s: dict) -> bool:
    return not s["sample_failures"]


if __name__ == "__main__":
    t0 = time.perf_counter()
    s = run()
    s["wall_sec"] = round(time.perf_counter() - t0, 2)
    print(json.dumps(s, indent=2))
    r = s["results"]
    n = r["selftest_checks"] + r["pipeline_rows"]
    m = r["frameworks"]
    ok = passed(s)
    if ok:
        print(f"\n=== COMPLIANCE TEST: PASS ({n} checks across {m} frameworks) ===")
    else:
        print(f"\n=== COMPLIANCE TEST: FAIL ({len(s['sample_failures'])} failure(s)) ===")
    sys.exit(0 if ok else 1)
