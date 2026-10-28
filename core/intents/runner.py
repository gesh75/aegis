"""Default intent runner: Batfish when configured, fail-closed otherwise.

  AEGIS_BATFISH_HOST          in-perimeter Batfish service (batfish/allinone), e.g. 127.0.0.1
  AEGIS_BATFISH_SNAPSHOT_DIR  reference snapshot (device config backup) — enables before/after
  AEGIS_BATFISH_NETWORK       Batfish network name (default "aegis")

Unset host, missing pybatfish, or an engine error → every requested intent is an ``error``
row and the verdict blocks. Intents are never silently skipped.
"""
from __future__ import annotations

import os

from .engine import check_intents
from .snapshot import SnapshotError, materialize, read_base


def run_intents(intents: list[dict], configs: list[dict], replace: bool = False) -> dict:
    """``replace=True`` (post-change): configs are complete running configs, never merged."""
    host = (os.environ.get("AEGIS_BATFISH_HOST") or "").strip()
    if not host:
        return check_intents(intents, candidate=None,
                             unavailable_reason="AEGIS_BATFISH_HOST is not set")
    try:
        from .batfish_oracle import BatfishSnapshots
    except ImportError:
        return check_intents(intents, candidate=None,
                             unavailable_reason="pybatfish is not installed "
                                                "(pip install -r requirements-batfish.txt)")
    try:
        base = read_base(os.environ.get("AEGIS_BATFISH_SNAPSHOT_DIR") or None)
        reference, candidate, log = materialize(configs, base, replace=replace)
    except OSError as exc:
        return check_intents(intents, candidate=None,
                             unavailable_reason=f"reference snapshot unreadable: "
                                                f"{type(exc).__name__}")
    except SnapshotError as exc:   # duplicate device / config not shown complete
        return check_intents(intents, candidate=None,
                             unavailable_reason=f"candidate snapshot rejected: {exc}")
    snap_meta = {"reference": reference is not None, "merge": log,
                 "reference_files": len(reference or {}), "candidate_files": len(candidate)}
    try:
        with BatfishSnapshots(host, os.environ.get("AEGIS_BATFISH_NETWORK") or "aegis",
                              reference, candidate) as (ref_oracle, cand_oracle):
            return check_intents(intents, candidate=cand_oracle, reference=ref_oracle,
                                 engine="batfish", snapshot=snap_meta)
    except Exception as exc:  # noqa: BLE001 — engine down / snapshot rejected → fail closed
        return check_intents(intents, candidate=None, snapshot=snap_meta,
                             unavailable_reason=f"batfish error: {type(exc).__name__}: "
                                                f"{str(exc)[:200]}")
