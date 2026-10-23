"""OSCAL-shaped Assessment Results export.

Honest: this is an AEGIS-shaped AR JSON, not a FedRAMP authorization package.
It maps one PreFlight bundle onto NIST OSCAL 1.1.2 *structure* so a GRC tool
can ingest control rows. It does not claim FedRAMP, CMMC, or agency ATOs.

integrity.sha256 is self-consistency. Authenticity is the detached seal.
"""
from __future__ import annotations
import uuid as _uuid


OSCAL_VERSION = "1.1.2"
EXPORT_KIND = "aegis-oscal-ar-v1"
# Stable namespace so the same run always maps to the same RFC 4122 UUIDs (OSCAL
# requires real UUIDs; deterministic v5 keeps re-exports idempotent for GRC ingest).
_NS = _uuid.UUID("6f2a8f0e-4b1c-5d3a-9e7f-a1e9a5e0c0de")


def _u(*parts: str) -> str:
    return str(_uuid.uuid5(_NS, "/".join(parts)))


def _run_uuid(run: str) -> str:
    """The run's own UUID in RFC 4122 form (run_id is uuid4().hex); v5 fallback otherwise."""
    try:
        return str(_uuid.UUID(hex=run))
    except ValueError:
        return _u(run)


def _compliance_rows(bundle: dict) -> list:
    """Canonical path is validation.compliance (bundle schema v1.2)."""
    val = bundle.get("validation")
    if isinstance(val, dict) and "compliance" in val:
        return list(val.get("compliance") or [])
    return list(bundle.get("compliance") or [])


def _intent(bundle: dict) -> str:
    ch = bundle.get("change") if isinstance(bundle.get("change"), dict) else {}
    return str(bundle.get("intent") or ch.get("intent") or "")


def to_oscal(bundle: dict, authenticity: str | None = None) -> dict:
    """Pure function. Does not verify the bundle — callers must bundler.verify first.
    ``authenticity`` is the caller's seal verdict; it is carried in the result remarks."""
    run = str(bundle.get("run_id") or "bundle")
    created = str(bundle.get("created_utc") or bundle.get("created") or "")
    intent = _intent(bundle)
    rows = _compliance_rows(bundle)
    verdict = bundle.get("verdict") or {}
    twin = bundle.get("twin") or {}
    integrity = bundle.get("integrity") or {}
    seal = bundle.get("seal")
    ch_ref = (bundle.get("change") or {}).get("change_ref") if isinstance(bundle.get("change"), dict) else None
    findings = []
    observations = []
    for i, c in enumerate(rows):
        fw = str(c.get("framework") or "")
        cid = str(c.get("control") or "")
        status = str(c.get("status") or "")
        evidence = str(c.get("evidence") or "")
        kind = str(c.get("kind") or "")
        obs_uuid = _u(run, "obs", str(i))
        observations.append({
            "uuid": obs_uuid,
            "description": f"{fw} {cid}: {status} — {evidence}",
            "methods": ["TEST" if kind == "config-checked" else "EXAMINE"],
            "collected": created,
        })
        if status == "fail":
            findings.append({
                "uuid": _u(run, "find", str(len(findings))),
                "title": f"{fw} {cid} failed",
                "description": evidence,
                "target": {"type": "objective-id", "target-id": cid,
                           "status": {"state": "not-satisfied"}},
                "related-observations": [{"observation-uuid": obs_uuid}],
                "related-controls": [{"control-id": cid}],
            })
    seal_alg = None
    if isinstance(seal, dict):
        seal_alg = ((seal.get("signature") or {}).get("alg"))
    twin_id = twin.get("twin_id") or twin.get("topology") or ""
    return {
        "kind": EXPORT_KIND,
        "assessment-results": {
            "uuid": _run_uuid(run),
            "metadata": {
                "title": "AEGIS PreFlight Assessment Results",
                "oscal-version": OSCAL_VERSION,
                "published": created,
                "last-modified": created,
                "version": "0.3.0",
                "props": [p for p in (
                    {"name": "aegis-run-id", "value": run},
                    {"name": "change-ref", "value": str(ch_ref)} if ch_ref else None,
                ) if p],
                "remarks": (
                    "AEGIS-shaped OSCAL AR export. Not a FedRAMP authorization package. "
                    "integrity.sha256 is self-consistency; authenticity is the detached seal."
                ),
            },
            "import-ap": {"href": "#aegis-preflight-assessment-plan"},
            "results": [{
                "uuid": _u(run, "result"),
                "title": f"PreFlight {run}",
                "description": intent,
                "start": created,
                "reviewed-controls": {
                    "remarks": f"{len(rows)} controls across AEGIS framework modules",
                    "control-selections": [{
                        "include-controls": [
                            {
                                "control-id": str(c.get("control") or ""),
                                "remarks": f"{c.get('framework')} · {c.get('status')}",
                            }
                            for c in rows
                        ],
                    }],
                },
                "observations": observations,
                "findings": findings,
                "remarks": "\n".join([
                    f"verdict: {verdict.get('decision')} — {verdict.get('reason')}",
                    f"twin: {twin_id} converged={twin.get('converged')}",
                    f"integrity.sha256: {integrity.get('sha256')}",
                    f"seal: {seal_alg or 'null'}",
                    f"authenticity: {authenticity or 'not evaluated by caller'}",
                    f"egress: {integrity.get('egress')}",
                ]),
            }],
        },
    }
