"""OSCAL-shaped Assessment Results export.

Honest: this is an AEGIS-shaped AR JSON, not a FedRAMP authorization package.
It maps one PreFlight bundle onto NIST OSCAL 1.1.2 *structure* so a GRC tool
can ingest control rows. It does not claim FedRAMP, CMMC, or agency ATOs.

integrity.sha256 is self-consistency. Authenticity is the detached seal.
"""
from __future__ import annotations


OSCAL_VERSION = "1.1.2"
EXPORT_KIND = "aegis-oscal-ar-v1"


def _compliance_rows(bundle: dict) -> list:
    """Canonical path is validation.compliance (bundle schema v1.2)."""
    val = bundle.get("validation")
    if isinstance(val, dict) and "compliance" in val:
        return list(val.get("compliance") or [])
    return list(bundle.get("compliance") or [])


def _intent(bundle: dict) -> str:
    ch = bundle.get("change") if isinstance(bundle.get("change"), dict) else {}
    return str(bundle.get("intent") or ch.get("intent") or "")


def to_oscal(bundle: dict) -> dict:
    """Pure function. Does not verify the bundle — callers must bundler.verify first."""
    run = str(bundle.get("run_id") or "bundle")
    created = str(bundle.get("created_utc") or bundle.get("created") or "")
    intent = _intent(bundle)
    rows = _compliance_rows(bundle)
    verdict = bundle.get("verdict") or {}
    twin = bundle.get("twin") or {}
    integrity = bundle.get("integrity") or {}
    seal = bundle.get("seal")
    findings = []
    observations = []
    for i, c in enumerate(rows):
        fw = str(c.get("framework") or "")
        cid = str(c.get("control") or "")
        status = str(c.get("status") or "")
        evidence = str(c.get("evidence") or "")
        kind = str(c.get("kind") or "")
        observations.append({
            "uuid": f"{run}-obs-{i}",
            "description": f"{fw} {cid}: {status} — {evidence}",
            "methods": ["TEST" if kind == "config-checked" else "EXAMINE"],
        })
        if status == "fail":
            findings.append({
                "uuid": f"{run}-find-{len(findings)}",
                "title": f"{fw} {cid} failed",
                "description": evidence,
                "related-controls": [{"control-id": cid}],
            })
    seal_alg = None
    if isinstance(seal, dict):
        seal_alg = ((seal.get("signature") or {}).get("alg"))
    twin_id = twin.get("twin_id") or twin.get("topology") or ""
    return {
        "kind": EXPORT_KIND,
        "assessment-results": {
            "uuid": run,
            "metadata": {
                "title": "AEGIS PreFlight Assessment Results",
                "oscal-version": OSCAL_VERSION,
                "published": created,
                "version": "0.2.0",
                "remarks": (
                    "AEGIS-shaped OSCAL AR export. Not a FedRAMP authorization package. "
                    "integrity.sha256 is self-consistency; authenticity is the detached seal."
                ),
            },
            "results": [{
                "uuid": f"{run}-result",
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
                    f"egress: {integrity.get('egress')}",
                ]),
            }],
        },
    }
