"""Assemble the evidence bundle and seal it with an integrity hash.

The sha256 is computed over the canonical bundle with the `sha256` field blanked,
so the hash is reproducible and verifiable after the fact. `egress` is hard-pinned
to "none" — the structural promise that nothing left the perimeter.
"""
from __future__ import annotations
import hashlib
import json


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def compute_sha256(bundle: dict) -> str:
    """Hash of the bundle with integrity.sha256 emptied (stable, verifiable)."""
    clone = json.loads(json.dumps(bundle))
    clone["integrity"]["sha256"] = ""
    return hashlib.sha256(_canonical(clone)).hexdigest()


def verify(bundle: dict) -> bool:
    return bundle["integrity"]["sha256"] == compute_sha256(bundle)


def build_bundle(*, run_id, created, operator, intent, source, configs, batfish,
                 twin, diff, compliance, tier, needs_approval, approver,
                 approval_utc, rollback_plan, decision, reason,
                 model_identity: dict | None = None,
                 authority: dict | None = None,
                 signed: bool = False) -> dict:
    severity = _severity(diff["devices_affected"],
                         len(diff["sessions_dropped"]),
                         batfish["errors"], twin["converged"])
    bundle = {
        "bundle_version": "1.2",
        "run_id": run_id,
        "created_utc": created,
        "operator": operator,
        "change": {
            "intent": intent,
            "source": source,
            "generated_configs": [
                {"device": c["device"], "vendor": c["vendor"],
                 "config": c["config"], "grounded_commands": c["grounded_commands"]}
                for c in configs
            ],
            "risk_tier": tier,
            "approval": {
                "required": needs_approval,
                "granted_by": approver,
                "granted_utc": approval_utc,
            },
            "model_identity": (model_identity if model_identity is not None
                               else _unknown_identity()),
            "authority": (authority if authority is not None
                          else _failclosed_authority(severity)),
        },
        "twin": {
            "engine": "containerlab",
            "topology": twin["topology"],
            "node_count": twin["node_count"],
            "converged": twin["converged"],
            "convergence_sec": twin["convergence_sec"],
            "bgp_sessions": {"before": twin["bgp_before"], "after": twin["bgp_after"]},
        },
        "validation": {
            "batfish": {
                "errors": batfish["errors"], "warnings": batfish["warnings"],
                "passed": batfish["passed"], "findings": batfish["findings"],
            },
            "state_diff": {
                "routes_added": diff["routes_added"],
                "routes_removed": diff["routes_removed"],
                "sessions_dropped": diff["sessions_dropped"],
            },
            "blast_radius": {
                "devices_affected": diff["devices_affected"],
                "severity": severity,
            },
            "compliance": compliance,
        },
        "rollback": {"plan": rollback_plan, "tested_in_twin": twin["converged"]},
        "verdict": {"decision": decision, "reason": reason},
        "integrity": {
            "sha256": "",
            "signed": signed,
            "generated_by": "AEGIS",
            "egress": "none",
        },
    }
    bundle["integrity"]["sha256"] = compute_sha256(bundle)
    return bundle


def _severity(devices, dropped, errors, converged) -> str:
    if not converged or errors > 0 or dropped > 0:
        return "critical" if (not converged or errors > 0) else "high"
    if devices >= 4:
        return "high"
    if devices >= 2:
        return "medium"
    if devices >= 1:
        return "low"
    return "none"


# Fixed timestamp for synthetic identities (UNKNOWN / simulator) so stress determinism
# (INV-3: same intent -> identical bundle) holds. Real backends carry their own resolved_at.
_SYNTHETIC_RESOLVED_AT = "1970-01-01T00:00:00+00:00"


def _unknown_identity() -> dict:
    """The honest _UNKNOWN_IDENTITY for a change no model produced (config_import /
    operator-supplied) — keeps the v1.1 bundle schema-valid WITHOUT claiming authorship."""
    return {
        "provider": "none",
        "model": "operator-supplied",
        "model_hash": None,
        "model_hash_kind": "identity-claim",
        "api_version": None,
        "capabilities": [],
        "resolved_at_utc": _SYNTHETIC_RESOLVED_AT,
    }


def unattested_identity() -> dict:
    """A model DID produce this change (nl_intent) but the backend could not attest WHICH.
    Deliberately DISTINCT from _unknown_identity (operator-supplied) so a missing
    attestation can NEVER be read as 'no model was involved' (that would falsely deny AI
    authorship). provider 'unknown' + model 'unattested' make the gap auditable."""
    return {
        "provider": "unknown",
        "model": "unattested",
        "model_hash": None,
        "model_hash_kind": "identity-claim",
        "api_version": None,
        "capabilities": [],
        "resolved_at_utc": _SYNTHETIC_RESOLVED_AT,
    }


def _failclosed_authority(severity: str) -> dict:
    """Fallback when no authority was computed (a direct build_bundle call). Fail CLOSED:
    an unknown authority is BLOCK, so it can never be promoted. run_preflight always
    supplies a real record (core.risk.authority_record)."""
    return {
        "severity": severity,
        "required": "block",
        "max_authorized": "auto",
        "allowed": False,
        "effective": "block",
        "change_class": {"touches_asn": False, "touches_rd_rt": False,
                         "touches_spine": False, "touches_underlay": False},
    }
