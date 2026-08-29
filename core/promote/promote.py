"""Promote a verified, approved evidence bundle to production through a connector.

Flow:  gate.evaluate(...) -> if allowed, push each device's config via the connector,
then emit a sealed PROMOTION RECORD (its own sha256) that references the source bundle's
hash — a tamper-evident audit trail linking "what was validated" to "what was pushed".

The raw approval token is never written. The record stores method + token sha256 so an
examiner can see whether G2/G3 ran HMAC or the asserted-unverified honesty tier.
"""
from __future__ import annotations
import hashlib
import json
import uuid
from datetime import datetime, timezone

from . import gate
from .connectors import ProdConnector


class PromoteDenied(Exception):
    """Gate refused the promotion. Carries the reason for the API/UI."""


def _sha256(obj: dict) -> str:
    clone = json.loads(json.dumps(obj))
    clone["integrity"]["sha256"] = ""
    return hashlib.sha256(
        json.dumps(clone, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def promote(bundle: dict, *, connector: ProdConnector, approver: str | None = None,
            approval_token: str | None = None, allow_live: bool = False) -> dict:
    configs = (bundle.get("change") or {}).get("generated_configs") or []
    if not configs:
        raise PromoteDenied("nothing to promote")

    decision = gate.evaluate(
        bundle, approver=approver, approval_token=approval_token,
        connector_is_live=getattr(connector, "live", False), allow_live=allow_live)
    if not decision.allowed:
        raise PromoteDenied(decision.reason)

    now = datetime.now(timezone.utc).isoformat()
    pushed = []
    all_ok = True
    for c in configs:
        try:
            r = connector.push(c["device"], c["vendor"], c["config"])
        except Exception as e:  # noqa: BLE001 — a connector failure is a per-device result
            r = {"pushed": False, "detail": f"{type(e).__name__}: {e}"}
        all_ok = all_ok and bool(r.get("pushed"))
        pushed.append({"device": c["device"], "vendor": c["vendor"], **r})

    record = {
        "promotion_id": uuid.uuid4().hex,
        "source_run_id": bundle["run_id"],
        "source_sha256": bundle["integrity"]["sha256"],
        "promoted_utc": now,
        "connector": "live" if getattr(connector, "live", False) else "dry_run",
        "dry_run": not getattr(connector, "live", False),
        "approver": approver,
        "approval_token_present": bool(approval_token),
        "approval": {
            "method": decision.approval_method,
            "token_sha256": decision.token_sha256,
            "bound_bundle_sha256": bundle["integrity"]["sha256"] if decision.token_sha256 else None,
        },
        "gate_reason": decision.reason,
        "status": "promoted" if all_ok else "partial",
        "pushed": pushed,
        "integrity": {"sha256": "", "generated_by": "AEGIS", "egress": "none"},
    }
    record["integrity"]["sha256"] = _sha256(record)
    return record
