"""Promote a verified, approved evidence bundle to production through a connector.

Flow:  gate.evaluate(...) -> if allowed, push each device's config via the connector,
then emit a sealed PROMOTION RECORD (its own sha256) that references the source bundle's
hash — a tamper-evident audit trail linking "what was validated" to "what was pushed".

The raw approval token is never written. The record stores method + token sha256 so an
examiner can see whether G2/G3 ran HMAC or the asserted-unverified honesty tier.

With a ``ledger`` (evidence/ledger.py) every promotion and denial is appended to the
hash-chained audit log, and an HMAC approval token is SINGLE-USE: it is claimed
atomically before the first push, so replaying it — even after a restart, when the
ledger is file-backed — is a deny.
"""
from __future__ import annotations
import hashlib
import json
import uuid
from datetime import datetime, timezone

from . import gate
from .connectors import ProdConnector
from .. import secretref


class PromoteDenied(Exception):
    """Gate refused the promotion. Carries the reason for the API/UI."""


def _sha256(obj: dict) -> str:
    clone = json.loads(json.dumps(obj))
    clone["integrity"]["sha256"] = ""
    return hashlib.sha256(
        json.dumps(clone, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def promote(bundle: dict, *, connector: ProdConnector, approver: str | None = None,
            approval_token: str | None = None, allow_live: bool = False,
            live_inventory_sha256: str | None = None, ledger=None,
            seal: dict | None = None, verifier=None, require_seal: bool = False,
            require_verified_approval: bool = False, secret_store=None) -> dict:
    configs = (bundle.get("change") or {}).get("generated_configs") or []
    if not configs:
        raise PromoteDenied("nothing to promote")

    decision = gate.evaluate(
        bundle, approver=approver, approval_token=approval_token,
        connector_is_live=getattr(connector, "live", False), allow_live=allow_live,
        live_inventory_sha256=live_inventory_sha256, seal=seal, verifier=verifier,
        require_seal=require_seal, require_verified_approval=require_verified_approval)
    run_id = bundle.get("run_id")
    src_sha = (bundle.get("integrity") or {}).get("sha256")
    if not decision.allowed:
        if ledger is not None:
            ledger.append("promotion_denied", run_id=run_id, source_sha256=src_sha,
                          approver=approver, reason=decision.reason)
        raise PromoteDenied(decision.reason)

    # D3: resolve secret references AFTER the gate and BEFORE the token is claimed, so a
    # store outage or a tampered value denies without burning the single-use approval.
    # Resolved text lives only in memory for the push; it is never recorded or ledgered.
    push_text: dict[int, str] = {}
    if any(secretref.has_refs(c.get("config", "")) for c in configs):
        why = None
        if secret_store is None:
            why = "bundle carries secret references but no secret store is configured"
        else:
            try:
                push_text = {i: secretref.resolve_text(c["config"], run_id=str(run_id),
                                                       store=secret_store)
                             for i, c in enumerate(configs)}
            except secretref.SecretStoreError as exc:
                why = f"secret references could not be resolved: {exc}"
        if why:
            if ledger is not None:
                ledger.append("promotion_denied", run_id=run_id, source_sha256=src_sha,
                              approver=approver, reason=why)
            raise PromoteDenied(why)

    # single-use approval: claim BEFORE the first push so two concurrent promotions with
    # one token cannot both proceed. A failed push still burns the token (re-approve).
    if ledger is not None and decision.approval_method == "hmac-sha256" and decision.token_sha256:
        if not ledger.claim_token(decision.token_sha256, run_id=run_id,
                                  source_sha256=src_sha, approver=approver):
            reason = "approval token already used — tokens are single-use (replay denied)"
            ledger.append("promotion_denied", run_id=run_id, source_sha256=src_sha,
                          approver=approver, reason=reason)
            raise PromoteDenied(reason)

    now = datetime.now(timezone.utc).isoformat()
    pushed = []
    all_ok = True
    for i, c in enumerate(configs):
        try:
            r = connector.push(c["device"], c["vendor"], push_text.get(i, c["config"]))
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
            "live_inventory_sha256": live_inventory_sha256 or None,
        },
        "gate_reason": decision.reason,
        "status": "promoted" if all_ok else "partial",
        "pushed": pushed,
        "integrity": {"sha256": "", "generated_by": "AEGIS", "egress": "none"},
    }
    record["integrity"]["sha256"] = _sha256(record)
    if ledger is not None:
        ledger.append("promotion", promotion_id=record["promotion_id"], run_id=run_id,
                      source_sha256=src_sha, record_sha256=record["integrity"]["sha256"],
                      connector=record["connector"], status=record["status"],
                      approver=approver, approval_method=decision.approval_method)
    return record
