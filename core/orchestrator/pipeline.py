"""AEGIS deterministic preflight pipeline.

intent -> guard -> generate(LLM) -> batfish -> intent checks (optional) -> spawn twin
       -> apply+converge -> diff -> compliance map -> risk tier -> rollback -> verdict
       -> evidence bundle

The only non-deterministic / AI step is generate_config (inside the backend). Every
step after it is verification. The twin is ALWAYS torn down (finally). The result is a
schema-valid evidence bundle whose integrity hash covers the whole record.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone

from ..backends.base import Backend, GeneratedConfig
from . import guards, rollback
from ...evidence.bundler import build_bundle, unattested_identity
from ..risk import (Tier, authority_record, classify_change, load_max_authorized,
                    requires_approval, unify_severity)
from ..intents.runner import run_intents
from ...evidence.compliance import map_controls


class PreflightError(Exception):
    """Raised only for guard rejections; everything else lands in a bundle."""


def run_preflight(intent: str, *, backend: Backend, lab: str = "clos-evpn",
                  frameworks: list[str] | None = None,
                  operator: str = "unknown",
                  source: str = "nl_intent",
                  approver: str | None = None,  # an unverified claim: never an approval (step 8)
                  imported_configs: list[dict] | None = None,
                  model_identity: dict | None = None,
                  change_ref: str | None = None,
                  intents: list[dict] | None = None,
                  intent_runner=None,
                  inventory_lookup=None) -> dict:
    frameworks = frameworks or ["pci_dss_v4"]
    run_id = uuid.uuid4().hex
    created = datetime.now(timezone.utc).isoformat()

    # 1. guard ------------------------------------------------------------
    if source == "config_import":
        if not imported_configs:
            raise PreflightError("config_import requires at least one config")
        if sum(len(c.get("config", "")) for c in imported_configs) > 200_000:
            raise PreflightError("imported config exceeds 200k chars")
        intent = intent or f"config-import: {len(imported_configs)} device(s)"
    else:
        pc = guards.precheck_intent(intent)
        if not pc.ok:
            raise PreflightError(pc.reason)

    twin_id = None
    try:
        # 2. obtain candidate config --------------------------------------
        #    nl_intent -> LLM proposes;  config_import -> operator supplies (no LLM)
        if source == "config_import":
            configs = [GeneratedConfig(
                device=c.get("device") or f"{lab}-import-{i+1}",
                vendor=c.get("vendor") or "frr",
                config=c.get("config", ""),
                grounded_commands=["operator-supplied"],
            ) for i, c in enumerate(imported_configs)]
        else:
            configs = backend.generate_config(intent, lab)

        # 2b. source of truth (NetBox): roles raise authority, the rev is sealed ----
        #     ``inventory_lookup(device_names) -> {roles, inventory_rev, missing}``; it may
        #     raise PreflightError (e.g. production refuses to run without NetBox).
        inventory = (inventory_lookup([c["device"] for c in configs])
                     if inventory_lookup else None)

        # 3. static analysis ----------------------------------------------
        bf = backend.batfish_check(configs)

        # 3b. intent checks (reachability / ACL / BGP / references) ---------
        #     Before/after differential against the reference snapshot. A failed OR
        #     un-evaluable intent counts as a verification error (fail closed).
        intent_record = None
        if intents:
            intent_record = (intent_runner or run_intents)(intents, configs)
        intent_problems = (intent_record["failed"] + intent_record["errors"]
                           if intent_record else 0)
        verify_errors = bf["errors"] + intent_problems

        # 4. spawn throwaway twin -----------------------------------------
        twin_id = backend.spawn_twin(lab)

        # 5. apply + converge ---------------------------------------------
        twin = backend.apply_and_converge(twin_id, configs)

        # 6. before/after diff --------------------------------------------
        diff = backend.state_diff(twin_id)

        # 7. compliance mapping -------------------------------------------
        compliance = map_controls(configs, bf, frameworks, twin=twin, diff=diff,
                                  intent=intent or "", source=source)

        # 8. risk tier ----------------------------------------------------
        tier = guards.risk_tier(
            batfish_errors=verify_errors,
            devices_affected=diff["devices_affected"],
            sessions_dropped=len(diff["sessions_dropped"]),
            converged=twin["converged"],
        )
        # authority tier (#5): orthogonal to risk_tier -- a twin-clean LOW-severity change
        # to a fabric-identity construct (AS/RD/RT) is still BLOCK. Sealed + enforced at G5.
        # Computed BEFORE the verdict (YzNoXPaU): a change whose required authority is HITL
        # or HOTL needs a person's approval whatever its risk tier, so the sealed
        # approval.required and the verdict must say so -- as the promotion gate will.
        authority = authority_record(
            unify_severity(batfish_errors=verify_errors,
                           devices_affected=diff["devices_affected"],
                           sessions_dropped=len(diff["sessions_dropped"]),
                           converged=twin["converged"]),
            classify_change(configs, roles=(inventory or {}).get("roles")),
            load_max_authorized(),
        )
        needs_approval = (guards.approval_required(tier)
                          or requires_approval(Tier[authority["required"].upper()]))
        # Approval is granted ONLY at promotion, by an HMAC token bound to this sealed
        # bundle (mbDZXhDK). A run-time ``approver`` is a claim nobody verified: it never
        # flips the verdict and is never sealed as granted_by. (The caller may log it.)
        approval_granted = False

        # 9. rollback plan ------------------------------------------------
        plan = rollback.build_rollback_plan(configs)

        # 10. verdict -----------------------------------------------------
        decision, reason = _verdict(bf, twin, tier, needs_approval,
                                    approval_granted, intent_record)

        # seal WHICH model produced the change (#4 wedge). config_import is operator-
        # supplied (no model) -> None -> build_bundle seals the honest _UNKNOWN_IDENTITY.
        # nl_intent ALWAYS went through a model (generate_config), so the backend MUST
        # attest which; if it cannot, seal an explicit UNATTESTED marker -- NEVER the
        # operator-supplied identity (that would falsely deny model authorship).
        if model_identity is not None:
            mi = model_identity
        elif source == "config_import":
            mi = None
        else:
            attested = backend.model_identity() if hasattr(backend, "model_identity") else None
            mi = attested if attested is not None else unattested_identity()

        return build_bundle(
            run_id=run_id, created=created, operator=operator, intent=intent,
            source=source, configs=configs, batfish=bf, twin=twin, diff=diff,
            compliance=compliance, tier=tier, needs_approval=needs_approval,
            approver=None, approval_utc=None,
            rollback_plan=plan, decision=decision, reason=reason,
            model_identity=mi, authority=authority, change_ref=change_ref,
            intents=intent_record, verify_errors=verify_errors,
            inventory=inventory,
        )
    finally:
        if twin_id is not None:
            backend.teardown_twin(twin_id)


def _verdict(bf, twin, tier, needs_approval, approval_granted, intent_record=None):
    if bf["errors"] > 0:
        return "blocked", f"static analysis found {bf['errors']} error(s)"
    if intent_record and (intent_record["failed"] or intent_record["errors"]):
        bad = [r["id"] for r in intent_record["results"] if r["status"] != "pass"]
        reg = intent_record.get("regressions") or 0
        return "blocked", (f"intent check: {intent_record['failed']} failed, "
                           f"{intent_record['errors']} not evaluable"
                           + (f", {reg} regression(s) vs reference" if reg else "")
                           + f" ({', '.join(bad[:5])}{'…' if len(bad) > 5 else ''})")
    if not twin["converged"]:
        return "blocked", "twin failed to converge after change"
    if twin["bgp_after"] < twin["bgp_before"]:
        return "blocked", (f"BGP sessions dropped "
                           f"{twin['bgp_before']}->{twin['bgp_after']} in twin")
    if needs_approval and not approval_granted:
        return "needs_approval", f"{tier}-risk change awaiting human approval"
    return "ship_ready", f"{tier}-risk change verified in twin, no regressions"
