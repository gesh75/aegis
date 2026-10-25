"""ServiceNow change_request sync: attach the AEGIS verdict to the CHG and hold blocked ones.

Configuration (all env, never in the bundle or the ledger):

  AEGIS_SNOW_URL              https://<instance>.service-now.com, or your in-perimeter proxy/MID
  AEGIS_SNOW_TOKEN            OAuth bearer token (preferred), or
  AEGIS_SNOW_USER / AEGIS_SNOW_PASSWORD   basic auth for an integration user
  AEGIS_SNOW_VERDICT_FIELD    custom field that receives the decision (default u_aegis_verdict;
                              set to "" to skip it if the field does not exist)
  AEGIS_SNOW_HOLD_ON_BLOCKED  1 (default): a blocked verdict sets on_hold + on_hold_reason

What one ``sync`` does, using the Table and Attachment REST APIs:

  1. GET    /api/now/table/change_request?number=<change_ref>   exactly one match, or fail
  2. POST   /api/now/attachment/file   the redacted examiner PDF + a verdict summary JSON.
            The bundle JSON is NOT sent: it carries the candidate config (decision D3).
  3. PATCH  /api/now/table/change_request/<sys_id>   work note, verdict field and, when
            blocked, on_hold. AEGIS never changes state/approval itself. Hard CAB
            enforcement is a ServiceNow business rule on the verdict field (docs/INTEGRATIONS.md).

The CHG number comes from the SEALED bundle (``change.change_ref``), never from the request,
so a verdict can only land on the ticket it was sealed against.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx

from . import IntegrationError, assert_integration_url

_TIMEOUT = httpx.Timeout(15.0, connect=5.0)
# "^" is the encoded-query separator; a ref must never be able to widen the query
_NUMBER = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


def configured() -> bool:
    return bool((os.environ.get("AEGIS_SNOW_URL") or "").strip())


def verdict_summary(bundle: dict) -> dict:
    """What ITSM needs, and nothing else: no configs, no secrets."""
    v = bundle.get("verdict") or {}
    ch = bundle.get("change") or {}
    ints = (bundle.get("validation") or {}).get("intents") or {}
    seal = bundle.get("seal") or {}
    return {
        "aegis_run_id": bundle.get("run_id"),
        "change_ref": ch.get("change_ref"),
        "decision": v.get("decision"),
        "reason": v.get("reason"),
        "risk_tier": ch.get("risk_tier"),
        "authority_required": (ch.get("authority") or {}).get("required"),
        "intents": ({"failed": ints.get("failed"), "errors": ints.get("errors"),
                     "regressions": ints.get("regressions")} if ints else None),
        "bundle_sha256": (bundle.get("integrity") or {}).get("sha256"),
        "seal_key_id": seal.get("key_id"),
        "created_utc": bundle.get("created_utc"),
        "operator": bundle.get("operator"),
    }


class ServiceNowClient:
    def __init__(self, base_url: str | None = None, *, token: str | None = None,
                 user: str | None = None, password: str | None = None,
                 transport: httpx.BaseTransport | None = None) -> None:
        url = base_url if base_url is not None else os.environ.get("AEGIS_SNOW_URL", "")
        self.base = assert_integration_url("servicenow", url)
        token = token if token is not None else (os.environ.get("AEGIS_SNOW_TOKEN") or "")
        user = user if user is not None else (os.environ.get("AEGIS_SNOW_USER") or "")
        password = (password if password is not None
                    else (os.environ.get("AEGIS_SNOW_PASSWORD") or ""))
        headers = {"Accept": "application/json"}
        auth = None
        if token.strip():
            headers["Authorization"] = f"Bearer {token.strip()}"
        elif user and password:
            auth = httpx.BasicAuth(user, password)
        else:
            raise IntegrationError("servicenow: set AEGIS_SNOW_TOKEN or "
                                   "AEGIS_SNOW_USER + AEGIS_SNOW_PASSWORD")
        # trust_env=False: never pick up a proxy from the environment, only the declared host
        self._http = httpx.Client(base_url=self.base, headers=headers, auth=auth,
                                  timeout=_TIMEOUT, transport=transport, trust_env=False,
                                  follow_redirects=False)

    def close(self) -> None:
        self._http.close()

    def _call(self, method: str, path: str, **kw) -> Any:
        try:
            r = self._http.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise IntegrationError(f"servicenow: {type(exc).__name__} on {method} "
                                   f"{path.split('?')[0]}") from exc
        if r.status_code >= 400:
            # never echo the body: instance error pages can carry session details
            raise IntegrationError(f"servicenow: HTTP {r.status_code} on {method} "
                                   f"{path.split('?')[0]}")
        try:
            return r.json().get("result")
        except (ValueError, AttributeError) as exc:
            raise IntegrationError(f"servicenow: non-JSON reply on {method} "
                                   f"{path.split('?')[0]}") from exc

    def find_change(self, number: str) -> dict:
        if not _NUMBER.match(number or ""):
            raise IntegrationError("servicenow: change_ref is not a plain ticket number")
        res = self._call("GET", "/api/now/table/change_request", params={
            "sysparm_query": f"number={number}", "sysparm_limit": "2",
            "sysparm_fields": "sys_id,number,state,approval,on_hold"})
        rows = res if isinstance(res, list) else []
        if len(rows) != 1 or rows[0].get("number") != number:
            raise IntegrationError(f"servicenow: change {number} not found "
                                   f"({len(rows)} match(es))")
        return rows[0]

    def attach(self, sys_id: str, file_name: str, content: bytes, content_type: str) -> str:
        res = self._call("POST", "/api/now/attachment/file", params={
            "table_name": "change_request", "table_sys_id": sys_id, "file_name": file_name},
            content=content, headers={"Content-Type": content_type})
        return str((res or {}).get("sys_id") or "")

    def update_change(self, sys_id: str, fields: dict) -> dict:
        return self._call("PATCH", f"/api/now/table/change_request/{sys_id}",
                          json=fields) or {}

    def sync(self, bundle: dict, pdf: bytes) -> dict:
        """Attach + annotate the CHG the bundle was sealed against. Returns a ledger-safe
        record (sys_ids, decision, what was set). Raises IntegrationError, fail closed."""
        summary = verdict_summary(bundle)
        number = str(summary["change_ref"] or "").strip()
        if not number:
            raise IntegrationError("servicenow: bundle has no change_ref; cannot pick a CHG")
        chg = self.find_change(number)
        sys_id = str(chg.get("sys_id") or "")
        slug = str(summary["aegis_run_id"] or "run")[:12]
        att_pdf = self.attach(sys_id, f"aegis-{slug}.pdf", pdf, "application/pdf")
        att_json = self.attach(sys_id, f"aegis-{slug}-verdict.json",
                               json.dumps(summary, indent=2, sort_keys=True).encode(),
                               "application/json")
        decision = str(summary["decision"] or "unknown")
        note = (f"[AEGIS] verdict: {decision.upper()}. {summary['reason'] or ''}\n"
                f"run {summary['aegis_run_id']}, bundle sha256 {summary['bundle_sha256']}, "
                f"seal key {summary['seal_key_id'] or 'none'}. "
                "Verify offline: python -m aegis.verify --bundle <file> --seal <file>")
        fields: dict = {"work_notes": note}
        vf = os.environ.get("AEGIS_SNOW_VERDICT_FIELD", "u_aegis_verdict").strip()
        if vf:
            fields[vf] = decision
        hold = (decision == "blocked"
                and os.environ.get("AEGIS_SNOW_HOLD_ON_BLOCKED", "1").strip() != "0")
        if hold:
            fields["on_hold"] = "true"
            fields["on_hold_reason"] = f"AEGIS preflight blocked: {summary['reason'] or ''}"[:250]
        self.update_change(sys_id, fields)
        return {"change_ref": number, "change_sys_id": sys_id, "decision": decision,
                "attachments": [a for a in (att_pdf, att_json) if a],
                "verdict_field": vf or None, "on_hold": hold}
