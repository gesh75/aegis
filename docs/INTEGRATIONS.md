# Integrations: ServiceNow, NetBox, post-change verification

Every integration is **off** until it is configured. Every call is an explicit,
operator-triggered, ledgered API request, never a side effect of a preflight run. The
sealed `integrity.egress: "none"` describes the preflight run, and it stays true.

Status: contract-tested against mock HTTP servers (`tests/integrations_test.py`, 69
checks) that mirror the ServiceNow Table/Attachment REST APIs and the NetBox
`/api/dcim/devices/` API. **Not yet exercised against a live One Call instance.** That
needs the instance URL, a service account and a CHG test record (see "Pilot checklist").

## Perimeter rule (applies to every integration)

| Setting | Effect |
|---|---|
| Default (air-gap on) | The URL must be loopback, or its host must be listed in `AEGIS_INTEGRATION_HOSTS`, for example `snow-mid.corp.example,netbox.corp.example`. That list is your declaration that the host is inside the perimeter. AEGIS never resolves DNS to decide. |
| `AEGIS_AIRGAP=0` | Any https host is allowed. This needs a separate risk acceptance. |
| Always | Plain `http://` only to loopback. Credentials in the URL are refused. Redirects are not followed. Proxy environment variables are ignored. |
| Always | `AEGIS_API_KEY` is required: an unauthenticated server never writes to ITSM. |

## ServiceNow: attach the verdict, hold blocked changes

`POST /api/integrations/servicenow/sync`. The body is the evidence bundle exactly as
`/api/preflight/run` returned it.

| Step | API | What |
|---|---|---|
| 1 | `GET /api/now/table/change_request?sysparm_query=number=<change_ref>` | Exactly one CHG, taken from the **sealed** `change.change_ref`. It is never taken from the request. An encoded-query character (`^`) is refused. |
| 2 | `POST /api/now/attachment/file` (×2) | The redacted examiner PDF, plus `aegis-<run>-verdict.json` (decision, reason, risk, intents summary, bundle sha256, seal key id). **The bundle JSON is not sent**, because it still carries the candidate config (decision D3). |
| 3 | `PATCH /api/now/table/change_request/<sys_id>` | A work note with the verdict, run id, sha256, seal key and offline-verify command. `u_aegis_verdict` = decision. When blocked: `on_hold=true` plus `on_hold_reason`. |

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_SNOW_URL` | — | The instance, or your in-perimeter proxy/MID endpoint |
| `AEGIS_SNOW_TOKEN` | — | OAuth bearer (preferred) |
| `AEGIS_SNOW_USER` / `AEGIS_SNOW_PASSWORD` | — | Basic auth for an integration user (alternative) |
| `AEGIS_SNOW_VERDICT_FIELD` | `u_aegis_verdict` | The custom field that receives the decision. Set `""` to skip it. |
| `AEGIS_SNOW_HOLD_ON_BLOCKED` | `1` | A blocked verdict puts the CHG on hold |

AEGIS never changes `state` or `approval` itself. **Hard CAB enforcement belongs in
ServiceNow**, so the change platform owns its own workflow. Example business rule
(*before update* on `change_request`, condition: State changes to Scheduled or Implement):

```javascript
// Block scheduling/implementation unless the latest AEGIS verdict allows it.
if (current.u_aegis_verdict == 'blocked' || current.u_aegis_verdict.nil()) {
    gs.addErrorMessage('AEGIS preflight verdict is ' +
        (current.u_aegis_verdict.nil() ? 'missing' : 'BLOCKED') +
        ' — attach a passing AEGIS run before scheduling this change.');
    current.setAbortAction(true);
}
```

The service account needs read on `change_request`, write on the work notes, the verdict
field, `on_hold` and `on_hold_reason`, and create on `sys_attachment` for `change_request`.

Responses:

- **200**: a record of sys_ids and what was set (ledgered as `itsm_synced`).
- **422**: tampered or forged bundle.
- **502**: a ServiceNow error. The status is returned, never the instance's response body. It is ledgered as `itsm_sync_failed`.
- **503**: the integration is not configured, or `AEGIS_API_KEY` is unset.

## NetBox: roles for the authority model, sealed inventory revision

When `AEGIS_NETBOX_URL` and `AEGIS_NETBOX_TOKEN` are set, every preflight run looks up its
target devices (`GET /api/dcim/devices/?name=...`):

| Output | Where | Effect |
|---|---|---|
| Device role | `twin.device_roles` | A role in `AEGIS_NETBOX_SPINE_ROLES` (default `spine,super-spine`) sets `touches_spine`. A role in `AEGIS_NETBOX_UNDERLAY_ROLES` (default `super-spine,underlay,core`) sets `touches_underlay`. Roles only **add** flags on top of the name/protocol heuristic; they never clear one. |
| `inventory_rev` = `netbox:<sha256>` over the sorted name, role, status, primary IP and last_updated | `twin.inventory_rev` | Sealed in the bundle and folded into the v2 approval token's inventory digest. At promotion the server re-queries NetBox for the bundle's devices and recomputes the digest from the live revision (a value in the promote request is ignored). If NetBox changed between approval and push, the promotion is denied (403); if NetBox cannot answer, it is denied (503) and the token is not spent. |

Without `AEGIS_NETBOX_URL` there is no live source: the approval's inventory claim is not re-checked and the promotion record says `approval.inventory_verified: false` (`inventory_source: "none"`). Only a server-derived NetBox value is recorded as `inventory_verified: true`. A bundle sealed without NetBox cannot be promoted after NetBox is switched on (its inventory claim no longer matches); re-run it.

If NetBox is unreachable, production rejects the run (fail closed, ledgered as
`preflight_rejected`). The community tier records `netbox:unavailable` and falls back to
the heuristic. Both NetBox 3.x (`device_role`) and 4.x (`role`) are handled.

## Post-change verification

`POST /api/postchange/verify` with
`{"bundle": <sealed bundle>, "running_configs": [{"device", "vendor", "config"}], "intents"?: [...]}`.
Collect the running configs after the push. For Junos, `show configuration | display set`
or the hierarchical form is fine.

| Check | Rule |
|---|---|
| Applied | Junos: each `set` line is present, and each `delete` path is absent. Others: each line is present after whitespace normalization, and each `no X` means `X` is absent. This checks line presence, not position. |
| Intents | The org baseline (`AEGIS_INTENTS_PATH`) plus any supplied intents, evaluated by Batfish against the running configs as full files (no merge) |
| Status | `verified` · `drift` (a line is missing, still present, or a device has no running config) · `failed` (an intent fails or cannot be evaluated) · `unverifiable` (nothing checkable). It is never "verified" by default. |

Only a bundle sealed by **this** AEGIS (pinned key) is accepted. The result is ledgered
as `postchange_verified` with its `record_sha256`.

## Pilot checklist (what is needed from One Call)

| Item | Owner | Status |
|---|---|---|
| ServiceNow instance or MID endpoint URL, listed in `AEGIS_INTEGRATION_HOSTS` | ITSM platform team | Unknown |
| OAuth client or integration user with the ACLs above | ITSM platform team | Unknown |
| `u_aegis_verdict` field + business rule on `change_request` | ITSM platform team | Not created |
| NetBox URL + read-only token; confirm role slugs for spine/core | Network automation | Unknown |
| One test CHG in a sub-production instance | Change management | Unknown |
