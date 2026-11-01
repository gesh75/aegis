# D3: secret references (as built)

**Status:** Implemented 2026-10-27 (`core/secretref.py`, `tests/secretref_test.py`, 99
checks; hardened after the PR #42 review). This is decision D3 in `docs/STRATEGY_2026-10.md`. It is required in
`AEGIS_MODE=production`. Community mode without `AEGIS_SECRET_STORE` keeps the earlier
behavior, so treat those bundles as Confidential.

## What it guarantees

Once a store is configured, no credential value leaves the pipeline in any artifact. That
covers:

- the evidence bundle and its seal;
- the PDF, CAB and OSCAL exports;
- ServiceNow attachments;
- the promotion record and the ledger.

Each value is replaced by a reference:

```text
set protocols bgp group EBGP authentication-key "AEGISREF-3f9c0d2e7a41b8c6d5e4f3a2"
neighbor 10.0.0.1 password 7 AEGISREF-a1b2c3d4e5f60718293a4b5c
```

`change.secret_refs` lists each reference with its device, its kind (`plaintext`,
`reversible` or `hash`) and the detector label. The list never includes a value.

| Property | How |
|---|---|
| A reference reveals nothing about the value | The token is `HMAC-SHA256(ref_key, run_id ‖ 0x00 ‖ value)[:96 bits]`. A bare hash of a weak password could be guessed offline; a keyed one cannot. |
| A reference is bound to its run | `run_id` is inside the HMAC. The same secret in two runs gets two tokens, and a token cannot be replayed into another bundle. |
| The store cannot swap a value | Resolution re-derives the token from the stored value and refuses on a mismatch. |
| Nothing slips through | The credential patterns run on every **config-like** field: configs, grounded commands, rollback plan, findings and examples. Every value found is then scrubbed from **every free-text field**, including intent, evidence (compliance rows too), reason and descriptions. Values of 4+ characters are replaced anywhere, even inside longer tokens such as `pw-backup`. Shorter values are replaced as whole tokens only. Text inside existing references is never touched. Structural fields (enums, ids, hashes) are never rewritten. If a value would survive, the run is **rejected**, and the values this run stored are deleted. A 200-run property test checks this. |
| Only real references are trusted | Detectors, redaction and tokenization skip a value only if it is a **well-formed** `AEGISREF-<24 hex>` token. A credential that merely starts with the prefix, or is literally `<redacted>`, is still tokenized. |
| Connector output is scrubbed | If a connector echoes the pushed config (in its result or an exception), resolved values are replaced by their references before the record, the API response or the ledger see them. |
| Production never pushes clear credentials | `AEGIS_MODE=production` denies promotion of a bundle that still carries credentials in clear (sealed before D3, or by a store-less instance). Re-run the preflight. |
| The approval is not burned by an outage | References are resolved after the gate passes and **before** the single-use token is claimed. A dead vault denies the push, and the same token works once the store is back. |
| Values never touch disk in clear | The file store uses AES-256-GCM with AAD = the reference, so a file renamed to another reference fails. Files are written atomically with mode 0600, in a 0700 directory. |

## Flow

| Stage | Sees |
|---|---|
| Batfish, twin, compliance (inside the perimeter) | The **real** configuration, so validation results are unchanged |
| `protect_bundle` (end of `run_preflight`) | Tokenizes, stores the values, scrubs, runs the leak check, re-hashes |
| Seal, exports, ServiceNow, ledger | References only |
| `promote` → connector | References resolved in memory for the push only; the record keeps references |
| `postchange/verify` | A referenced line must match the running config's structure, and the key value is then **judged**. Clear text is compared directly. Cisco type 7 is decoded and compared, since it is reversible. A Cisco type digit (`0`→`7` under `service password-encryption`) is tolerated. A Junos `$9$` or a hashed running value is **unverifiable** and makes the result `partial`, never `verified`. A different key is `drift`. |

## What it does NOT do

| Not covered | Why / what to do |
|---|---|
| PCI 8.3.2 on the device | D3 protects AEGIS artifacts. A Junos box still stores the key as `$9$`, so the PCI row keeps judging the device. That needs device-side change: TCP-AO, a key-chain policy, or a hardware key store. |
| Batfish and the twin seeing placeholders | The earlier design proposed that. As built, validation runs on the real config inside the perimeter, so results are exact. Batfish snapshots are deleted after each run. |
| A credential typed **only** into prose (intent text) and never into the configuration | Running the patterns over prose misfires ("password to ..." is not a credential), so prose only gets value scrubbing. A credential the configuration carries is scrubbed from the intent too. |
| Junos `$9$` value comparison after a push | `$9$` is reversible, so a decoder is possible. It is not shipped yet, and such keys report `partial`. |
| Multi-process deployments | The ledger's single-use claim and hash chain are per-process. Run one gunicorn worker with threads, as the Dockerfile does. A shared-ledger fix is tracked separately. |
| A secret the detectors don't recognize | Tokenization uses the `evidence/secrets.py` pattern table: Cisco/FRR/EOS type 0/5/7/8/9, key-strings, OSPF/AAA keys, SNMP communities, Junos keys/secrets/PSKs/`$9$`/`$1$`/`$6$`. A vendor syntax outside that table is not tokenized. Extend the table and add a test case. |
| Key rotation of `AEGIS_SECRET_KEY` | Rotating the key orphans existing references, because their tokens no longer re-derive. At startup the file store decrypts its newest entry and **refuses to start** on a key mismatch. Promote or re-run open changes, then prune or move the old store. A dual-key rotation window is a follow-up. |

## Configuration

| Variable | Value |
|---|---|
| `AEGIS_SECRET_STORE` | `file:/var/lib/aegis/secrets` (persistent volume, 0700), or `vault:https://vault.corp:8200/v1/secret/data/aegis` (HashiCorp Vault / OpenBao KV v2) |
| `AEGIS_SECRET_KEY` | 64 hex characters: `python -c "import secrets;print(secrets.token_hex(32))"`. Keep it in your KMS, separately from the store. |
| `AEGIS_VAULT_TOKEN` | Vault token with `create`/`read` on the path (AppRole recommended). |
| `AEGIS_INTEGRATION_HOSTS` | Must list the Vault host while air-gap is on. |
| `AEGIS_SECRET_RETENTION_DAYS` | Default 30; `0` keeps entries forever. The file store prunes entries older than this at startup. Approvals expire in hours and audit needs only references, so an expired value is never needed again. For Vault, set `delete_version_after` on the mount, because AEGIS does not prune Vault. |

At startup the server checks the key against existing entries, prunes past retention,
and writes and reads back a canary entry. A bad specification, a wrong or rotated key,
or an unreachable vault stops the start, rather than failing the first change. The file
store directory must be owned by the service user. A looser existing directory is
tightened to 0700 or refused. Writes are fsync'd (file and directory). The Vault base
URL must be a KV v2 `/data/` path with no query or fragment. Delete is a metadata delete,
which removes all versions. `GET /api/status` reports `secret_refs: file | vault | off`.

Minimal Vault policy:

```hcl
path "secret/data/aegis/*" { capabilities = ["create", "update", "read"] }
```

## Tests (`tests/secretref_test.py`)

| ID | Covers |
|---|---|
| S1 | Tokenization across vendor syntaxes: idempotent, the detectors ignore references, structure kept |
| S2 | 200-run property test: no value anywhere in the bundle JSON; the bundle verifies and validates; PCI still judged on the real config; the rollback plan is tokenized; a surviving value rejects the run |
| S3 | File store: round trip, permissions, ciphertext opaque, tamper / rename / wrong key / path traversal refused |
| S4 | Vault KV v2 contract: paths, token header, 404/500 handling, perimeter rule |
| S5 | Resolve: other-run token, swapped value and missing value all refused |
| S6 | Promote: the connector gets the real config, record and ledger stay clean, deny without burning the token, replay still denied |
| S7 | Post-change matches a re-encrypted key by position |
| S8 | Configuration errors; production requires the store |
| S9 | HTTP end to end: sealed referenced bundle, clean CAB, promote resolves, values only in the store |

Review regressions (F1–F14, from the PR #42 review) cover: prefix look-alikes, short and
embedded values, findings, compliance and rollback coverage, enum safety, cleanup on
failure, connector echo, the production clear-credential deny, type-7 and `partial`
post-change results, the key-rotation refusal, retention and directory permissions.

Mutation-checked. Each of these fails the suite:

- removing the HMAC check on resolve;
- pushing unresolved text;
- trusting the prefix instead of the full token;
- dropping the connector scrub;
- skipping cleanup on failure.

Removing the bundle-wide scrub makes runs fail closed, and S2 asserts that.
