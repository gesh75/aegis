# AEGIS — Developer & operator notes

Concise contracts for the subsystems that changed after 0.2.0. Behavior below is
verified against source; if a comment and this page disagree, trust the code.

Companion pages: [ARCHITECTURE.md](ARCHITECTURE.md) (maps) · [GO_LIVE.md](GO_LIVE.md)
(live twin) · [COMPLIANCE.md](COMPLIANCE.md) (framework modules).

---

## 1. Environment (what the code actually reads)

| Variable | Where | Effect |
|---|---|---|
| `AEGIS_AIRGAP` (**default on**; only `0` opts out) | `core/llm/airgap.py:airgap_enabled`, `config.py`, backends, `HttpBackend` | Drop `anthropic-cloud` from the chain; refuse non-loopback model URLs at construction (also in `HttpBackend.generate_config`); abort if `anthropic` is already in `sys.modules`. A missing or mistyped value stays air-gapped. |
| `AEGIS_LLM_URL` | `AdapterConfig.from_env` | Local OpenAI-compat base. Default `http://localhost:11434`. Fallback: `MODEL_RUNNER_URL`. |
| `AEGIS_LLM_MODEL` | same | Default `ai/qwen3:latest`. |
| `AEGIS_LLM_WEIGHTS` | same | Optional path; hashed once (path, mtime, size cache) into `weights-sha256`. Missing file → honest `identity-claim`, not a crash. |
| `ANTHROPIC_API_KEY` | `from_env` | Presence-only. Enables cloud fallback **only when air-gap is off**. The key is never stored on the config object. |
| `AEGIS_MAX_AUTHORIZED_TIER` | `core/risk/authority.py` | `AUTO` \| `HITL` \| `HOTL`. Default `HOTL`. `BLOCK` and unknown values **raise**. |
| `AEGIS_SEAL_KEY` | `serve.py` | 64 hex chars = pinned Ed25519 seed. Unset = ephemeral demo key. Invalid = `SystemExit`. Pinned key **requires** `AEGIS_API_KEY` (T1 #10). |
| `AEGIS_API_KEY` | `serve.py` | When set, mutating routes require header `X-Aegis-Key`. Custom header also breaks trivial CSRF POSTs. |
| `AEGIS_APPROVE_KEY` | `core/promote/tokens.py` | HMAC-SHA256 key for G2/G3 tokens. Hex (≥32 chars) or raw (≥16 bytes). Unset = asserted-unverified. Set-but-too-short = `SystemExit`. Set **requires** `AEGIS_API_KEY` (startup `SystemExit`; mint 503). |
| `AEGIS_INTEGRATION_HOSTS` | `core/integrations/__init__.py` | Hosts declared in-perimeter for ServiceNow / NetBox while air-gap is on. Exact hostnames, comma-separated. |
| `AEGIS_SNOW_*`, `AEGIS_NETBOX_*` | `core/integrations/` | See `docs/INTEGRATIONS.md`. |
| `AEGIS_SECRET_STORE` / `AEGIS_SECRET_KEY` / `AEGIS_VAULT_TOKEN` | `core/secretref.py` | D3 secret references. Store = `file:/abs/path` or `vault:https://.../v1/<mount>/data/<path>`. Probed at startup (key check against existing entries, retention prune, canary write + read); a bad spec, a wrong or rotated key, or a dead vault = `SystemExit`. Required in production. `AEGIS_SECRET_RETENTION_DAYS` (default 30, 0 = keep) prunes the file store. |
| `AEGIS_REVERSIBLE_SECRETS` | `evidence/secrets.py` | `fail` (default, D2) or `report`: whether type 7 / `$9$` fail PCI 8.3.2. Invalid = startup `SystemExit`. |
| `AEGIS_PROMOTE_ALLOW_LIVE=1` | `core/promote/gate.py` G4 | Required in addition to a live connector. |
| `AEGIS_HOST` / `AEGIS_PORT` | `serve.py` | Bind address (default `127.0.0.1:8088`). |

`HttpBackend` itself still uses constructor args (`base_url`, `model_runner_url`), defaulting
to `http://127.0.0.1:5757` and `http://localhost:12434`. The air-gap hostname check runs on
the **adapter** backends, not on that urllib client.

---

## 2. Air-gap URL rules (`core/llm/airgap.py`)

`is_loopback(url)` is fail-closed and does **not** resolve DNS.

Allowed:

```text
http://127.0.0.1:11434
http://127.1.2.3:9          # any 127.0.0.0/8
http://[::1]:5757
http://localhost:11434
http://ip6-localhost:11434
```

Rejected (construction raises `RuntimeError`):

```text
https://api.anthropic.com          # cloud provider also forbidden by name
http://10.0.0.5:11434              # LAN
http://127.evil.com:11434          # prefix spoof — parsed as a hostname
http://ollama.local:11434          # mDNS; could be another machine
http://:11434                      # empty host
```

Pitfall: pointing `AEGIS_LLM_URL` at a Docker service name (`http://ollama:11434`) fails
under `AEGIS_AIRGAP=1`. Use a loopback publish or run the model on localhost.

---

## 3. HTTP backend parsers (`core/backends/http_backend.py`)

Pure functions; contract-tested in `tests/contract_test.py` with **no network**.

### `parse_nornir_bgp` → `(bgp_up, node_count, converged)`

- `converged` is true only when the payload has both `error` and `results`, `error == 0`,
  `results` is a non-empty list, and at least one Established session was observed.
  Missing keys, `results: null`, Idle-only output, or an empty inventory → not converged.
- A device contributes Established peers from `show bgp summary`-shaped output: a line
  starting with an IPv4 address **or** an IPv6 address (must contain `:`) and ending with a
  numeric prefix-received column or `Estab*`.
- Bare digit-terminated lines (uptimes, totals) do **not** count.
- Nornir `status == "ok"` means the command ran — it is **not** a session. There is no
  ok-status fallback (that path used to invent one session per device and seal `ship_ready`).
- `apply_succeeded` is true only when the apply response has `applied is True`. A missing
  key, the string `"true"`, or a non-dict body fails closed.
- A 20k-character flood of `:` is treated as zero sessions (ReDoS guard + fail-closed).

Twin verdict uses these counts: `bgp_after < bgp_before` → `blocked`. An IPv6-only fabric
was previously under-counted; do not compare old vs new `bgp_sessions` numbers blindly.

### `parse_configgen`

- Extracts the first JSON object (tolerates Qwen `<think>` preamble / fences).
- **Unparseable JSON** or a non-object payload → `PreflightError("generation_failed: …")`.
  No stub config, no `ship_ready`.
- Empty, blank, or non-list `configs` also raise `generation_failed`. There is no
  `# (no configs returned)` stub.

---

## 4. Authority & promotion

`run_preflight` always writes `change.authority` via `authority_record(...)`.

| Change class (regex on candidate config / device name) | Floor |
|---|---|
| `router bgp N`, `local-as`, `autonomous-system` (the device's own AS) | BLOCK |
| `remote-as` / `peer-as` (default `AEGIS_PEER_AS_POLICY=hitl`, D1) | ≥ HITL (peering change, never AUTO) |
| `remote-as` / `peer-as` with `AEGIS_PEER_AS_POLICY=block` | BLOCK (the original behavior) |
| `route-distinguisher` / `route-target` / `rd N:N` / `rt N:N` | BLOCK |
| device name contains `spine`, or OSPF/ISIS/underlay text | ≥ HOTL |

`evaluate()` in `core/promote/gate.py`:

0. G0 — `verify_seal` against the pinned key (server: always). No seal, a foreign key or a
   mismatched seal → deny.
1. G1 — `bundler.verify` (sha256, `seal` excluded from the hash)
2. G2 — `blocked` never promotes; `needs_approval` needs approver + **verified** token
3. G3 — medium/high risk needs approver + **verified** token
4. G4 — live connector needs `AEGIS_PROMOTE_ALLOW_LIVE=1`
5. G5 — re-load ceiling and `authorize(required, ceiling)`. Missing / unknown
   `change.authority` → deny.
6. SoD — when approval is required, approver ≠ `bundle.operator`.
7. Single-use — with a `ledger`, an HMAC token is claimed before the first push. A replay
   → deny.

Token verification (`core/promote/tokens.py`):

- `AEGIS_APPROVE_KEY` **set**: token must be `aegis1.<b64url payload>.<b64url hmac-sha256>`,
  payload `{"a": approver, "b": bundle_sha256, "exp": unix, "n": nonce, "v": 1}`, MAC over
  the exact payload bytes. Wrong approver, wrong hash, expiry, or a random string → deny.
- **Unset**: any non-empty pair is accepted and recorded as `asserted-unverified`.
- The raw token is never written. Promotion records store `approval.method` + `token_sha256`.

The seal (`core/seal/seal.py`) additionally refuses to certify an unbounded change.

---

## 5. Community HTTP surface (`serve.py`)

| Method | Path | Notes |
|---|---|---|
| GET | `/preflight` | Sim-tier UI |
| GET | `/api/status` | Public. `{api_auth, approve_hmac, seal, egress}` — no secrets. |
| POST | `/api/preflight/run` | `mode=live` → **501**. Sim only. Auth when `AEGIS_API_KEY` set. |
| POST | `/api/preflight/evidence/pdf` | Integrity must verify or **422**. Auth when key set. |
| POST | `/api/preflight/evidence/oscal` | OSCAL-shaped AR JSON. Same integrity gate. Not FedRAMP. |
| POST | `/api/preflight/evidence/cab` | CAB one-pager. Rollback is a plan, not a verified execution. |
| POST | `/api/approve/mint` | HMAC token. Body `{bundle}` → **v2** (config + inventory). Hash-only → **v1**. Tampered bundle → **422**. **503** if HMAC unset. |
| POST | `/api/preflight/promote` | Gate G0–G5 + SoD + single-use, then dry-run (default). Optional `inventory_sha256` live override. **403** on deny. |
| POST | `/api/integrations/servicenow/sync` | Sealed bundle → verdict + redacted PDF attached to its CHG; blocked → on hold. Needs `AEGIS_API_KEY` + `AEGIS_SNOW_URL` (**503** otherwise). See `docs/INTEGRATIONS.md`. |
| POST | `/api/postchange/verify` | `{bundle, running_configs, intents?}` → verified / drift / failed / unverifiable. Bundle must carry this server's seal (**422**). |
| GET | `/api/seal/pubkey` | Offline verify material (public). |
| POST | `/api/seal/verify` | Body `{bundle, seal}` (public). |

CSP is loopback-oriented; `MAX_CONTENT_LENGTH` is 2 MB.

### Runbook: run → mint → promote (HMAC mode)

Server prerequisites: `AEGIS_API_KEY` **and** `AEGIS_APPROVE_KEY`. If the HMAC key is set
but the API key is not, the server refuses to start. If the API key is removed while the
server is running, mint returns **503**. Approvals are never minted on an unauthenticated
server. With `AEGIS_APPROVER_KEYS` set, each approver authenticates with their own
credential.

```bash
H=(-H "Content-Type: application/json" -H "X-Aegis-Key: $AEGIS_API_KEY")
# 1. operator runs the preflight; the response IS the sealed bundle (seal under .seal)
curl -s "${H[@]}" -d '{"intent":"add vlan 10 to leaf-1","operator":"alice","change_ref":"CHG0001234"}' \
  http://127.0.0.1:8088/api/preflight/run > bundle.json
# 2. a DIFFERENT person mints a v2 token bound to that bundle's config + inventory
jq '{bundle: .}' bundle.json | curl -s "${H[@]}" -H "X-Aegis-Approver-Key: $MY_APPROVER_CRED" \
  -d @- http://127.0.0.1:8088/api/approve/mint > token.json
# 3. promote (dry_run connector by default)
jq -n --slurpfile b bundle.json --slurpfile t token.json \
  '{bundle: $b[0], approver: $t[0].approver, approval_token: $t[0].token}' \
  | curl -s "${H[@]}" -d @- http://127.0.0.1:8088/api/preflight/promote
```

| Response | Meaning | Fix |
|---|---|---|
| mint **401** | Missing or unknown `X-Aegis-Approver-Key`. The denial is ledgered. | The approver uses their own credential. |
| mint **403** "separation of duties" | The approver is the bundle's `operator`. | A second person approves. |
| mint **422** | The bundle was edited after the run (sha256 mismatch). | Re-run the preflight. |
| mint **503** | The HMAC key is unset, or the API key is unset. | Set both keys. |
| promote **403** G0 | The seal is missing, foreign, or mismatched. | Use the bundle exactly as `/run` returned it. |
| promote **403** "already used" | Single-use token replay. | Mint a new token. |
| promote **403** inventory | The live `inventory_sha256` differs from the one the token was bound to. | Re-run against the current inventory. |

---

## 6. Tests you can run locally

CI (`.github/workflows/test.yml`) runs nine modules. These extra suites are **not** in
that workflow and are the right place to lock air-gap / authority / seal behavior:

```bash
python -m aegis.tests.llm_egress_test
python -m aegis.tests.authority_test
python -m aegis.tests.ceiling_test
python -m aegis.tests.seal_test
python -m aegis.tests.wedge_test
python -m aegis.tests.tokens_test
```

Run them from the directory **above** `aegis/` (same as CI: checkout into `aegis/`).
