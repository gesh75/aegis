# AEGIS — Developer & operator notes

Concise contracts for the subsystems that changed after 0.2.0. Behavior below is
verified against source; if a comment and this page disagree, trust the code.

Companion pages: [ARCHITECTURE.md](ARCHITECTURE.md) (maps) · [GO_LIVE.md](GO_LIVE.md)
(live twin) · [COMPLIANCE.md](COMPLIANCE.md) (framework modules) ·
[EVIDENCE.md](EVIDENCE.md) (sha256 vs Ed25519, OSCAL/CAB). HMAC mint/promote: §7.

---

## 1. Environment (what the code actually reads)

| Variable | Where | Effect |
|---|---|---|
| `AEGIS_AIRGAP=1` | `core/llm/config.py`, `airgap.py`, backends | Drop `anthropic-cloud` from the chain; refuse non-loopback URLs at construction; abort if `anthropic` is already in `sys.modules`. |
| `AEGIS_LLM_URL` | `AdapterConfig.from_env` | Local OpenAI-compat base. Default `http://localhost:11434`. Fallback: `MODEL_RUNNER_URL`. |
| `AEGIS_LLM_MODEL` | same | Default `ai/qwen3:latest`. |
| `AEGIS_LLM_WEIGHTS` | same | Optional path; hashed once (path, mtime, size cache) into `weights-sha256`. Missing file → honest `identity-claim`, not a crash. |
| `ANTHROPIC_API_KEY` | `from_env` | Presence-only. Enables cloud fallback **only when air-gap is off**. The key is never stored on the config object. |
| `AEGIS_MAX_AUTHORIZED_TIER` | `core/risk/authority.py` | `AUTO` \| `HITL` \| `HOTL`. Default `HOTL`. `BLOCK` and unknown values **raise**. |
| `AEGIS_SEAL_KEY` | `serve.py` | 64 hex chars = pinned Ed25519 seed. Unset = ephemeral demo key. Invalid = `SystemExit`. Pinned key **requires** `AEGIS_API_KEY` (T1 #10). |
| `AEGIS_API_KEY` | `serve.py` | When set, mutating routes require header `X-Aegis-Key`. Custom header also breaks trivial CSRF POSTs. |
| `AEGIS_APPROVE_KEY` | `core/promote/tokens.py` | HMAC-SHA256 key for G2/G3 tokens. Hex (≥32 chars) or raw (≥16 bytes). Unset = asserted-unverified. Set-but-too-short = `SystemExit`. Set this **with** `AEGIS_API_KEY` — HMAC-only is an unauthenticated mint (see §7). |
| `AEGIS_PROMOTE_ALLOW_LIVE=1` | `core/promote/gate.py` G4 | Required in addition to a live connector. The shipped `live` connector is still inert (`DisabledLiveConnector`). |
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
| `router bgp N`, `remote-as`, `local-as`, `peer-as`, `autonomous-system` | BLOCK |
| `route-distinguisher` / `route-target` / `rd N:N` / `rt N:N` | BLOCK |
| device name contains `spine`, or OSPF/ISIS/underlay text | ≥ HOTL |

`evaluate()` in `core/promote/gate.py`:

1. G1 — `bundler.verify` (sha256, `seal` excluded from the hash)
2. G2 — `blocked` never promotes; `needs_approval` needs approver + **verified** token
3. G3 — medium/high risk needs approver + **verified** token
4. G4 — live connector needs `AEGIS_PROMOTE_ALLOW_LIVE=1`
5. G5 — re-load ceiling and `authorize(required, ceiling)`. Missing / unknown
   `change.authority` → deny.

Token verification (`core/promote/tokens.py`, **v1**):

- `AEGIS_APPROVE_KEY` **set**: token must be `aegis1.<b64url payload>.<b64url hmac-sha256>`,
  payload `{"a": approver, "b": bundle_sha256, "exp": unix, "n": nonce, "v": 1}`, MAC over
  the exact payload bytes. Wrong approver, wrong hash, expiry, or a random string → deny.
- **Unset**: any non-empty pair is accepted and recorded as `asserted-unverified`.
- v1 binds **approver + bundle sha256 + expiry only**. It does not bind grounded config
  or live inventory. A hash-valid bundle whose contents still match `integrity.sha256`
  reuses a minted token until `exp`.
- Approver charset: `^[A-Za-z0-9._@/-]{1,128}$`. TTL default 4 h, min 60 s, max 7 d.
- The raw token is never written. Promotion records store `approval.method` + `token_sha256`.

`evaluate()` does **not** call `verify_seal`. A hash-valid unsigned bundle can still be a
promotion candidate if G2–G5 pass.

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
| POST | `/api/approve/mint` | HMAC token bound to `bundle_sha256`. **503** if HMAC unset. Auth only when `AEGIS_API_KEY` is set. |
| POST | `/api/preflight/promote` | Gate G1–G5 then dry-run (default). **403** on deny. `connector=live` is still inert. |
| GET | `/api/seal/pubkey` | Offline verify material (public). |
| POST | `/api/seal/verify` | Body `{bundle, seal}` (public). |

CSP is loopback-oriented; `MAX_CONTENT_LENGTH` is 2 MB.

---

## 6. Tests you can run locally

CI (`.github/workflows/test.yml`) runs **nine** modules: `stress_test`, `promote_test`,
`twin_test`, `pdf_test`, `contract_test`, `tokens_test`, `oscal_test`, `api_test`,
`compliance_test`. These extra suites are **not** in that workflow and are the right
place to lock air-gap / authority / seal behavior:

```bash
python -m aegis.tests.llm_egress_test
python -m aegis.tests.authority_test
python -m aegis.tests.ceiling_test
python -m aegis.tests.seal_test
python -m aegis.tests.wedge_test
```

Run them from the directory **above** `aegis/` (same as CI: checkout into `aegis/`).

---

## 7. HMAC approval + promote runbook (community `:8088`)

This is the operator path for T1 #9 / #10 on the sim-tier server. Live twin mode on
`:5757` is a different process ([GO_LIVE.md](GO_LIVE.md)); these routes live in
`serve.py`.

### Pair the keys

```bash
export AEGIS_APPROVE_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export AEGIS_API_KEY=$(python3 -c "import secrets; print(secrets.token_hex(16))")
# optional stable seal — also requires AEGIS_API_KEY or serve.py SystemExits
# export AEGIS_SEAL_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
python -m aegis.serve
```

`GET /api/status` is public and names the mode without leaking secrets:

```bash
curl -s http://127.0.0.1:8088/api/status
# {"api_auth":"required","approve_hmac":"required","seal":"ephemeral","egress":"none"}
```

| `AEGIS_APPROVE_KEY` | `AEGIS_API_KEY` | What actually happens |
|---|---|---|
| unset | unset | Mint **503**. Promote accepts any non-empty pair as `asserted-unverified`. |
| set | set | Mint and promote require `X-Aegis-Key`. G2/G3 need a bound HMAC token. |
| set | unset | Mint and promote stay reachable with **no** header. Anyone who can hit the port can mint a valid G2/G3 token. Do not run this pairing. Pinned `AEGIS_SEAL_KEY` already refuses to start without an API key; HMAC mint does not. |
| unset | set | Mutating routes need `X-Aegis-Key`. Mint still **503**. Promote is `asserted-unverified`. |

### Mint, then dry-run promote

```bash
KEY=…   # same value as AEGIS_API_KEY

# 1. sim-tier PreFlight (mode=live is 501 here)
curl -s -X POST http://127.0.0.1:8088/api/preflight/run \
  -H "Content-Type: application/json" -H "X-Aegis-Key: $KEY" \
  -d '{"intent":"add vlan 10 to leaf-1","lab":"single","frameworks":["pci_dss_v4"]}' \
  > /tmp/aegis-bundle.json

SHA=$(jq -r '.integrity.sha256' /tmp/aegis-bundle.json)

# 2. mint — bound to this hash + this approver
curl -s -X POST http://127.0.0.1:8088/api/approve/mint \
  -H "Content-Type: application/json" -H "X-Aegis-Key: $KEY" \
  -d "{\"approver\":\"noc-lead\",\"bundle_sha256\":\"$SHA\",\"ttl_sec\":600}"
# 200 {"token":"aegis1.…","alg":"hmac-sha256","bound_to":"<sha>","approver":"noc-lead"}
# 400 approver / sha / ttl rejected   401 missing or wrong X-Aegis-Key
# 503 AEGIS_APPROVE_KEY unset

# 3. promote — default connector is dry_run (records, mutates nothing)
curl -s -X POST http://127.0.0.1:8088/api/preflight/promote \
  -H "Content-Type: application/json" -H "X-Aegis-Key: $KEY" \
  -d "{\"bundle\":$(cat /tmp/aegis-bundle.json),\"approver\":\"noc-lead\",\"approval_token\":\"$TOKEN\",\"connector\":\"dry_run\"}"
# 200 promotion record   403 gate deny   400 missing bundle / unknown connector
```

A 200 record includes `approval.method` (`hmac-sha256` or `asserted-unverified`),
`approval.token_sha256` (never the raw token), `source_sha256`, `connector`,
`dry_run`, `status` (`promoted` / `partial`), and its own `integrity.sha256`.
Empty `change.generated_configs` is `PromoteDenied` (`nothing to promote`) before
the gate runs.

`connector=live` is accepted as a name (`get_connector`) and is `live=True`, so G4
also needs `AEGIS_PROMOTE_ALLOW_LIVE=1`. The shipped `DisabledLiveConnector.push`
then raises `RuntimeError` — serve.py maps that to **500**. There is no production
push in the community core.

### Pitfalls

- **HMAC without API auth.** `_guard_api()` is a no-op when `AEGIS_API_KEY` is unset.
  Pair the keys, or leave HMAC unset for the honesty tier.
- **Wrong approver string.** The mint payload `a` must equal promote `approver`
  exactly. `noc-lead` ≠ `NOC-Lead`.
- **Random token once HMAC is on.** `"tok-123"` is a **403**. That is the whole
  point of T1 #9.
- **Promote ≠ seal.** G1 is `bundler.verify`. Swapping `bundle.seal` does not trip
  the gate. Authenticity is still `POST /api/seal/verify` ([EVIDENCE.md](EVIDENCE.md)).
- **`live` is not a push.** Opt-in env + `connector=live` still hits the inert
  placeholder. SSH/NETCONF is not on `main`.
