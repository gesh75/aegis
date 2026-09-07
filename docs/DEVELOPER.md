# AEGIS — Developer & operator notes

Concise contracts for the subsystems that changed after 0.2.0. Behavior below is
verified against source; if a comment and this page disagree, trust the code.

Companion pages: [ARCHITECTURE.md](ARCHITECTURE.md) (maps) · [GO_LIVE.md](GO_LIVE.md)
(live twin) · [COMPLIANCE.md](COMPLIANCE.md) (framework modules) ·
[EVIDENCE.md](EVIDENCE.md) (sha256 vs Ed25519, OSCAL/CAB).

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
| `AEGIS_APPROVE_KEY` | `core/promote/tokens.py` | HMAC-SHA256 key for G2/G3 tokens. Hex (≥32 chars) or raw (≥16 bytes). Unset = asserted-unverified. Set-but-too-short = `SystemExit`. **Pair with `AEGIS_API_KEY`** — HMAC without API auth leaves `POST /api/approve/mint` reachable (see §7). |
| `AEGIS_PROMOTE_ALLOW_LIVE=1` | `core/promote/gate.py` G4 | Required in addition to a live connector. `connector=live` is still `DisabledLiveConnector` (raises). |
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

Token verification (`core/promote/tokens.py`):

| Version | How minted | Claims checked at G2/G3 |
|---|---|---|
| **v2** | `mint_token_for_bundle()` or `POST /api/approve/mint` with `{bundle}` | approver + bundle sha256 + **config** digest + **inventory** digest + expiry |
| **v1** | `mint_token(approver, bundle_sha256)` or hash-only mint body | approver + bundle sha256 + expiry. Extra hashes are ignored. |

- Format: `aegis1.<b64url payload>.<b64url hmac-sha256>`. MAC over the exact payload bytes.
- v2 payload: `{"a","b","c","inv","exp","n","v":2}`. `c` = SHA-256 of canonical grounded
  configs (`device`/`vendor`/`config`). `inv` = SHA-256 of twin `topology` + `engine` +
  `node_count` + device list + optional `twin.inventory_rev` (or `twin.rev`).
- A v2 token minted against inventory N dies if N+1 is supplied at promote time, even
  when the sealed bundle hash is unchanged. Missing live hashes on a v2 token is a deny.
- Unknown `v` (not 1 or 2) fails closed. v1 tokens keep verifying.
- `AEGIS_APPROVE_KEY` **unset**: any non-empty pair is `asserted-unverified`.
- The raw token is never written. Promotion records store `approval.method` +
  `token_sha256` + optional `live_inventory_sha256`.

The seal (`core/seal/seal.py`) additionally refuses to certify an unbounded change.

Operator curl path: [§7](#7-hmac-approval--promote-community-8088).

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
| POST | `/api/preflight/promote` | Gate G1–G5 then dry-run (default). Optional `inventory_sha256` live override. **403** on deny. |
| GET | `/api/seal/pubkey` | Offline verify material (public). |
| POST | `/api/seal/verify` | Body `{bundle, seal}` (public). |

CSP is loopback-oriented; `MAX_CONTENT_LENGTH` is 2 MB.

---

## 6. Tests you can run locally

CI (`.github/workflows/test.yml`) runs **nine** modules: `stress`, `promote`, `twin`,
`pdf`, `contract`, `tokens`, `oscal`, `api`, `compliance`. HMAC v1+v2 and OSCAL/CAB
are in that workflow. These extra suites are **not** and lock air-gap / authority /
seal behavior:

```bash
python -m aegis.tests.llm_egress_test
python -m aegis.tests.authority_test
python -m aegis.tests.ceiling_test
python -m aegis.tests.seal_test
python -m aegis.tests.wedge_test
```

Run them from the directory **above** `aegis/` (same as CI: checkout into `aegis/`).

---

## 7. HMAC approval + promote (community `:8088`)

Goal: mint a token bound to *this* bundle, then dry-run promote. Community
`python -m aegis.serve` is sim-tier only (`mode=live` → **501**).

### Pair the keys

```bash
export AEGIS_APPROVE_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export AEGIS_API_KEY=$(python3 -c "import secrets; print(secrets.token_hex(16))")
# restart serve.py so load_approve_key() sees the HMAC key
```

| Config | What happens on `main` |
|---|---|
| Both unset | Mint **503**. Promote accepts any non-empty pair as `asserted-unverified`. |
| HMAC set, API unset | **Pairing hole.** `_guard_api()` is a no-op, so anyone who can reach the port can mint a valid G2/G3 token. Draft #28 would refuse this; it is **not** shipped. |
| Both set | Mint/promote require `X-Aegis-Key`. Missing header → **401**. |
| API set, HMAC unset | Mint **503**. Mutating routes still need the header. |

Pinned `AEGIS_SEAL_KEY` already refuses to start without `AEGIS_API_KEY`. HMAC mint
does not.

`GET /api/status` (public): `{api_auth, approve_hmac, seal, egress}` — no secrets.

### Mint v2 from a sealed bundle

```bash
# 1. Run PreFlight and keep the bundle
curl -s -X POST http://127.0.0.1:8088/api/preflight/run \
  -H "Content-Type: application/json" \
  -H "X-Aegis-Key: $AEGIS_API_KEY" \
  -d '{"intent":"add vlan 10 to leaf-1","lab":"single","frameworks":["pci_dss_v4"]}' \
  > /tmp/aegis-bundle.json

# 2. Mint — body {bundle} → v2 (config + inventory). Tampered bundle → 422.
curl -s -X POST http://127.0.0.1:8088/api/approve/mint \
  -H "Content-Type: application/json" \
  -H "X-Aegis-Key: $AEGIS_API_KEY" \
  -d "$(jq -n --arg a noc-lead --slurpfile b /tmp/aegis-bundle.json \
        '{approver:$a, bundle:$b[0], ttl_sec:14400}')"
# 200 {token, alg, version:2, bound_to, config_sha256, inventory_sha256, approver}
```

Hash-only body `{approver, bundle_sha256}` still emits **v1**. Supplying both
`config_sha256` and `inventory_sha256` (64 lowercase hex) without a `bundle`
also emits v2. `ttl_sec` default 14400 (4 h); allowed 60 … 7 days.
Approver charset: `[A-Za-z0-9._@/-]{1,128}`.

### Dry-run promote

```bash
TOKEN=…   # from mint
curl -s -X POST http://127.0.0.1:8088/api/preflight/promote \
  -H "Content-Type: application/json" \
  -H "X-Aegis-Key: $AEGIS_API_KEY" \
  -d "$(jq -n --arg a noc-lead --arg t "$TOKEN" --slurpfile b /tmp/aegis-bundle.json \
        '{bundle:$b[0], approver:$a, approval_token:$t, connector:"dry_run"}')"
# 200 promotion record  ·  403 {denied:true, error} on gate fail
```

Optional `inventory_sha256` on the promote body overrides the bundle-derived
fingerprint (`live_inventory_sha256` in `gate.evaluate` / the record). Use it
when a live CMDB digest is available; a drift from the v2 claim is a deny.

Promotion record (never stores the raw token):

- `approval.method` — `hmac-sha256` | `asserted-unverified` | `none`
- `approval.token_sha256` · `approval.bound_bundle_sha256`
- `approval.live_inventory_sha256` — only when the caller supplied the override
- `connector` / `dry_run` · `status` `promoted` | `partial` · own `integrity.sha256`

### Constraints operators miss

- **G1 is `bundler.verify`, not `verify_seal`.** A hash-valid unsigned bundle can
  still promote if G2–G5 pass.
- **Empty `generated_configs`** → `PromoteDenied("nothing to promote")` before the gate.
- **`connector=live`** is `DisabledLiveConnector`. G4 also needs
  `AEGIS_PROMOTE_ALLOW_LIVE=1`. Even then `push()` raises `RuntimeError` — there is
  no SSH/NETCONF connector on `main`.
- **v2 vs config edit.** Changing grounded config after mint invalidates `c`.
  Changing `twin.inventory_rev` (or the live override) invalidates `inv`.
- Community mint **503** if HMAC is unset. That is not the pairing hole — the hole
  is HMAC set and API unset.

---

## 8. PIV pins (step 0 only)

`core/seal/pins.py` now ships compiled-in constants. Editing this module and
rebuilding is the rotation path — a runtime file must not loosen the root.

| Constant | Current `main` value |
|---|---|
| `YUBICO_PIV_ROOT_CA_DER_SHA256` | `63ece914e54dd87915f34033c85af4c0696ba1512f8add66ced738331207b546` (Yubico PIV Root CA Serial 263751, DER SHA-256; source `developers.yubico.com/PKI/yubico-piv-ca-1.pem`) |
| `PIV_SERIAL_ALLOWLIST` | empty `frozenset` |
| `PINNED_PIV_KEY_ID` | `None` |

What did **not** land in #27 despite the PR title: `PivSigner`, PKCS#11 `C_Sign`,
raw `r‖s` → DER helpers, attestation walker, SSH/NETCONF connectors, Batfish
sidecar. `signing.py` is still software Ed25519 only. Seals stay
`signature.alg == "ed25519"`. Plan for the remaining steps:
[PIV_HARDWARE_SIGNER_PLAN.md](PIV_HARDWARE_SIGNER_PLAN.md).
