# AEGIS — Developer & operator notes

Concise contracts for the subsystems that changed after 0.2.0. Behavior below is
verified against source; if a comment and this page disagree, trust the code.

Companion pages: [ARCHITECTURE.md](ARCHITECTURE.md) (maps) · [GO_LIVE.md](GO_LIVE.md)
(live twin) · [COMPLIANCE.md](COMPLIANCE.md) (framework modules).

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
| `AEGIS_APPROVE_KEY` | `core/promote/tokens.py` | HMAC-SHA256 key for G2/G3 tokens. Hex (≥32 chars) or raw (≥16 bytes). Unset = asserted-unverified. Set-but-too-short = `SystemExit`. |
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
| POST | `/api/approve/mint` | HMAC token bound to `bundle_sha256`. **503** if HMAC unset. |
| POST | `/api/preflight/promote` | Gate G1–G5 then dry-run (default). **403** on deny. |
| GET | `/api/seal/pubkey` | Offline verify material (public). |
| POST | `/api/seal/verify` | Body `{bundle, seal}` (public). |

CSP is loopback-oriented; `MAX_CONTENT_LENGTH` is 2 MB.

---

## 6. Tests you can run locally

CI (`.github/workflows/test.yml`) runs seven modules. These extra suites are **not** in
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
