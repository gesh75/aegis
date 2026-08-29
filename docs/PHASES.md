# AEGIS — Project Phases (living document)

Every phase of the AEGIS project, what was decided, what was built, and what's next.
Updated as work lands. Newest status at the bottom of each phase.

---

## Phase R — Research & positioning  ·  ✅ done 2026-05-28

**Question:** with the four assets we own (NetLog AI, AI dashboard, 52k-command tool,
DCN + CLOS containerlab), what's the best next product — combine or new?

**Method:** independent EXA market research across AIOps, network digital twins, agentic
NetOps, air-gapped enterprise AI, and network compliance automation.

**Key finding that reframed everything:** on **2026-05-20** Forward Networks shipped
**Forward Predict** — run a proposed change against a digital twin, get deterministic
before/after evidence, MCP-exposed, $1k/mo+. NetPilot already does the runnable-lab
version. So the "PreFlight / change-validation" lane the earlier plan recommended is now
occupied by a funded incumbent and a freemium startup.

**The defensible gap:** both leaders are **cloud-by-architecture**. Regulated networks
(finance, telco, federal, healthcare) that legally cannot send topology/config off-prem are
locked out of them. Nobody combines **on-prem / air-gapped + real emulation (containerlab) +
self-hosted LLM + audit-grade evidence**. That is exactly the shape of our stack (Qwen3 on
Docker Model Runner = zero egress; clab = real convergence; 52k corpus = config grounding;
compliance scanner = evidence engine).

**Decision:** do NOT build PreFlight. Build the air-gapped version Forward/NetPilot
architecturally cannot follow us into. Working codename **AEGIS** (Air-gapped Evidence-Grade
Inspection System). Target buyer #1: regulated finance / telco NOC.

Sources captured in chat: Forward (Network World, PRNewswire, SiliconANGLE), NetPilot blog,
Itential "Real vs Theater", GÉANT guarded-agentic, on-prem LLM guides (Allganize,
TrueFoundry), Titania/Viwago network compliance.

---

## Phase P — Build plan  ·  ✅ done 2026-05-28

Deliverable: `AEGIS_PHASE_0-1_BUILD_PLAN.md` (repo root).

**Architecture decision — "guarded agentic":** only the config-generation step touches an
LLM; everything after it (static check, twin apply, convergence, diff, compliance, verdict,
evidence) is **deterministic verification**. The LLM proposes; the pipeline verifies. This
is what makes the evidence auditable rather than "the AI said so."

**Open-core split:** `core/` + `labs/` + evidence schema = Apache-2.0 community tier;
`pro/` (PDF render, continuous compliance, connectors, RBAC) = commercial.

**Monetization:** Community (free OSS, self-host) → Pro (hosted twin compute, observability,
evidence export) → Enterprise (air-gapped deploy, connectors w/ approval gates, RBAC).

---

## Phase 0 — Scaffold + stress test  ·  ✅ done 2026-05-28

Built a runnable `aegis/` package with a **pluggable backend** so the identical
deterministic pipeline runs against the live `:5757` stack OR an in-process simulator.

Files:
- `core/orchestrator/pipeline.py` — the deterministic loop (intent → guard → generate →
  batfish → spawn twin → apply+converge → diff → compliance → risk-tier → rollback →
  verdict → sealed evidence bundle). Twin always torn down in `finally`.
- `core/orchestrator/guards.py` — pre-checks, risk tiering, approval gate (pure functions).
- `core/orchestrator/rollback.py` — reversal-plan generator.
- `core/backends/base.py` — the `Backend` protocol (the contract all backends satisfy).
- `core/backends/simulator.py` — deterministic, failure-injecting in-process backend.
- `evidence/bundler.py` — assembles the bundle + computes/verifies the integrity sha256.
- `evidence/compliance.py` — PCI/SOC2/NIST control crosswalk.
- `evidence/schema/evidence_bundle.schema.json` — the paid artifact's contract (draft-07).
- `tests/stress_test.py` — 8 invariants, adversarial sweep, concurrency, latency.

**Stress result (25,000 runs):** PASS, 0 invariant violations. 0 schema/hash failures,
0 unsafe ships, 0 ungated high-risk ships, 0 twin leaks, egress="none" on all. 2,000
concurrent runs across 8 threads: 0 failures. ~0.1 ms p50 orchestrator overhead. Full
detail: `STRESS_TEST_RESULTS.md`. Worked example: a plaintext-auth-key intent is blocked
and auto-mapped to PCI 8.3.1 fail + 1.2.1 fail.

---

## Phase 0L — Live adapters (HttpBackend)  ·  ✅ parsing done · ⏳ network + 3 endpoints pending

Read the **real** `:5757` handlers and tests in `DCN_Network_Tool/src/app.py` and
implemented `HttpBackend` against the actual response shapes:

| Endpoint | Real response shape | AEGIS mapping |
|---|---|---|
| `POST /api/batfish/analyze` | `{errors,warnings,passes,findings[{severity,message}]}` | `BatfishResult` (note: `passes`→`passed`) |
| `POST /api/nornir/run` (bgp_health) | `{devices,ok,warn,error,results[{hostname,status,output}]}` | bgp_up + node_count + converged |
| `POST /api/pyats/diff` | `{total_changes,diffs[{type,name,pre_up,post_up}]}` | `DiffResult` (bgp-down → sessions_dropped) |
| Qwen3 model runner `/v1/chat/completions` | OpenAI-compat completion | `generate_config` (parses `<think>` preamble) |

Parsing is split into **pure functions** (`parse_batfish`, `parse_nornir_bgp`,
`parse_pyats_diff`, `parse_configgen`) and contract-tested against fixtures shaped like the
real handlers: `tests/contract_test.py` — **PASS (14 checks)**. A real bug was caught and
fixed: a recovered (came-up) BGP peer was wrongly counted as "dropped"; corrected to flag
only sessions that are down *after* the change.

**Honest findings recorded for the live step:**
1. The existing `:5757` tool is **read-only**. `/api/ai-command` only translates *show*
   commands — it is NOT a config generator. AEGIS config-gen therefore calls the Qwen3
   model runner directly (no new endpoint needed, stays in-perimeter).
2. Pushing a candidate config into a throwaway twin needs **three small net-new write
   endpoints** (safe — twin only, never production):
   `POST /api/preflight/twin/{spawn,apply,destroy}`.
3. `pyats/diff` reports interface + BGP-neighbor state, not RIB routes — so
   `routes_added/removed` stay empty until a richer collector is wired.

**Remaining for Phase 0 live:** ~~add the 3 twin endpoints to `app.py`~~ → done (Phase 0T),
then run `stress_test`/`contract_test` against the live fabric inside the air gap.

---

## Phase 0T — Twin write endpoints  ·  ✅ code + stress done 2026-05-28 · ⏳ live deploy pending

Built the three net-new write endpoints as a framework-free `TwinManager` plus a thin Flask
blueprint, in `04_Scripts_Tools/DCN_Network_Tool/src/preflight_twin.py`:

```
POST /api/preflight/twin/spawn    {lab}               -> {twin_id, lab, nodes, status}
POST /api/preflight/twin/apply    {twin_id, configs}  -> {applied, per_device[]}
POST /api/preflight/twin/destroy  {twin_id}           -> {destroyed}
```

Each twin is a **clone** of a reference topology (`containerlab-multivendor/topologies/`)
deployed under a unique `twin-…` name, so its containers are `clab-twin-…-<node>` and can
never collide with the production labs (`clab-clos-evpn-*`) or real devices.

**Safety invariants (enforced + stress-tested):**

| ID | Invariant |
|---|---|
| ISO-1 | apply/destroy reject any id that isn't a known `twin-` id → production isolation |
| ISO-2 | spawn only accepts labs in the allowlist → no path/topology injection |
| ISO-3 | device names must match `^[A-Za-z0-9_.:-]+$` → no shell injection |
| ISO-4 | at most `MAX_TWINS` (4) live at once → host protection |
| ISO-5 | destroy is idempotent (unknown/gone → ok) → no leaks |
| ISO-6 | all commands run as arg-lists, never `shell=True` → no injection |

All containerlab/docker calls go through an **injectable runner**, so the logic is testable
with no Docker/Flask present (Flask is lazy-imported only in `make_blueprint`).

**Stress result (`src/tests/test_preflight_twin.py`, 20,000 ops):** PASS. Headline audit
over all ~15k issued commands: **0 production-container hits, 0 injection tokens reached a
command, 0 non-arg-list commands, 0 twin leaks, 0 concurrency errors** (60 parallel
spawn→apply→destroy). Bad labs rejected, over-limit spawns 429'd, injection device names
blocked, non-twin destroys correctly refused (403).

**Wiring:** AEGIS `HttpBackend` already calls these exact paths. To activate, register the
blueprint in `app.py` next to `mv_bp`:
```python
from preflight_twin import make_blueprint as _preflight_bp
app.register_blueprint(_preflight_bp())
```

**Remaining for live:** ~~register the blueprint~~ → done (Phase 0W); point `HttpBackend` at
`127.0.0.1:5757` + the Qwen3 runner and run an end-to-end preflight against the real
clos-evpn fabric. The only thing the mocks can't prove is real containerlab convergence timing.

---

## Phase 0W — Wire into app.py + run endpoint + UI  ·  ✅ done 2026-05-28

**Blueprints registered in `app.py`** (next to `mv_bp`, in a fail-safe try/except so a
missing AEGIS never blocks app boot):
```python
from preflight_twin import make_blueprint as _preflight_twin_bp
from preflight_run  import make_blueprint as _preflight_run_bp
app.register_blueprint(_preflight_twin_bp())
app.register_blueprint(_preflight_run_bp())
```

**`POST /api/preflight/run`** (`src/preflight_run.py`) — the end-to-end loop endpoint. Drives
the AEGIS pipeline and returns the sealed evidence bundle. `mode:"sim"` (default,
`SimulatorBackend` — runs with no Qwen3/clab) or `mode:"live"` (`HttpBackend` → Qwen3 runner
+ twin endpoints on the same `:5757`). The aegis package is added to `sys.path` inside the
module, so `app.py` needs no change beyond the two registration lines.

**UI** — `aegis/ui/preflight_screen.html`, a self-contained dark dashboard (no build step).
Four panels (verdict · twin · generated config · evidence/compliance), a step strip
showing the loop, a color-coded verdict badge (green/red/amber), PCI/SOC2/NIST control
chips, and an integrity footer surfacing `egress: none` + the sha256. Talks to
`/api/preflight/run`; API base auto-detects (same-origin on :5757, else localhost:5757).

**Verification:**
- `src/tests/test_preflight_flask.py` — **7/7 PASS** Flask test-client tests over the real
  HTTP surface (twin spawn/apply/destroy happy path, unknown-lab reject, non-twin destroy
  403, injection-device block, run returns sealed bundle, plaintext-key blocked w/ PCI fail,
  empty-intent guard 400).
- UI field audit — all **28** dotted paths the JS dereferences (+ nested config/compliance
  lists) resolve against a real bundle (catches key typos like `passed` vs `passes`).
- Regression: AEGIS contract + 25k stress + 20k twin stress all still PASS.

---

## Phase 1 — Shippable MVP  ·  ⏳ next

Per build plan: config-import path (no prod touch), risk tiering + approval gate (built),
rollback plan (built), evidence bundle v1 + examiner-ready PDF, continuous compliance (Pro),
air-gap packaging (`docker-compose.airgap.yml`), community GitHub launch.

Explicitly deferred to Phase 2+: live production push connectors, RBAC/SSO, multi-tenant
hosting, 10k-device scale.

---

## Phase 1a — Examiner-ready evidence PDF  ·  ✅ done 2026-05-28

The paid artifact. `aegis/evidence/pdf.py` `render_pdf(bundle) -> bytes` (reportlab only,
no network — air-gap safe) produces an auditor-facing document: color-coded verdict,
risk/blast-radius/approval block, digital-twin outcome (convergence, BGP before→after,
regression flag), a framework-mapped compliance table (PCI/SOC2/NIST, fails in red), the
Batfish findings, the grounded per-vendor config, the rollback plan, and the tamper-evident
integrity block (`sha256` + `egress: none`).

Endpoint: `POST /api/preflight/evidence/pdf` (in `preflight_run.py`) — accepts a produced
bundle, returns `application/pdf` (400 if the bundle has no integrity hash). UI: a
**⬇ Download evidence PDF** button appears in the evidence panel after a run.

**Stress (`aegis/tests/pdf_test.py`, 1,500 bundles):** PASS — 1500/1500 structurally valid
PDFs (`%PDF` header + `%%EOF`), 0 renderer exceptions, avg ~4.2 KB, both ship_ready and
blocked verdicts exercised. Sample saved at `tests/sample_bundles/evidence_sample.pdf`.

Live-twin spawn deferred to a Linux host (native clab binary; trivial there). Docker-image
clab mode (`AEGIS_CLAB_MODE=docker`) is wired for macOS but not the priority — the product's
real target is Linux.

---

## Phase 1b — Config-import path  ·  ✅ done 2026-05-28

The enterprise-safe entry point: instead of an NL intent, the operator pastes a sanitized
running-config. **No LLM touches this path** — the config is used verbatim and every step
after it is the same deterministic verification, so it's the most auditable mode.

`run_preflight(..., source="config_import", imported_configs=[{device,vendor,config}])`
skips `generate_config`, tags each config `grounded_commands=["operator-supplied"]`, and
guards on size (≤200k chars) instead of the intent prechecks. Endpoint accepts
`{"source":"config_import","config":"…","vendor":"…"}` or a `configs:[…]` list; 400s if no
config supplied. UI: a **source** toggle (`intent` ⇄ `paste config`) reveals a config
textarea + vendor select and greys out the "generate (LLM)" step.

**Tests:** `test_preflight_flask.py` now **10/10** — added clean-import ships,
plaintext-import blocks with PCI 8.3.1 fail, and empty-import 400-guards. Pipeline/twin/
contract/PDF suites all still PASS.

---

## Phase 1c — Twin mgmt-network isolation  ·  ✅ done 2026-05-28

A throwaway twin can now run **alongside the live prod lab** without colliding.
`_materialize_topo` rewrites, per twin: the `name`, the mgmt `network` name, the mgmt
`ipv4-subnet` (a deterministic unique `10.100-199.x.0/24` derived from the twin id), and
strips every static `mgmt-ipv4:` so clab auto-assigns inside the new subnet. Fabric configs
(loopbacks/BGP/EVPN) are untouched — only the clab management plane moves. Verified in the
twin stress harness (`mgmt_isolation.ok == true`): twin reuses neither prod name, network,
nor subnet for clos-evpn and minimal.

Also fixed the macOS docker-clab invocation: the clab image entrypoint is not
`containerlab`, so docker mode now runs `… ghcr.io/srl-labs/clab:latest containerlab deploy …`
(was failing with `exec: "deploy": not found`). `hashlib` import added.

## Phase 1d — GitHub / air-gap packaging  ·  ✅ done 2026-05-28

The community core is now a standalone, self-contained repo:
- `aegis/serve.py` — `python -m aegis.serve` → PreFlight UI + pipeline in **sim tier**
  (no LLM, no clab, fully offline). Live mode returns 501 (lives in the integrated product).
- `Dockerfile` + `docker-compose.yml` → `docker compose up`, open `:8088/preflight`.
- `docker-compose.airgap.yml` → build online once, `docker save` → signed media →
  `docker load` → run with `network_mode: none` + `pull_policy: never` (proves zero egress).
- `LICENSE` (Apache-2.0), `.gitignore`, `requirements.txt` (jsonschema, reportlab, flask).
- UI API base now same-origin over http(s) so it works on any port / behind the server.

Verified via the standalone app test client: `/preflight` 200, sim run ships with
`egress: none`, live → 501, config-import works, evidence PDF returns `application/pdf`.
Compose files parse; full 5-suite regression still green (flask 10/10, twin stress + mgmt
isolation, contract, pipeline 25k, pdf).

**Phase 1 is complete.**

---

## Phase 2 — Closed-loop promotion (started 2026-05-28)

Turns AEGIS from "validate" into "validate → human-authorize → push, with an audit trail."
**Safe by default — AEGIS never mutates production on its own.**

- `core/promote/connectors.py` — `ProdConnector` protocol. Shipped: `DryRunConnector`
  (records, mutates nothing, the default). `DisabledLiveConnector` is an inert placeholder
  that refuses to run — a real SSH/NETCONF push is an explicit operator-wired extension.
- `core/promote/gate.py` — deterministic approval policy (G1 integrity re-verify · G2
  blocked never promotes / needs_approval requires human approval · G3 medium/high-risk
  requires approver + token · G4 live connector requires `AEGIS_PROMOTE_ALLOW_LIVE=1`).
- `core/promote/promote.py` — runs the gate, pushes via the connector, emits a **sealed
  promotion record** (its own sha256, referencing the source bundle's hash → tamper-evident
  link from "what was validated" to "what was pushed").
- Endpoint: `POST /api/preflight/promote {bundle, approver, approval_token, connector}` —
  default connector `dry_run`; 403 on gate denial.

**Stress (`aegis/tests/promote_test.py`, 6,000 bundles × approval combos):** PASS — across
1,861 promotions and 4,139 denials: 0 blocked promoted, 0 tampered promoted, 0
needs_approval-without-approval, 0 risk-unapproved, 0 dry-run mutations, 0 record-hash
failures, live refused without opt-in. Endpoint verified (dry-run ships, blocked → 403).

GO-LIVE runbook (Linux native binary + macOS docker-clab, triage table): `docs/GO_LIVE.md`.

### Bounded autonomy (landed on main after the 0.2.0 tag)

The Phase 2 gate grew a fifth rule and three supporting packages. Documented in
`docs/ARCHITECTURE.md` §§8–10 and `docs/DEVELOPER.md`.

- `core/llm/` — local-first egress; `AEGIS_AIRGAP=1` refuses cloud, non-loopback, and mDNS
  hostnames at construction; model identity (weights-sha256 or honest identity-claim).
- `core/risk/authority.py` — severity × change-class → AUTO/HITL/HOTL/BLOCK; AS/RD/RT is
  always BLOCK; `AEGIS_MAX_AUTHORIZED_TIER` ceiling (default HOTL).
- `core/seal/` — detached Ed25519 receipt; invalid `AEGIS_SEAL_KEY` refuses to start.
- `core/promote/gate.py` **G5** — re-derives the ceiling at promote time; missing authority
  fail-closes.
- `HttpBackend.parse_nornir_bgp` counts IPv4 **and** IPv6 peer rows; unparseable LLM output
  raises `generation_failed`.
- DISA STIG CISC-RT-000480 / 000050 bind authentication to the routing peer, not a stray
  key-chain token.

Remaining Phase 2: implement + audit a real SSH/NETCONF connector behind the gate, RBAC/SSO,
multi-tenant hosting, Linux live-twin end-to-end run, eval corpus / golden traces.
Hardware-PIV signer + compiled-in ceiling: `docs/PIV_HARDWARE_SIGNER_PLAN.md`.

---

## Phase 3 — Evidence authenticity  ·  software closed 2026-08-29

HMAC approvals and API auth close the two remaining honesty holes in the promotion
path (improvement plan T1 #9 and T1 #10). Hardware PIV stays later — it needs a
token in hand.

- `core/promote/tokens.py` — `aegis1.<payload>.<mac>` HMAC-SHA256 tokens bound to
  bundle sha256 + approver + expiry. `AEGIS_APPROVE_KEY` unset = `asserted-unverified`.
- `core/promote/gate.py` G2/G3 consume `verify_approval`. A random string is a deny
  once the key is set.
- `core/promote/promote.py` writes `approval.method` + `token_sha256` (never the raw
  token). Empty `generated_configs` is `PromoteDenied`.
- `serve.py` — `X-Aegis-Key` on mutating routes when `AEGIS_API_KEY` is set. Pinned
  `AEGIS_SEAL_KEY` without an API key is `SystemExit`. New:
  `GET /api/status`, `POST /api/approve/mint`, `POST /api/preflight/promote`.
- Tests: `tests/tokens_test.py` in CI; promote P8; api_test auth + mint + promote.

### OSCAL AR + CAB export  ·  2026-08-29

Closes the two remaining *software* items on Phase 3. Hardware PIV stays later.

- `evidence/oscal.py` — AEGIS-shaped OSCAL 1.1.2 Assessment Results. Remarks admit
  this is not a FedRAMP package. Integrity.sha256 is self-consistency; authenticity
  is the detached seal.
- `evidence/cab.py` — one-page CAB packet. `rollback.verified_in_twin` is always
  false (plan generated, reversal not executed).
- `POST /api/preflight/evidence/oscal` and `/cab` — same 400/422 integrity gate as PDF.
- Tests: `tests/oscal_test.py` in CI.

Phase 3 software is closed. Remaining on this phase: YubiKey PIV
(`docs/PIV_HARDWARE_SIGNER_PLAN.md`) when the hardware is on the desk.
Live SSH/NETCONF connector, batfish sidecar, and RBAC stay later.
