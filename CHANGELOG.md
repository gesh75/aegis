# Changelog

All notable changes to AEGIS. Format follows [Keep a Changelog](https://keepachangelog.com);
versioning is [SemVer](https://semver.org).

## [Unreleased]

### Security: review findings on PR #40
- **Air-gap is now the default (high).** The cloud fallback and non-loopback model URLs used
  to be allowed unless `AEGIS_AIRGAP=1` was set. Now only an explicit `AEGIS_AIRGAP=0` opts
  out, and a missing or mistyped value stays air-gapped. `HttpBackend.generate_config`,
  which calls the model runner directly, now enforces the same loopback check.
- **Rejected preflights are ledgered.** Every guard and pipeline rejection appends
  `preflight_rejected` (stage and reason only, never the configs). Denied mints append
  `approval_mint_denied`. A non-object JSON body is a 400, not a 500.
- Docs qualified:
  - the twin is containerlab in the live tier and a simulator in the community tier;
  - the OSCAL export is "AEGIS-shaped, not schema-validated";
  - Forward's on-prem deployment applies to Enterprise, and Predict's parity is unknown;
  - NetPilot's air-gap option is a vendor claim;
  - ingesting IP Fabric or Forward results is proposed, not built.

### Intent checks via Batfish: reachability, ACL, BGP, references (bundle v1.4)
Closes the biggest gap from the strategy doc, G1 (reachability and ACL analysis).

- `core/intents/`: a declarative intent spec in JSON or YAML. Unknown kinds or fields are
  rejected. The fail-closed evaluator runs a **before/after differential** against a
  reference snapshot and flags regressions. A parse-fidelity gate turns every intent into
  `error` when the candidate doesn't parse. A vacuous `allow` (no matching flow) is an
  error, not a pass.
- Snapshot materialization: Junos `set` deltas are merged onto the base config, other
  vendors need a full-config replacement, and file names are sanitized.
- A pybatfish oracle runs against an in-perimeter `batfish/allinone` (optional
  `requirements-batfish.txt`). Snapshots are uploaded under unique names and deleted.
- Pipeline: a failed or un-evaluable intent sets the verdict to `blocked`, with risk and
  severity treated like a static-analysis error. Results are sealed under
  `validation.intents` (schema **v1.4**).
- API: `intents` in `POST /api/preflight/run`, and an org baseline via
  `AEGIS_INTENTS_PATH` (invalid means the server refuses to start). `/api/status` reports
  the engine. New metric: `aegis_intent_results_total{status}`.
- Evidence: the PDF has an intent table (before → after, control, example flows), and
  CAB and OSCAL include intent observations and findings. The UI shows intent chips.
- Tests: `intents_test` (51 checks, fixture oracle) and a **new CI job `batfish`** running
  `batfish_live_test` against a real `batfish/allinone`.
- Docs: `docs/INTENTS.md`.

### Docs: competitive landscape and positioning correction (2026-10-23)
- `docs/STRATEGY_2026-10.md` §3 adds a sourced market map (12 vendors and categories), two
  capability matrices (assurance depth; governance and evidence), ranked gaps and
  advantages, market signals, a recommendation (AEGIS + Batfish pilot) and RFP questions.
  Every claim carries a Confirmed / Inferred / Unknown label.
- **Positioning corrected.** README and Pages no longer say Forward and NetPilot are
  "cloud-by-architecture". Forward Enterprise documents on-prem deployment (Predict's
  on-prem parity is unknown), Forward Predict went GA on 2026-09-29, and NetPilot *claims*
  an air-gapped option (vendor claim, partly contradicted by its pricing page). AEGIS is now positioned as
  the open-source, offline-verifiable evidence and governance layer.
  `docs/PHASES.md` is annotated, not rewritten. The older launch copy is flagged in the
  strategy doc (§8).

### 2026-10 security & product audit (bundle v1.3)

Driven by a cross-session audit: the earlier review's findings A1–A10, re-checked against the code, plus new
findings. Full analysis, competitor matrix and roadmap: `docs/STRATEGY_2026-10.md`.

#### Security
- **Promotion gate authenticates the bundle (A1).** New rule **G0**: the server verifies the
  detached Ed25519 seal against its pinned key before any other rule runs.
  `POST /api/preflight/promote` always requires it (`require_seal=True`). Previously G1 only
  re-hashed the bundle, so a client could forge a `ship_ready`/low bundle, recompute the
  sha256, and pass.
- **Exports verify the seal.** PDF, OSCAL and CAB return 422 for a present-but-invalid seal,
  which used to render as an "offline-verifiable receipt". Every artifact now carries an
  `authenticity` line ("seal verified …" or "UNSEALED — integrity self-consistency only").
- **Separation of duties (A2).** The gate and `/api/approve/mint` deny approver == operator
  whenever approval is required.
- **Approver identity registry (A2).** With `AEGIS_APPROVER_KEYS` (`name:sha256` entries),
  minting requires the approver's own `X-Aegis-Approver-Key`, and the identity is taken from
  that credential, not from the request body or the shared API key.
  `python -m aegis.core.promote.approvers <name>` generates entries.
- **Single-use approval tokens (A4).** HMAC tokens are claimed atomically in the ledger
  before the first push. A replay is denied, including after a restart.
- **Hash-chained audit ledger (A5).** `evidence/ledger.py` records runs, mints, promotions,
  denials and consumed tokens, in JSONL with an fcntl lock when `AEGIS_LEDGER_PATH` is set.
  `GET /api/ledger/verify` re-walks the chain, and a broken chain refuses to load.
- **Production mode (A3).** With `AEGIS_MODE=production`:
  - the server refuses to start unless API key, approve key, seal key, ledger path and
    approver registry are all set;
  - `asserted-unverified` approvals are denied;
  - only v2 tokens are minted;
  - `change_ref` is required and run-time `approver` is rejected;
  - exports need a seal (blocked verdicts excepted);
  - internal errors are not echoed to clients.
- **Container (A6).**
  - The server now listens on `0.0.0.0` *inside* the container. It used to inherit the
    127.0.0.1 default, so the published port was unreachable.
  - Gunicorn (1 worker, 8 threads) replaces the Flask dev server.
  - Non-root UID 10001, `HEALTHCHECK` on `/healthz`.
  - Compose publishes on `127.0.0.1` only, with a read-only root FS, `cap_drop: ALL`,
    `no-new-privileges` and a ledger volume.
  - `.dockerignore` keeps `.git`, docs, videos and tests out of the image.
  - The air-gap overlay resets `ports` (it conflicted with `network_mode: none`).
- **CI (A7).** All 15 suites run in CI. The five that back the seal, ceiling and egress
  claims were previously local-only, and `hardening_test` is new. New `security` job:
  Bandit, gating on HIGH, plus pip-audit. New `container` job: build, non-root assertion and
  a smoke run. Dependabot added, plus `SECURITY.md`.
- Runtime vs dev requirements split. jsonschema moves from the 2019 3.2.0 pin to the
  test-only `>=4.17`.

#### Fixed — evidence honesty
- `rollback.tested_in_twin` was set to *forward convergence*, so bundles, PDFs and the UI
  said "tested in twin: yes" for a rollback that was never executed. It is now `false`, with
  `rollback.verification: "plan-only"`.
- The rollback plan is vendor-aware:
  - IOS/EOS/FRR: `no …` inside its parent mode;
  - Junos: `delete …`, plus `commit confirmed` / `rollback 1`;
  - restoring a deleted value is flagged, never guessed.
  For real CLI lines the plan used to read "revert -> <same line>".
- **Secrets are redacted** in PDF configs and rollback steps (`evidence/secrets.py`). This
  covers cleartext, Cisco type 7, Junos `$9$` and hashes.
- Every bundle string is escaped before it enters ReportLab markup. Device names or config
  lines containing `<` previously returned a 500 or injected markup.
- OSCAL export: RFC 4122 UUIDs, plus `import-ap`, `last-modified`, observation `collected`,
  and finding `target`. The `change-ref` prop and authenticity remark are new.

#### Fixed — compliance accuracy (affects verdict rows)
- **Junos support.** Hierarchical `{ }` configs are flattened to `set` lines, and inactive
  statements are dropped. DISA BGP checks understand Junos peers authenticated at neighbor,
  group or global level, and per routing-instance. Previously every Junos BGP peer was
  invisible to CISC-RT-000480.
- **Real plaintext-secret detection** replaces the `abc123` demo predicate:
  - Cisco type 0 and bare passwords, key-string, OSPF and AAA keys;
  - SNMP v1/v2c communities;
  - Junos keys not in `$9$` form.
  Type 7 and `$9$` are reported as reversible, not failed (a policy decision; see the
  strategy doc).
- **DISA CISC-RT-000050 no longer passes MD5.** `message-digest` / `authentication mode`
  counted as FIPS 198-1. Now only HMAC-SHA, AES-CMAC or TCP-AO pass. Junos GTSM
  (`ttl-except 255`) is recognized.

#### Added
- `change_ref` (ITSM change number), sealed into the bundle as schema v1.3 and shown in the
  PDF, CAB and OSCAL.
- `python -m aegis.verify`: an offline auditor CLI for integrity, seal (pinned public key)
  and ledger chain. Exit codes are 0, 1 and 2.
- `/metrics` (Prometheus text format: runs by decision, promotions, denials, seal verifies,
  exports, ledger size) and `/healthz`.
- UI: change-ref and API-key fields; labs match the backend; all 11 frameworks.
  **The hard-coded `approver: "noc-lead"` was removed**, so the demo no longer self-approves
  high-risk changes.

- `AEGIS_PEER_AS_POLICY=hitl` (opt-in; the default `block` is unchanged): a `remote-as` or
  `peer-as` change, meaning a BGP neighbor add, becomes a peering change at HITL minimum.
  `router bgp N`, `local-as`, `autonomous-system`, RD and RT stay BLOCK. Previously no BGP
  neighbor add could ever be sealed or promoted.
- `HttpBackend` rejects non-http(s) URLs (Bandit B310).
- **Off-box ledger anchor.** `AEGIS_LEDGER_SYSLOG=host:port[/tcp|/udp]` sends every
  hash-chained entry to the SIEM as RFC 5424, using the stdlib only. It is best-effort: a SIEM
  outage never blocks a change. Failures are exposed as `aegis_ledger_anchor_failures_total`.
- **CSP drops `script-src 'unsafe-inline'` (A10).** The UI script moved to `/preflight.js`
  and handlers are wired with `addEventListener` and event delegation. This was verified in
  headless Chromium under the real header: zero CSP violations, and run, PDF download and
  the source toggle all work. `style-src 'unsafe-inline'` remains.

#### Performance
- `ComplianceSignal.text()` and the secret scan are memoized. With 11 frameworks the sim
  pipeline goes from 0.80 to 0.43 ms per run (about 1.9×).

### Earlier unreleased items

Post-0.2.0 hardening that landed on `main` after the 0.2.0 tag. Documented here so
operators can see fail-closed behavior that is already in the code.

### Added
- **OSCAL Assessment Results export**: `evidence/oscal.py` `to_oscal(bundle)` plus
  `POST /api/preflight/evidence/oscal`. AEGIS-shaped AR JSON (OSCAL 1.1.2 structure).
  Honest: not a FedRAMP authorization package. Integrity must verify (same 400/422
  contract as the PDF).
- **CAB one-pager**: `evidence/cab.py` `to_cab(bundle)` plus
  `POST /api/preflight/evidence/cab`. What changed, which intents still hold, rollback
  plan. `rollback.verified_in_twin` is always false — the reversal was not executed.

### Fixed
- **Fail-closed Idle BGP / empty apply / empty configgen** (#17): Nornir `status==ok`
  no longer invents a session. Idle or empty results never converge. Twin-apply requires
  `applied: true`. Empty/blank LLM `configs` raise `generation_failed`.
- **DISA STIG peer binding**: CISC-RT-000480 / CISC-RT-000050 require authentication on
  the actual `neighbor` (or IGP interface). A leftover `key chain` / HMAC token in the
  same file no longer produces a pass.
- **IPv6 BGP session count** (`http_backend.parse_nornir_bgp`): peer rows now match IPv4
  **and** IPv6 neighbor addresses. Established = numeric `PfxRcd` or `Estab*`. The
  contract fixture (`NORNIR_IPV6`) expects two IPv6 Established sessions.
- **IPv6 parser ReDoS**: a malformed flood of `:` no longer hangs the parser; the
  contract suite treats it as zero sessions (`bgp_up == 0`).

### Security
- **HMAC v2 config + inventory binding** (#24): `mint_token_for_bundle()` and
  `POST /api/approve/mint` with a `bundle` emit v2 tokens bound to the grounded-config
  hash and target inventory fingerprint. G2/G3 deny on config or inventory drift.
  `POST /api/preflight/promote` accepts `inventory_sha256` as a live override.
  Hash-only mint still emits v1. Unknown versions fail closed.
- **HMAC-signed approval tokens** (T1 #9): when `AEGIS_APPROVE_KEY` is set, G2/G3 require
  an `aegis1.<payload>.<mac>` token bound to the bundle sha256, the approver, and an
  expiry. A random non-empty string is a deny. Unset key stays the honesty tier
  (`asserted-unverified`) so community tests and air-gap demos keep working. Promotion
  records store `approval.method` + `approval.token_sha256` — never the raw token.
  `POST /api/approve/mint` and `POST /api/preflight/promote` are now on the community
  server.
- **API-key header** (T1 #10): when `AEGIS_API_KEY` is set, mutating routes require
  `X-Aegis-Key` (constant-time compare). A pinned `AEGIS_SEAL_KEY` without an API key
  refuses to start — unauthenticated deploys never mint pinned-key seals. Public:
  `/api/status`, `/api/seal/pubkey`, `/api/seal/verify`.
- **Air-gap LLM URLs**: `is_loopback` rejects mDNS `.local` and any non-literal hostname.
  Only `127.0.0.0/8`, `::1`, `localhost`, and `ip6-localhost` are trusted. No DNS lookup.
- **CI workflow tokens**: `permissions: contents: read` and
  `persist-credentials: false` on checkout.

### Docs
- Live architecture page no longer loads remote Mermaid from a CDN (air-gap safe).
- **Evidence runbook** (`docs/EVIDENCE.md`): `integrity.sha256` is self-consistency;
  the detached Ed25519 receipt is origin + ceiling proof. Documents that
  `POST /api/preflight/evidence/pdf` calls `bundler.verify` only (not `verify_seal`),
  plus the auditor path (`/api/seal/pubkey`, `/api/seal/verify`, G0–G6).
- Pages (`docs/index.html`) now advertises **v0.2.0**, G1–G5 + HMAC, 8+ CI suites,
  11 frameworks, OSCAL/CAB exports, and does not call the content hash a seal.

## [0.2.0] — 2026-06-12

Hardening release driven by a 16-agent adversarially-verified review (security,
quality, compliance-domain, API/UI lenses) — see `docs/IMPROVEMENT_PLAN_2026-06.md`.

### Fixed
- **Compliance defensibility**: NIST 800-53 CM-3, SOC 2 CC8.1 and NERC CIP-010-R1.2 no
  longer assert "verified in digital twin" unconditionally — they now gate on a recorded,
  converged twin run and report `not_applicable` otherwise (mirrors the HIPAA pattern).
- **PCI DSS v4 control id**: strong-cryptography-for-authentication check relabeled
  8.3.1 → 8.3.2 (the correct requirement number) across module, docs and sample bundles.
- **BGP convergence parser** (`http_backend.parse_nornir_bgp`): the Established-session
  count matched any digit-terminated line; it now matches real peer rows only
  (neighbor IP + numeric/Estab state column) and fails closed on a malformed response.
- Missing runtime dependency `httpx` added to requirements.txt; `/favicon.ico` 404 noise.

### Security
- **Evidence PDF endpoint verifies the bundle sha256** before rendering — a body whose
  fields no longer match `integrity.sha256` is rejected with 422. That check is
  self-consistency, not origin authentication: a client that computes the public hash
  over invented content still gets a PDF. Cryptographic authenticity is
  `POST /api/seal/verify` / `verify_seal` (G0–G6 against the pinned key). See
  `docs/EVIDENCE.md`.
- **Seal key fails closed**: an invalid `AEGIS_SEAL_KEY` now refuses to start instead of
  silently degrading to an ephemeral key.
- **LLM output fails closed**: unparseable generation raises `generation_failed` instead
  of synthesizing a no-op stub config that would sail through validation to `ship_ready`.

## [0.1.0] — 2026-05-28

First public release of the community core. Air-gapped, self-hostable, sim-tier — the whole
change → twin → validate → evidence loop, proven offline.

### Added
- **Deterministic preflight pipeline** (`core/orchestrator/pipeline.py`): intent | config-import
  → guard → generate (LLM) → batfish → twin → diff → compliance → risk-tier → rollback →
  verdict → sealed evidence bundle. The LLM is the only non-deterministic step.
- **Pluggable backends** (`core/backends/`): in-process `SimulatorBackend` (CI/offline) and
  `HttpBackend` for a live `:5757` stack, behind a single `Backend` protocol.
- **Evidence** (`evidence/`): JSON-Schema-validated bundle, sha256 integrity seal, grounded-
  command provenance, `egress: none` invariant, PCI-DSS/SOC2/NIST control crosswalk, and an
  examiner-ready PDF renderer.
- **Config-import path**: paste a sanitized running-config instead of an NL intent — no LLM in
  the loop, the most auditable mode.
- **Throwaway digital twins** (integrated product): `POST /api/preflight/twin/{spawn,apply,
  destroy}` clone a topology under a unique `twin-…` name with an isolated mgmt network +
  subnet, so a twin runs alongside production without collision. Six enforced safety
  invariants (prod isolation, lab allowlist, shell-injection guard, concurrency cap, idempotent
  destroy, arg-list-only commands).
- **Phase 2 — closed-loop promotion** (`core/promote/`): deterministic approval gate +
  dry-run connector. Never auto-pushes to production; blocked/tampered/unapproved changes are
  denied; the live connector is inert without explicit opt-in.
- **UI** (`ui/preflight_screen.html`): self-contained dashboard — verdict, twin, grounded
  config, compliance, evidence PDF download.
- **Packaging**: standalone `serve.py`, `Dockerfile`, `docker-compose.yml`, air-gap overlay
  (`docker-compose.airgap.yml`, `network_mode: none`), Apache-2.0 license.
- **Docs**: `docs/PHASES.md` (full project log), `docs/GO_LIVE.md` (live-run runbook),
  `docs/architecture.svg`.

### Tested
- 6 suites, **0 violations**: pipeline invariants (25k adversarial runs + concurrency),
  HttpBackend contract (vs real API shapes), evidence PDF (1.5k bundles), promotion gate (6k
  bundles), Flask test-client (10/10), twin safety + mgmt isolation (8k ops).

### Security / safety invariants
- Zero egress is structural (`integrity.egress: "none"`, air-gap overlay).
- The LLM proposes; deterministic code verifies; a human authorizes any promotion.
- Tamper-evident bundles (sha256) and promotion records.

[0.1.0]: https://github.com/gesh75/aegis/releases/tag/v0.1.0
