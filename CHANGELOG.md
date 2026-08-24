# Changelog

All notable changes to AEGIS. Format follows [Keep a Changelog](https://keepachangelog.com);
versioning is [SemVer](https://semver.org).

## [Unreleased]

### Documentation
- **Evidence runbook** (`docs/EVIDENCE.md`): the two-layer contract — `integrity.sha256`
  is self-consistency; the detached Ed25519 receipt is origin + ceiling proof. Documents
  that `POST /api/preflight/evidence/pdf` calls `bundler.verify` only (not `verify_seal`),
  plus the auditor verify path (`/api/seal/pubkey`, `/api/seal/verify`, G0–G6).

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
