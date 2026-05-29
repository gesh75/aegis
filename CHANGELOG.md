# Changelog

All notable changes to AEGIS. Format follows [Keep a Changelog](https://keepachangelog.com);
versioning is [SemVer](https://semver.org).

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
