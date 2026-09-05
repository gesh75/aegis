# Changelog

All notable changes to AEGIS. Format follows [Keep a Changelog](https://keepachangelog.com);
versioning is [SemVer](https://semver.org).

## [Unreleased]

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
- **HMAC mint requires API auth**: `AEGIS_APPROVE_KEY` without `AEGIS_API_KEY` is
  `SystemExit` at start and `503` on `POST /api/approve/mint`. Same class as pinned
  seals — an unauthenticated mint was a signing oracle for valid G2/G3 tokens.
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
