# GitHub Release — v0.1.0 (paste-ready)

**Tag:** `v0.1.0`  ·  **Target:** `main`  ·  **Title:** `AEGIS v0.1.0 — air-gapped change validation`

> When creating the release, drag `docs/overview_video.mp4` into the asset/description box —
> GitHub generates a `…/assets/…` URL that renders an inline player. Paste that URL on its own
> line where marked below (and into the README's commented `INLINE PLAYER` spot).

---

## Release body (copy everything below this line)

Prove a network change **before** it ships — against a real digital twin, entirely inside your perimeter.

<!-- paste the uploaded overview_video.mp4 asset URL on its own line here for an inline player -->

Network change is still a leading cause of outages, because production is the only place most teams ever really test a change. The tools that fix this (Forward Predict, NetPilot) are cloud by architecture — so the networks that most need pre-deploy validation (banks, telcos, government, healthcare) legally can't use them. **AEGIS is the air-gapped, self-hosted answer.**

### What it does
Describe a change, or paste a running-config. AEGIS:
1. **guards** the input, then **proposes** config with a self-hosted LLM (the *only* AI step — config-import skips it),
2. runs a **Batfish** static check,
3. spins a **real containerlab digital twin** of the affected slice — isolated by its own name, network and subnet — applies the change, and watches **BGP/EVPN actually converge** on real vendor control planes (SR Linux, cEOS, FRR), then tears it down,
4. diffs state, maps results to **PCI-DSS / SOC 2 / NIST**, sets a verdict, and emits a **sealed evidence bundle** (SHA-256, grounded-command provenance, rollback plan, `egress: none`) — plus an examiner-ready PDF.

**Guarded-agentic:** the LLM proposes, the pipeline verifies, and a human authorizes the push. AEGIS never mutates production on its own.

### Highlights in 0.1.0
- Deterministic preflight pipeline + pluggable backends (simulator / live `:5757`)
- Real-emulation throwaway twins with mgmt-network isolation
- Sealed, framework-mapped evidence bundle + PDF
- NL-intent **and** config-import paths
- Phase 2 promotion gate (dry-run default, never auto-push)
- Standalone server + Docker + air-gap overlay (`network_mode: none`)

### Verified — 6 suites, 0 violations
pipeline invariants (25k runs) · promotion gate (6k) · twin safety + mgmt isolation (8k) · evidence PDF (1.5k) · API contract · Flask endpoints (10/10)

### Try it (fully offline)
```bash
git clone https://github.com/gesh75/aegis && cd aegis
docker compose up        # → http://localhost:8088/preflight
```
This build runs the full loop against a **built-in simulator** so you can evaluate it on a
laptop. Point it at your own **containerlab + self-hosted LLM** for the real-fabric twin — see
[`docs/GO_LIVE.md`](https://github.com/gesh75/aegis/blob/main/docs/GO_LIVE.md).

Apache-2.0. Full project log: [`docs/PHASES.md`](https://github.com/gesh75/aegis/blob/main/docs/PHASES.md) · go-live: [`docs/GO_LIVE.md`](https://github.com/gesh75/aegis/blob/main/docs/GO_LIVE.md)

---

## gh CLI one-liner (alternative to the web UI)

```bash
gh release create v0.1.0 \
  --title "AEGIS v0.1.0 — air-gapped change validation" \
  --notes-file docs/RELEASE_v0.1.0.md \
  docs/overview_video.mp4 docs/overview_video_narrated.mp4
```
(Note: `--notes-file` will include this whole file's prose; for a clean release, paste the
"Release body" section above into the web editor instead, or split that section into its own
notes file.)
