# AEGIS — Launch Post (LinkedIn)

Final, ready to paste. Attach `overview_video.mp4` (silent, 64s) as **native video**
(LinkedIn autoplays muted — the on-screen captions carry the message). Keep the link in
the first comment if you want max reach, or inline if you don't care about the algorithm tax.

---

## Primary (≈190 words)

Network change is still the #1 cause of outages — because for most of us, production is the
only place a change ever really gets tested. Network engineering never got a staging
environment.

The newer tools that fix this — Forward Predict, NetPilot — are cloud by architecture. So the
networks that most need pre-deploy validation (banks, telcos, government, healthcare) are the
ones that legally can't use them. You can't send topology and running-config off-prem.

That's the gap. So I built AEGIS — open-source, air-gapped change validation that runs
entirely inside your perimeter.

Describe a change, or paste a running-config. AEGIS spins a real containerlab digital twin of
the affected slice — isolated by its own name, network and subnet — applies the change, and
watches BGP/EVPN actually converge on real vendor control planes. Then it tears the twin down
and emits a sealed evidence bundle: the verified outcome, a rollback plan, and control results
mapped to PCI / SOC 2 / NIST, with a SHA-256 seal and egress: none.

Guarded-agentic by design: the LLM only proposes the config. Everything after is deterministic
verification, and a human authorizes the push — AEGIS never touches production on its own.

Self-hosted LLM. `docker compose up`. Apache-2.0. 6 test suites, 0 violations.

github.com/gesh75/aegis

---

## Short variant (≈110 words)

Network change is still the #1 cause of outages — because production is the only place we
ever actually test a change.

The tools that fix this (Forward Predict, NetPilot) are cloud-only, so regulated networks that
legally can't send config off-prem are locked out.

So I built AEGIS: open-source, air-gapped change validation. Describe a change (or paste a
config) → it spins a real containerlab digital twin inside your perimeter, applies it, watches
BGP/EVPN converge, and emits a sealed, PCI/SOC2/NIST-mapped evidence bundle. The LLM only
proposes; everything after is deterministic verification; a human authorizes the push. Zero
egress. `docker compose up`. Apache-2.0.

github.com/gesh75/aegis

---

## Pre-post checklist (from LAUNCH_PLAN.md)
- [ ] CI "tests passing" badge is **live and green** before posting (Day 0 gate).
- [ ] Upload `overview_video.mp4` as native video (not a YouTube link).
- [ ] First comment: the one-line wedge + a 3-line "why I built it."
- [ ] Repo README embeds the video + architecture.svg.

## Quality-gate notes (why it reads this way)
- One claim: regulated networks are locked out of cloud-only validation; AEGIS is the
  air-gapped answer. Everything supports that wedge.
- Specifics over adjectives: containerlab, BGP/EVPN, SHA-256, PCI/SOC 2/NIST, 6 suites / 0
  violations, `docker compose up`.
- No hype words, no "excited to share," no reply-farming question at the end.
- The "guarded-agentic" line pre-empts the #1 skeptical reply ("you let an LLM touch prod?").

## Video assets produced
| File | Length | Audio | Use |
|---|---|---|---|
| `docs/overview_video.mp4` | 64s | silent (captioned) | **LinkedIn** native autoplay |
| `docs/overview_video_narrated.mp4` | 129s | VO (offline TTS) | README embed · Show HN · blog/YouTube |
