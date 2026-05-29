# AEGIS — Launch Plan

Repo is live: **github.com/gesh75/aegis** (v0.1.0, Apache-2.0). This is the plan to take it
from "pushed" to "known."

## 1. Assets (status)

| Asset | Status | Where |
|---|---|---|
| Repo + README + diagram + release | ✅ done | github.com/gesh75/aegis |
| Architecture diagram (SVG) | ✅ done | `docs/architecture.svg` |
| Overview video (animated) | ✅ done | `docs/overview_video.html` (screen-record → MP4) |
| Narration script | ✅ done | `docs/overview_narration.md` |
| CI workflow (badge → live) | ⬜ next | `.github/workflows/test.yml` |
| 60–90s MP4 | ⬜ record | from `overview_video.html` |
| Launch posts | ⬜ draft below | LinkedIn · Show HN · NANOG/Slack |

## 2. The one-line positioning

> The air-gapped, self-hosted answer to Forward Predict / NetPilot — validate a network change
> against a **real** containerlab twin behind your perimeter and get sealed, PCI/SOC2/NIST
> evidence. Zero egress.

Lead with the **wedge** (regulated networks can't use cloud tools), not the feature list.

## 3. Make the MP4 (from the animated video)

1. Open `docs/overview_video.html` full-screen in Chrome.
2. Screen-record the stage region (macOS: `Cmd+Shift+5`, or QuickTime; or OBS for 1080p).
3. Record the narration over it (`docs/overview_narration.md`) — or ship it silent with captions.
4. ~70s total. Post natively to LinkedIn (autoplay) + attach to a GitHub Release asset + embed
   in the README (`https://github.com/gesh75/aegis/assets/...`).

## 4. Channels & sequencing

- **Day 0 — CI green + MP4.** Add the GitHub Actions test workflow so the "tests passing"
  badge is live; record the MP4. Don't launch until the badge is real.
- **Day 1 — LinkedIn** (your network of network engineers/architects). Native video + the
  positioning line + link. Best signal-to-effort channel for this audience.
- **Day 2 — Hacker News "Show HN".** Title: *Show HN: AEGIS – air-gapped network change
  validation with a real digital twin (Apache-2.0)*. First comment = the wedge + a 3-line
  "why I built it." Be present for replies.
- **Week 1 — practitioner communities.** r/networking, NANOG mailing list, networktothe
  Slack/Discord, the containerlab + Batfish communities (they'll appreciate the stack).
- **Week 2 — write-up.** A short blog/dev.to post: "Why network change validation has to run
  inside the air gap" — links the repo, embeds the diagram + video.

## 5. Launch post drafts

**LinkedIn**
> Network changes are still the #1 cause of outages — because production is the only place we
> ever really test them. The new tools that fix this (Forward Predict, NetPilot) are cloud-only,
> so regulated networks that legally can't send config off-prem are locked out.
>
> So I built **AEGIS** — open-source, air-gapped change validation. Describe a change (or paste
> a config) → it spins a real containerlab digital twin inside your perimeter, applies it,
> watches BGP/EVPN converge, and emits a sealed, PCI/SOC2/NIST-mapped evidence bundle. The LLM
> only proposes; everything after is deterministic verification; a human authorizes the push.
> Zero egress. `docker compose up`. Apache-2.0.
>
> github.com/gesh75/aegis  [native video]

**Show HN (first comment)**
> I'm a network engineer. Every change ritual ends the same way: review board, fingers crossed,
> production is the test. Forward and NetPilot now do pre-deploy validation, but they're
> cloud-by-architecture — a bank or a gov network can't use them. AEGIS runs the same loop on a
> self-hosted LLM + containerlab, fully offline, and the output is an auditor-grade evidence
> bundle (sha256, egress:none, control-mapped). Guarded-agentic: the model proposes, the
> pipeline verifies, a human approves. 6 test suites, 0 violations. Feedback welcome.

## 6. Metrics to watch (first 30 days)
GitHub stars + forks · unique cloners · Show HN rank/comments · issues opened (signal of real
use) · inbound from regulated orgs (the ICP). A star is vanity; an issue from a bank is the
real funnel.

## 7. Product roadmap that the launch feeds
- **Now:** CI/CD badge, the MP4, the posts.
- **Next (Phase 2 cont.):** an audited SSH/NETCONF live connector behind the gate; Linux
  live-twin end-to-end; eval corpus + golden traces.
- **Later (commercial tier):** hosted twin compute, RBAC/SSO, continuous compliance, the
  examiner-export workflow — the things regulated buyers pay for once the OSS core earns trust.
