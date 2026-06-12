# AEGIS 0.2 — LinkedIn post (Tuesday, June 16, 2026 · ~9:00 AM ET)

**Attach:** AEGIS_Carousel_2026-06-16.pdf (7-slide carousel)

---

Your change window opens at 2 AM. The config is written. Everyone *thinks* it's fine.

What if you could run it against a real digital twin of your network first — BGP converging, routes diffing, blast radius measured — without a single byte leaving your perimeter?

That's AEGIS, and version 0.2 just shipped. Open source, Apache 2.0.

𝗪𝗵𝗮𝘁'𝘀 𝗻𝗲𝘄:

→ 11 compliance frameworks, mapped automatically: NIST 800-53/800-171/CSF 2.0, PCI DSS v4, SOC 2, HIPAA, ISO 27001, CIS v8, DISA STIG, NERC CIP, IEC 62443. Every change emits a sealed, examiner-ready evidence bundle.

→ Evidence you can defend. A control only claims "verified in digital twin" when a converged twin run is actually recorded. No twin? It says not_applicable — honestly. Tampered bundle? The PDF endpoint rejects it.

→ Ed25519-sealed bundles you can verify offline, years later.

𝗧𝗵𝗲 𝗽𝗮𝗿𝘁 𝗜'𝗺 𝗺𝗼𝘀𝘁 𝗽𝗿𝗼𝘂𝗱 𝗼𝗳: before this release, I pointed a 16-agent adversarial AI review swarm at my own code — 4 lenses (security, code quality, compliance-domain correctness, API/UI), every HIGH finding independently re-verified before I touched anything.

It caught a BGP parser that overcounted Established peers, a PCI control labeled 8.3.1 that should have been 8.3.2, and compliance claims not backed by twin evidence. All fixed and shipped — that's what "evidence-grade" has to mean.

The design invariant stays the same: 𝘁𝗵𝗲 𝗟𝗟𝗠 𝗽𝗿𝗼𝗽𝗼𝘀𝗲𝘀, 𝘁𝗵𝗲 𝗽𝗶𝗽𝗲𝗹𝗶𝗻𝗲 𝘃𝗲𝗿𝗶𝗳𝗶𝗲𝘀. Only config generation touches the model. Everything after is deterministic — Batfish, containerlab, diff, verdict.

Try it (runs fully offline, docker compose up):
🔗 github.com/gesh75/aegis
📖 gesh75.github.io/aegis

If you run a network that legally can't send configs to someone else's cloud — this was built for you. What would you preflight first?

#NetworkEngineering #NetworkAutomation #Compliance #AI #OpenSource #DigitalTwin #NERC #PCIDSS

---

## Posting notes
- Tuesday 9:00–10:00 AM ET is the engagement window.
- Reply to first comment with the docs link to keep the post link-free for reach.
- Pin to Featured after 24h.
