# AEGIS Overview — Narration Script

Voiceover for `overview_video.html` (~70 s). Times are cumulative and match each scene's
on-screen duration. Tone: calm, confident, engineer-to-engineer. Read slightly under the clock
so each line lands before the scene changes.

---

**Scene 1 · Title (0:00–0:06)**
> "Every network change is a bet on production. AEGIS lets you prove the change before it ships —
> against a real digital twin, entirely inside your perimeter."

**Scene 2 · The problem (0:06–0:12)**
> "Change is still the number one cause of outages. Network engineering never got a staging
> environment — so production becomes the test, and the dangerous misconfigs are the quiet ones."

**Scene 3 · The gap (0:12–0:20)**
> "The tools that fix this — Forward Predict, NetPilot — are cloud by architecture. Banks,
> telcos, government and healthcare networks legally can't send their config off-prem. They're
> locked out. That's the gap AEGIS fills."

**Scene 4 · How it works (0:20–0:28)**
> "It's guarded-agentic. The language model only proposes the config — and you can skip even
> that by pasting a running-config. Every step after the proposal is deterministic verification.
> That's what makes the result auditable instead of 'the AI said so.'"

**Scene 5 · Real twin (0:28–0:35)**
> "AEGIS clones the affected slice into a live containerlab twin — its own name, network and
> subnet, so it never touches production — applies the change, and watches BGP and EVPN actually
> converge. Real control planes. Then it's torn down."

**Scene 6 · Evidence (0:35–0:43)**
> "Out comes the artifact that matters: a sealed evidence bundle. The verified outcome, the
> grounded config, a rollback plan, and control results mapped to PCI, SOC 2 and NIST — with a
> SHA-256 seal and egress: none. Hand it to your auditor."

**Scene 7 · Approval gate (0:43–0:50)**
> "And it closes the loop — with a human in it. A deterministic gate promotes only verified,
> approved changes. Blocked, tampered, or unapproved? Denied. AEGIS never pushes to production
> on its own."

**Scene 8 · Proof (0:50–0:58)**
> "This isn't a demo. Six test suites, zero violations — twenty-five thousand pipeline runs, a
> six-thousand-case approval-gate sweep, twin safety, evidence, and the API contract, all green."

**Scene 9 · CTA (0:58–1:05)**
> "It's open source, Apache-2.0, and it runs offline in one command. Clone it, docker compose up,
> and open the PreFlight screen. AEGIS — on GitHub at gesh-seven-five slash aegis."

---

### Recording notes
- Pause ~0.5 s between scenes; let each headline animate in before the first word.
- For a silent/captioned cut, the on-screen text already carries the message — just record the
  stage and add light background music.
- Keep total under 75 s for LinkedIn-native autoplay; trim Scene 8's list read if needed.
