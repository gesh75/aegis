# AEGIS Demo — Caption Track (paste-ready)

On-screen text overlays for the real-product screencast, timed to the shots in
`DEMO_RECORDING.md`. Two-line max per caption, big and legible (44–56px), bottom-center or
lower-third, white on a 60% black bar. Times assume a ~80s silent+captioned cut — nudge to fit
your actual takes. Honesty rule holds: sim shots say "sim tier"; only the live-tier shots say
"real containerlab twin."

Format:  `[start–end]  CAPTION TEXT`  ( ›director note )

---

## Cut A — silent + captioned (LinkedIn native, ~80s)

**Title card (0:00–0:03)**
`AEGIS — prove a network change before it ships.`
› hold on a static title (or the first frame of overview_video.mp4)

**Shot 1 · the test running (0:03–0:12)**
`The safety gate: 6,000 adversarial cases.`
`0 violations.`
› terminal scrolling `promote_test 6000` → green PASS

**Shot 2 · clean change (0:12–0:32)**
`Describe a change…`            ( ›as you type "add VLAN 40 to leaf-1" )
`…validated in a twin (sim tier).`   ( ›when SHIP READY appears )
`Converged. No sessions dropped.`    ( ›over the twin panel: BGP before→after )

**Shot 3 · unsafe change (0:32–0:55)**
`Now a config with a plaintext BGP key.`   ( ›as you paste it )
`BLOCKED.`                                  ( ›big, when the red verdict lands )
`Auto-mapped to PCI-DSS 8.3.1 — fail.`      ( ›over the compliance row )

**Shot 4 · the evidence (0:55–1:06)**
`One click: a sealed evidence bundle.`
`SHA-256 · rollback plan · egress: none.`   ( ›over the PDF footer )

**Shot 5 · proof (1:06–1:16)**
`Not a demo. 6 CI-checked suites, all green.`
`Open source · github.com/gesh75/aegis`     ( ›hold 2s — end card )

---

## Cut B — extra captions if you add the LIVE-tier shots

**Live twin spawn (insert after Shot 4)**
`Live tier: a REAL containerlab twin.`
`Real SR Linux / cEOS / FRR — isolated, then destroyed.`   ( ›over `docker ps | grep clab-twin-` )

`BGP converges on a real bgpd — not a model.`   ( ›over the live-mode verdict )

---

## End card (both cuts)
`AEGIS · air-gapped change validation`
`docker compose up → localhost:8088/preflight`
`github.com/gesh75/aegis · Apache-2.0`

---

## Lower-third "kicker" (optional, persistent small text top-right)
`AEGIS · PreFlight`  — keep it on screen during the UI shots for brand continuity.

## If you record a voiceover instead of captions
Use `overview_narration.md` but swap any "spins a real containerlab twin" line for
"validated in a twin" during the sim shots; keep the real-twin wording only for the live-tier
footage. Captions and VO should never both run full sentences at once — pick one as primary.
