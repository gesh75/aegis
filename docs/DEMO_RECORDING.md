# AEGIS — Real-Product Demo: shot list

A real screencast beats the animated explainer for a technical audience. Keep the animated
`overview_video.mp4` as the 60s hook; record this as the proof. Target: **75–110s**, 1280×720+,
captions over silent capture (or VO from `overview_narration.md`).

**Record with:** macOS `Cmd+Shift+5` (region) or OBS for 1080p; terminal via `asciinema` or just
capture the window. Pre-size the browser to 1280×720 so it matches the animated cut.

## Setup before recording
```bash
# in one terminal — the sim-tier server (no clab/LLM needed for the UI proof)
cd .../VSS_Code_Georgi/aegis && python -m aegis.serve     # → localhost:8088/preflight
```
Have a second terminal ready at the repo root for the test run.

## Shots (in order)

**1 · The claim being tested (0:00–0:08)**
Terminal, type and run — let it scroll to green:
```
python -m aegis.tests.promote_test 6000
```
Caption: "The safety gate, 6,000 adversarial cases — 0 violations."

**2 · A change that should ship (0:08–0:30)**
Browser at `/preflight`. Type: `add VLAN 40 to leaf-1`. Click **Run PreFlight**.
Let the panels fill: SHIP READY (green), twin converged, BGP before→after, grounded config,
compliance all-pass. Caption: "Describe a change → verified in a twin → sealed evidence."

**3 · A change that should NOT ship (0:30–0:55)**
Switch source to **paste config**. Paste:
```
neighbor 10.0.0.1 remote-as 65020
set bgp authentication-key plaintext abc123
```
Run. Show BLOCKED (red), and the evidence panel: **PCI 8.3.1 · fail**, Batfish finding
"plaintext BGP auth-key". Caption: "It catches the unsafe change and maps it to the control."

**4 · The artifact (0:55–1:05)**
Click **⬇ Download evidence PDF**. Open it. Scroll the verdict, compliance table, and the
`egress: none` + sha256 footer. Caption: "An examiner-ready bundle. Nothing left the box."

**5 · Proof it's real, not a demo (1:05–1:15)**
Cut to the GitHub Actions run (the green 6/6) and the README badge. Caption: "CI-checked.
github.com/gesh75/aegis."

## Optional — the LIVE tier (record on a Linux host or Mac w/ Docker)
To show the *real* containerlab twin (the thing the posts now scope to the live tier):
```
# start the :5757 stack, set live env (see docs/GO_LIVE.md), then:
curl -s -X POST localhost:5757/api/preflight/twin/spawn -H 'Content-Type: application/json' \
  -d '{"lab":"minimal"}'        # show the twin_id + nodes
docker ps | grep clab-twin-     # the real containers, alongside prod, isolated
```
Then a live-mode PreFlight in the UI. This is the only footage that should be captioned
"real containerlab twin"; the sim shots above are captioned "validated in a twin (sim tier)."

## Assembly
- Trim, add captions (CapCut / iMovie / DaVinci — all free).
- Two cuts, mirroring the existing pair: a ~75s **silent+captioned** for LinkedIn-native, and a
  longer **narrated** cut (VO from `overview_narration.md`, adapted to these real shots) for the
  README/Show HN.
- Replace `overview_video.mp4` as the LinkedIn asset, OR lead with the animated hook and cut to
  this — hook (15s animated) + real demo (60s) is the strongest single video.

## Honesty rule (matches the posts)
Caption sim shots as "sim tier"; reserve "real containerlab twin / real vendor control planes"
for the live-tier shots in the optional section. Same line the launch copy now draws.
