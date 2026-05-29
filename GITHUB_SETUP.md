# Push AEGIS to GitHub

Run these on **your Mac** (the Cowork sandbox can't touch `.git` on the mounted disk and has
no GitHub credentials — your Mac has both). Everything below is copy-paste ready.

## 1. Community core → its own public repo

A partial `.git` may exist from the agent's attempt — start clean:

```bash
cd /Users/georgigaydarov/02_Projects/Network_Automation/VSS_Code_Georgi/aegis
rm -rf .git
git init -b main
git add -A
git commit -m "AEGIS v0.1 — air-gapped change-validation core (sim tier)"
```

Create the GitHub repo and push (pick one):

```bash
# with the GitHub CLI:
gh repo create gesh75/aegis --public --source=. --remote=origin --push

# or manually (create the empty repo on github.com first, then):
git remote add origin git@github.com:gesh75/aegis.git
git push -u origin main
```

### Description + topics (makes the repo page look finished)

```bash
gh repo edit gesh75/aegis \
  --description "Air-gapped, self-hosted pre-deployment network change validation. Validate a change against a REAL containerlab digital twin behind your perimeter and emit a sealed, PCI/SOC2/NIST-mapped evidence bundle. Zero egress." \
  --add-topic network-automation --add-topic containerlab --add-topic digital-twin \
  --add-topic change-validation --add-topic air-gapped --add-topic compliance \
  --add-topic netdevops --add-topic self-hosted-llm --add-topic batfish --add-topic aiops
```

### Tag the release

```bash
git tag -a v0.1.0 -m "AEGIS v0.1.0 — community core"
git push origin v0.1.0
gh release create v0.1.0 --title "AEGIS v0.1.0" --notes-file CHANGELOG.md
```

The repo page will render `docs/architecture.svg` (embedded at the top of the README), the
badges, the comparison table, and the test matrix. It is fully standalone:
`docker compose up` → `http://localhost:8088/preflight`.

## 2. Integrated changes → the DCN_Network_Tool repo

The twin endpoints + app wiring belong to the integrated product, not the community core.
They live in the existing `DCN_Network_Tool` repo (which already has remotes):

```bash
cd /Users/georgigaydarov/02_Projects/Network_Automation/VSS_Code_Georgi/04_Scripts_Tools/DCN_Network_Tool
git add src/preflight_twin.py src/preflight_run.py \
        src/tests/test_preflight_flask.py src/tests/test_preflight_twin.py src/app.py
git commit -m "AEGIS preflight: twin endpoints + /api/preflight/run + promote, wired into app.py"
git push        # to your gesh-ai-network-tool / multivendor-ai-network-lab remote
```

The project `CLAUDE.md` (AEGIS section + env knobs) is in the `VSS_Code_Georgi` working repo;
commit it there if/when you version that tree.

## 3. Sanity after cloning fresh

```bash
git clone git@github.com:gesh75/aegis.git && cd aegis
pip install -r requirements.txt
python -m aegis.tests.stress_test 25000      # expect: STRESS RESULT: PASS
python -m aegis.tests.promote_test           # expect: PROMOTE GATE TEST: PASS
python -m aegis.serve                        # open http://localhost:8088/preflight
```
