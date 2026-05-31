# Why network change validation has to run inside the air gap

Network engineering never got a staging environment. Application teams have had one for decades: a place to build, deploy a release candidate, run it against tests, and tear it down — all before a single user touches it. Networks skipped that step. The control plane is global and stateful, the "build" is a config push, and the only environment that behaves exactly like production is production. So production became the test environment by default.

That is not a controversial claim. Network changes remain a leading cause of outages, and the reason is structural, not careless. You can review a diff line by line and still not know whether a route-map change will reconverge BGP cleanly, whether an EVPN type-2 route will withdraw the way you expect, or whether a MTU edit will silently black-hole a fabric uplink. Static review tells you the config is *valid*. It does not tell you what the network will *do*.

## The cloud tools solved the wrong half of the problem for us

There is a category of products built to close this gap. Forward Predict offers a mathematical digital twin. NetPilot does cloud emulation. Both are genuinely good at predicting change outcomes. Both are also cloud-by-architecture: your topology and your running configs leave your perimeter to be analyzed.

For a regulated network, that is a non-starter — and not as a preference. Banks, telcos, government, and healthcare operators run under data-residency and architecture-disclosure constraints where the topology and device configuration *are* the sensitive artifact. Sending them to a SaaS analyzer is the exact thing the control framework exists to prevent. The auditor is not asking whether the tool is accurate. The auditor is asking where the data went. "It was encrypted in transit to a third party" is still an answer that fails the question.

So the most validation-hungry networks on the planet are locked out of the tools built to validate them. That is the gap **AEGIS** fills: an open-source (Apache-2.0), self-hosted, air-gapped pre-deployment change validator. The one-command build — `docker compose up`, open `localhost:8088/preflight` — runs the full loop offline against a built-in simulator, so you can try it on a laptop; point it at your own containerlab and self-hosted LLM for the real fabric. Either way, nothing about your network ever leaves the rack.

## Guarded-agentic: the LLM proposes, the pipeline verifies

There is an obvious objection to putting an LLM anywhere near a network change. LLMs are non-deterministic, and a config generator that hallucinates a route target is worse than no tool at all. AEGIS's design answer is to confine the model to exactly one step and make everything downstream deterministic.

A change enters as either a natural-language intent or a pasted running-config, and runs through a fixed pipeline:

- **guard** — input validation and policy gating before anything else happens
- **generate** — the *only* AI step; turns NL intent into candidate config. If you paste a running-config, this step is skipped entirely and no LLM is touched
- **batfish** — static analysis of the candidate config
- **twin** — spawn a throwaway containerlab digital twin
- **apply + watch** — push the change and watch BGP / EVPN actually converge
- **diff** — compare pre- and post-change state
- **compliance** — map control results to frameworks
- **risk tier** — classify the blast radius
- **rollback plan** — generate the back-out
- **verdict** — pass / fail
- **evidence bundle** — sealed, signed output

The model proposes; the pipeline verifies. That split is the whole point. An auditor cannot reason about a probabilistic generator, but they can reason about a deterministic verification chain that runs identically every time and produces the same artifact for the same input. The non-determinism is fenced off upstream of every decision that matters. And because config-import skips the generate step, the highest-assurance path — validate a change a human already wrote — has no AI in it at all.

The self-hosted LLM (Qwen3 via Ollama, for example) means even the one AI step keeps data inside the perimeter.

## A real twin, not a model of one

The validation core is emulation, not approximation. The twin is a real containerlab fabric running real vendor control planes — Nokia SR Linux, Arista cEOS, FRR — booting their actual routing daemons. When AEGIS says BGP converged, it is because BGP converged on a real `bgpd`, not because a solver concluded it should. (The open-source quickstart runs this loop against a simulator so you can evaluate it on a laptop; the real-fabric twin is the self-hosted tier — see `docs/GO_LIVE.md`.)

A mathematical twin reasons over a model of protocol behavior. That is fast and it scales, but it is only ever as correct as the model. A real twin runs the same software image that will run in production, so it surfaces the messy, vendor-specific, timing-dependent behavior a model abstracts away — the exact class of failure that makes change windows go sideways.

Running real containers next to production raises a collision question, and AEGIS isolates by construction: each twin gets a unique name, its own management network, and its own subnet, so it runs alongside production without touching it, then is destroyed when the run completes. Twin-safety and management-isolation are not assumed — they are tested across 8,000 operations with zero violations.

## The evidence bundle is the thing auditors actually want

A green/red verdict is useful for the engineer. It is useless to the examiner. What an examiner wants is a defensible record of what was tested, what happened, and that nothing leaked. That is what AEGIS produces as its primary output.

The evidence bundle is tamper-evident — sealed with a SHA-256 hash — and contains grounded-command provenance (which commands ran, against which device), the state diff, the rollback plan, control results mapped to PCI-DSS, SOC 2, and NIST, and an explicit `egress: none` invariant asserting nothing left the perimeter. The same bundle renders as an examiner-ready PDF, so the artifact you hand to an auditor is the artifact the pipeline generated, not a summary written about it after the fact.

## A closed loop that keeps a human in it

Validation is only half the value if a verified change still gets fat-fingered into production by hand. AEGIS closes the loop through a deterministic approval gate: only changes that are both verified and human-approved are promoted, via a connector. The default connector is dry-run, and AEGIS never auto-pushes to production. Blocked, tampered, or unapproved changes are denied at the gate. The human stays in the decision; the machine just refuses to promote anything that did not pass.

## What's actually been tested

The design claims above are backed by six test suites with zero violations: pipeline invariants across 25,000 adversarial runs, the promotion gate across 6,000 bundles, twin safety and management isolation across 8,000 operations, evidence-PDF generation across 1,500 bundles, an API contract suite, and Flask endpoints passing 10/10.

## Try it

If you operate a network that legally cannot send its topology to someone else's cloud, this is built for you. It runs entirely on your side of the air gap:

```bash
docker compose up
# open http://localhost:8088/preflight
```

Apache-2.0, self-hosted, no telemetry, no egress. The repo is at **github.com/gesh75/aegis**.
