"""D3 secret references: no credential value in any artifact, resolved only at push.

  S1  tokenization: Junos cleartext / $9$, Cisco type 0 / 7 / 5, SNMP community, AAA key
      → AEGISREF tokens with kinds; idempotent; the detectors ignore references
  S2  property (200 seeded runs): no secret value anywhere in the bundle JSON (configs,
      rollback plan, intent text, findings); bundle verifies + is schema-valid; PCI 8.3.2
      still judged on the REAL config (D3 does not change device-side compliance)
  S3  FileStore: AES-GCM round trip, 0600, ciphertext has no plaintext, a tampered or
      renamed file and a wrong key all fail closed
  S4  VaultStore (KV v2, MockTransport): POST/GET paths + token header; 404 / 500 fail
      closed; undeclared host refused under air-gap
  S5  resolve: values re-derive their token; a swapped value, a missing value or a token
      from another run is refused
  S6  promote: the connector receives the REAL config, the record/ledger never do; no
      store → denied; unresolvable → denied WITHOUT burning the single-use token
  S7  post-change: a referenced key matches the device's re-encrypted form by position
  S8  configuration: production requires the store; bad spec / key length are errors
  S9  HTTP: server with a file store seals a referenced bundle, PDF shows references,
      promote resolves, status reports the store

Usage:  python3 -m aegis.tests.secretref_test
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import stat
import string
import sys
import tempfile

_TMP = tempfile.mkdtemp(prefix="aegis-d3-")
KEY_HEX = "11" * 32
# S9 imports serve, which reads the store at import time
os.environ["AEGIS_SECRET_STORE"] = f"file:{_TMP}/serve-store"
os.environ["AEGIS_SECRET_KEY"] = KEY_HEX

import httpx  # noqa: E402

from ..core import secretref  # noqa: E402
from ..core.secretref import (FileStore, MemoryStore, SecretStoreError, VaultStore,  # noqa: E402
                              protect_bundle, resolve_text, tokenize_text)
from ..evidence import secrets as det  # noqa: E402

FAILS: list[str] = []
CHECKS = 0
_SCHEMA = os.path.join(os.path.dirname(__file__), "..", "evidence", "schema",
                       "evidence_bundle.schema.json")
KEY = bytes.fromhex(KEY_HEX)


def check(name: str, cond: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(f"{name}: {detail}")


def _raises(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except SecretStoreError as exc:
        return str(exc)
    return None


def _secret(rng: random.Random, n: int = 12) -> str:
    return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(n))


def _configs(rng: random.Random) -> tuple[list[dict], list[str]]:
    s = [_secret(rng) for _ in range(6)]
    t7 = "".join(rng.choice("0123456789ABCDEF") for _ in range(12))
    j9 = "$9$" + _secret(rng, 10)
    md5 = "$1$" + _secret(rng, 8) + "$" + _secret(rng, 22)
    jun = (f'set protocols bgp group EBGP authentication-key "{s[0]}"\n'
           f'set protocols ospf area 0 interface ge-0/0/0.0 authentication md5 1 key "{j9}"\n'
           f'set snmp community {s[1]} authorization read-only\n'
           "set protocols bgp group EBGP export EXPORT")
    ios = (f"username ops privilege 15 password 0 {s[2]}\n"
           f" neighbor 10.0.0.1 password 7 {t7}\n"
           f"enable secret 5 {md5}\n"
           f"tacacs-server key {s[3]}\n"
           f"snmp-server community {s[4]} RO")
    return ([{"device": "mx1", "vendor": "junos", "config": jun},
             {"device": "r1", "vendor": "ios", "config": ios}],
            [s[0], j9, s[1], s[2], t7, md5, s[3], s[4]])


def tokenize() -> None:
    store = MemoryStore(KEY)
    cfgs, values = _configs(random.Random(1))
    allrefs = []
    for c in cfgs:
        out, refs, mapping = tokenize_text(c["config"], run_id="run1", store=store,
                                           device=c["device"])
        allrefs += refs
        check(f"S1.no_values_{c['device']}", not any(v in out for v in values), out)
        check(f"S1.refs_present_{c['device']}", secretref.has_refs(out))
        again, more, _ = tokenize_text(out, run_id="run1", store=store)
        check(f"S1.idempotent_{c['device']}", again == out and not more, again)
        check(f"S1.detectors_ignore_refs_{c['device']}",
              not det.plaintext_hits(out) and not det.reversible_hits(out),
              f"{det.plaintext_hits(out)} {det.reversible_hits(out)}")
        check(f"S1.pdf_redact_keeps_refs_{c['device']}", det.redact(out) == out)
        check(f"S1.structure_kept_{c['device']}",
              out.count("\n") == c["config"].count("\n"))
    kinds = {r["kind"] for r in allrefs}
    check("S1.kinds", kinds == {"plaintext", "reversible", "hash"}, str(kinds))
    check("S1.ref_count", len({r["ref"] for r in allrefs}) == len(values),
          f"{len(allrefs)} vs {len(values)}")
    check("S1.token_keyed", store.ref_for("run1", "x") != MemoryStore().ref_for("run1", "x"))
    check("S1.token_run_bound", store.ref_for("run1", "x") != store.ref_for("run2", "x"))


def property_bundles() -> None:
    from ..core.backends.simulator import SimulatorBackend
    from ..core.orchestrator.pipeline import PreflightError, run_preflight
    from ..evidence.bundler import verify
    try:
        import jsonschema
        with open(_SCHEMA, encoding="utf-8") as fh:
            schema = json.load(fh)
    except ImportError:
        schema = None
    sim = SimulatorBackend(converge_fail_rate=0.0, batfish_error_rate=0.0)
    leaks, bad_hash, bad_schema, no_pci_fail = [], 0, 0, 0
    for seed in range(200):
        rng = random.Random(seed)
        cfgs, values = _configs(rng)
        store = MemoryStore(KEY)
        try:
            b = run_preflight(f"rotate keys ({values[0]}) on mx1 and r1", backend=sim,
                              lab="single", source="config_import", imported_configs=cfgs,
                              operator="alice", change_ref="CHG0012345", secret_store=store)
        except PreflightError as exc:
            leaks.append((seed, f"run rejected: {exc}"))
            continue
        blob = json.dumps(b)
        leaks += [(seed, v) for v in values if v in blob]
        bad_hash += 0 if verify(b) else 1
        if schema is not None:
            try:
                jsonschema.validate(b, schema)
            except jsonschema.ValidationError:
                bad_schema += 1
        pci = [r for r in b["validation"]["compliance"]
               if r.get("framework") == "pci_dss_v4" and r.get("control") == "8.3.2"]
        no_pci_fail += 0 if (pci and pci[0]["status"] == "fail") else 1
    check("S2.no_value_in_any_bundle", not leaks, str(leaks[:5]))
    check("S2.bundles_verify", bad_hash == 0, str(bad_hash))
    check("S2.schema_valid", bad_schema == 0, str(bad_schema))
    check("S2.pci_judged_on_real_config", no_pci_fail == 0, str(no_pci_fail))
    check("S2.refs_recorded", len(b["change"]["secret_refs"]) >= 8, str(b["change"]["secret_refs"]))
    check("S2.intent_scrubbed", "AEGISREF-" in b["change"]["intent"], b["change"]["intent"])
    plain = run_preflight("", backend=sim, lab="single", source="config_import",
                          imported_configs=_configs(random.Random(0))[0])
    check("S2.off_by_default", "secret_refs" not in plain["change"])
    rb = "\n".join(b["rollback"]["plan"])
    check("S2.rollback_tokenized", "AEGISREF-" in rb, rb[:300])
    # fail closed: if a value ever survives (simulated by disabling the scrub), the run is
    # rejected rather than sealed
    orig = secretref._scrub  # noqa: SLF001
    secretref._scrub = lambda obj, rx, mapping: obj  # noqa: SLF001
    try:
        run_preflight(f"rotate {values[0]}", backend=sim, lab="single", source="config_import",
                      imported_configs=cfgs, secret_store=MemoryStore(KEY))
        check("S2.leak_fails_closed", False, "sealed a bundle with a leaked value")
    except PreflightError as exc:
        check("S2.leak_fails_closed", "survived tokenization" in str(exc), str(exc))
    finally:
        secretref._scrub = orig  # noqa: SLF001


def review_findings() -> None:
    """Regression tests for the PR #42 review: prefix bypass, short/embedded values,
    compliance + findings coverage, rollback records, enum safety, cleanup on failure."""
    from ..evidence.bundler import verify
    store = MemoryStore(KEY)
    fake_ref = "AEGISREF-not-a-real-token"
    out, refs, _ = tokenize_text(f'set protocols bgp group G authentication-key "{fake_ref}"',
                                 run_id="r", store=store)
    check("F4.prefix_lookalike_tokenized", fake_ref not in out and refs, out)
    check("F4.detector_flags_prefix_lookalike",
          det.plaintext_hits(f'set protocols bgp group G authentication-key "{fake_ref}"'))
    out, refs, _ = tokenize_text("tacacs-server key <redacted>", run_id="r", store=store)
    check("F4.literal_redacted_is_a_value", "<redacted>" not in out and refs, out)

    base = {"run_id": "f" * 32, "operator": "alice",
            "change": {"intent": "rotate key hunter2xyz to hunter2xyz-new, ab stays",
                       "generated_configs": [{"device": "r1", "vendor": "ios", "grounded_commands": [],
                                              "config": "tacacs-server key hunter2xyz\n"
                                                        "snmp-server community ab RO\n"
                                                        "username u password 0 pass"}],
                       "risk_tier": "low"},
            "validation": {"batfish": {"findings": ["r1: line 'tacacs-server key hunter2xyz' parsed",
                                                    "r1: radius-server key onlyinfindings1 seen"]},
                           "compliance": [{"framework": "pci_dss_v4", "control": "8.3.2",
                                           "status": "pass", "evidence": "key hunter2xyz ok"}]},
            "rollback": {"plan": ["r1: no tacacs-server key hunter2xyz",
                                  "r1: restore tacacs-server key oldkeyonlyinrollback"]},
            "verdict": {"decision": "ship_ready", "reason": "ok"},
            "integrity": {"sha256": ""}}
    b = protect_bundle(base, store)
    blob = json.dumps(b)
    for v in ("hunter2xyz", "onlyinfindings1", "oldkeyonlyinrollback"):
        check(f"F1.no_{v}", v not in blob, blob[:400])
    check("F1.embedded_value_scrubbed", "hunter2xyz-new" not in b["change"]["intent"],
          b["change"]["intent"])
    check("F1.short_value_whole_token_scrubbed", " ab " not in b["change"]["intent"],
          b["change"]["intent"])
    check("F5.compliance_evidence_scrubbed",
          "hunter2xyz" not in b["validation"]["compliance"][0]["evidence"])
    check("F1.enum_fields_untouched", b["validation"]["compliance"][0]["status"] == "pass"
          and b["verdict"]["decision"] == "ship_ready", json.dumps(b["validation"]["compliance"]))
    check("F1.refs_not_corrupted", all(secretref.REF_RE.fullmatch(r["ref"])
                                       for r in b["change"]["secret_refs"]))
    check("F13.rollback_refs_recorded",
          any(r["device"] == "rollback" for r in b["change"]["secret_refs"]),
          json.dumps(b["change"]["secret_refs"]))
    check("F1.rehashed", verify(b))
    roundtrip = resolve_text(b["change"]["generated_configs"][0]["config"], run_id="f" * 32,
                             store=store)
    check("F1.config_resolves", roundtrip == base["change"]["generated_configs"][0]["config"])

    clean = MemoryStore(KEY)
    orig = secretref._scrub  # noqa: SLF001
    secretref._scrub = lambda obj, rx, mapping: obj  # noqa: SLF001
    try:
        check("F14.leak_rejected", _raises(protect_bundle, base, clean) is not None)
    finally:
        secretref._scrub = orig  # noqa: SLF001
    check("F14.failed_run_leaves_nothing", not clean._data, str(len(clean._data)))  # noqa: SLF001


def filestore() -> None:
    root = os.path.join(_TMP, "fs")
    fs = FileStore(root, KEY)
    ref = fs.ref_for("r", "s3cr3t-value")
    fs.put(ref, "s3cr3t-value")
    check("S3.roundtrip", fs.get(ref) == "s3cr3t-value")
    path = os.path.join(root, ref + ".bin")
    mode = stat.S_IMODE(os.stat(path).st_mode)
    check("S3.file_0600", mode == 0o600, oct(mode))
    check("S3.dir_0700", stat.S_IMODE(os.stat(root).st_mode) == 0o700)
    with open(path, "rb") as fh:
        blob = fh.read()
    check("S3.ciphertext_opaque", b"s3cr3t-value" not in blob)
    check("S3.wrong_key", _raises(FileStore(root, b"\x22" * 32).get, ref) is not None)
    other = fs.ref_for("r", "other")
    os.replace(path, os.path.join(root, other + ".bin"))
    check("S3.renamed_file_fails", _raises(fs.get, other) is not None)
    fs.put(ref, "s3cr3t-value")
    with open(path, "r+b") as fh:   # flip one ciphertext byte (never a no-op)
        fh.seek(20)
        b = fh.read(1)
        fh.seek(20)
        fh.write(bytes([b[0] ^ 0xFF]))
    check("S3.tampered_fails", "authentication" in (_raises(fs.get, ref) or ""))
    check("S3.missing", "not in store" in (_raises(fs.get, fs.ref_for("r", "nope")) or ""))
    check("S3.path_traversal", _raises(fs.get, "../../etc/passwd") is not None)
    loose = os.path.join(_TMP, "loose")
    os.makedirs(loose, mode=0o755)
    os.chmod(loose, 0o755)
    FileStore(loose, KEY)
    check("S3.existing_dir_tightened", stat.S_IMODE(os.stat(loose).st_mode) == 0o700,
          oct(stat.S_IMODE(os.stat(loose).st_mode)))
    fs.put(ref, "s3cr3t-value")
    check("S3.key_check_ok", _raises(fs.check_key) is None)
    check("S3.rotated_key_refused", "does not match" in (_raises(
        FileStore(root, b"\x33" * 32).check_key) or ""))
    old_ref = fs.ref_for("r", "ancient")
    fs.put(old_ref, "ancient")
    past = os.path.getmtime(os.path.join(root, old_ref + ".bin")) - 40 * 86400
    os.utime(os.path.join(root, old_ref + ".bin"), (past, past))
    check("S3.prune_removes_expired", fs.prune(30) >= 1
          and _raises(fs.get, old_ref) is not None and fs.get(ref) == "s3cr3t-value")
    check("S3.prune_zero_keeps", fs.prune(0) == 0)


class FakeVault:
    def __init__(self, status=200):
        self.data, self.reqs, self.status = {}, [], status

    def __call__(self, req: httpx.Request):
        self.reqs.append(req)
        if self.status != 200:
            return httpx.Response(self.status, json={"errors": ["boom"]})
        key = req.url.path.rsplit("/", 1)[-1]
        if req.method == "DELETE":
            self.data.pop(key, None)
            return httpx.Response(204)
        if req.method == "POST":
            self.data[key] = json.loads(req.content)["data"]["value"]
            return httpx.Response(200, json={"data": {"version": 1}})
        if key not in self.data:
            return httpx.Response(404, json={"errors": []})
        return httpx.Response(200, json={"data": {"data": {"value": self.data[key]},
                                                  "metadata": {"version": 1}}})


def vault() -> None:
    os.environ["AEGIS_INTEGRATION_HOSTS"] = "vault.corp"
    fake = FakeVault()
    v = VaultStore("https://vault.corp:8200/v1/secret/data/aegis", "vtok", KEY,
                   transport=httpx.MockTransport(fake))
    ref = v.ref_for("r", "vault-secret")
    v.put(ref, "vault-secret")
    check("S4.roundtrip", v.get(ref) == "vault-secret")
    check("S4.paths", [(r.method, r.url.path) for r in fake.reqs] ==
          [("POST", f"/v1/secret/data/aegis/{ref}"), ("GET", f"/v1/secret/data/aegis/{ref}")],
          str([(r.method, r.url.path) for r in fake.reqs]))
    check("S4.token_header", fake.reqs[0].headers.get("x-vault-token") == "vtok")
    check("S4.404", "not in store" in (_raises(v.get, v.ref_for("r", "x")) or ""))
    v500 = VaultStore("https://vault.corp:8200/v1/secret/data/aegis", "t", KEY,
                      transport=httpx.MockTransport(FakeVault(status=500)))
    check("S4.500", "500" in (_raises(v500.get, ref) or ""))
    os.environ.pop("AEGIS_INTEGRATION_HOSTS", None)
    check("S4.undeclared_host", "not declared" in (_raises(
        VaultStore, "https://vault.corp/v1/secret/data/aegis", "t", KEY) or ""))
    os.environ["AEGIS_INTEGRATION_HOSTS"] = "vault.corp"
    check("S4.no_token", "AEGIS_VAULT_TOKEN" in (_raises(
        VaultStore, "https://vault.corp:8200/v1/secret/data/aegis", "", KEY) or ""))
    check("S4.query_refused", "query" in (_raises(
        VaultStore, "https://vault.corp:8200/v1/secret/data/aegis?x=1", "t", KEY) or ""))
    check("S4.not_kv2_data_path", "data path" in (_raises(
        VaultStore, "https://vault.corp:8200/v1/secret/aegis", "t", KEY) or ""))
    fake = FakeVault()
    vd = VaultStore("https://vault.corp:8200/v1/secret/data/aegis", "t", KEY,
                    transport=httpx.MockTransport(fake))
    vd.delete(ref)
    check("S4.delete_destroys_all_versions", fake.reqs[-1].method == "DELETE"
          and fake.reqs[-1].url.path == f"/v1/secret/metadata/aegis/{ref}",
          str(fake.reqs[-1].url))
    os.environ.pop("AEGIS_INTEGRATION_HOSTS", None)


def resolve() -> None:
    store = MemoryStore(KEY)
    text = 'set protocols bgp group G authentication-key "hunter2hunter2"'
    tok, refs, _ = tokenize_text(text, run_id="runA", store=store)
    check("S5.roundtrip", resolve_text(tok, run_id="runA", store=store) == text)
    check("S5.other_run_refused",
          "does not match" in (_raises(resolve_text, tok, run_id="runB", store=store) or ""))
    store._data[refs[0]["ref"]] = "attacker-key"  # noqa: SLF001 — simulate a swapped value
    check("S5.swapped_value_refused",
          "does not match" in (_raises(resolve_text, tok, run_id="runA", store=store) or ""))
    check("S5.missing_refused", _raises(resolve_text, tok, run_id="runA",
                                        store=MemoryStore(KEY)) is not None)


class Capture:
    live = False

    def __init__(self):
        self.calls = []

    def push(self, device, vendor, config):
        self.calls.append(config)
        return {"pushed": True, "detail": "captured"}


def promotion() -> None:
    from ..core.backends.simulator import SimulatorBackend
    from ..core.orchestrator.pipeline import run_preflight
    from ..core.promote.promote import PromoteDenied, promote
    from ..core.promote.tokens import mint_token_for_bundle
    from ..evidence.bundler import compute_sha256
    from ..evidence.ledger import Ledger

    cfgs, values = _configs(random.Random(7))
    store = MemoryStore(KEY)
    sim = SimulatorBackend(converge_fail_rate=0.0, batfish_error_rate=0.0)
    b = run_preflight("", backend=sim, lab="single", source="config_import",
                      imported_configs=cfgs, operator="alice", secret_store=store)
    # force the approval path so the single-use token is in play
    b["change"]["risk_tier"] = "medium"
    b["verdict"] = {"decision": "needs_approval", "reason": "test"}
    b["integrity"]["sha256"] = ""
    b["integrity"]["sha256"] = compute_sha256(b)

    os.environ["AEGIS_APPROVE_KEY"] = KEY_HEX
    try:
        ledger = Ledger(os.path.join(_TMP, "ledger.jsonl"))
        tok = mint_token_for_bundle("bob", b, ttl_sec=600)
        cap = Capture()
        try:
            promote(b, connector=cap, approver="bob", approval_token=tok, ledger=ledger)
            check("S6.no_store_denied", False, "promoted")
        except PromoteDenied as e:
            check("S6.no_store_denied", "no secret store" in str(e), str(e))
        try:
            promote(b, connector=cap, approver="bob", approval_token=tok, ledger=ledger,
                    secret_store=MemoryStore(KEY))
            check("S6.unresolvable_denied", False, "promoted")
        except PromoteDenied as e:
            check("S6.unresolvable_denied", "could not be resolved" in str(e), str(e))
        check("S6.nothing_pushed_on_deny", not cap.calls)
        rec = promote(b, connector=cap, approver="bob", approval_token=tok, ledger=ledger,
                      secret_store=store)
        check("S6.token_not_burned_by_denials", rec["status"] == "promoted", str(rec)[:200])
        pushed = "\n".join(cap.calls)
        check("S6.connector_gets_real_config", all(v in pushed for v in values)
              and "AEGISREF-" not in pushed)
        trail = json.dumps(rec) + json.dumps(ledger.entries())
        check("S6.record_and_ledger_clean", not any(v in trail for v in values))
        legacy = run_preflight("", backend=sim, lab="single", source="config_import",
                               imported_configs=cfgs, operator="alice")
        try:
            promote(legacy, connector=Capture(), require_secret_refs=True, approver="bob",
                    approval_token=mint_token_for_bundle("bob", legacy, ttl_sec=600))
            check("F2.production_refuses_clear_credentials", False, "promoted")
        except PromoteDenied as e:
            check("F2.production_refuses_clear_credentials", "in clear" in str(e), str(e))
        check("F2.referenced_bundle_has_no_clear_credentials",
              not any(secretref.raw_secret_labels(c["config"])
                      for c in b["change"]["generated_configs"]))

        class Echo(Capture):
            def push(self, device, vendor, config):
                raise RuntimeError(f"device rejected: {config}")
        b2 = run_preflight("", backend=sim, lab="single", source="config_import",
                           imported_configs=cfgs, operator="alice", secret_store=store)
        rec2 = promote(b2, connector=Echo(), secret_store=store, approver="bob",
                       approval_token=mint_token_for_bundle("bob", b2, ttl_sec=600))
        check("F3.connector_echo_scrubbed", not any(v in json.dumps(rec2) for v in values)
              and "AEGISREF-" in json.dumps(rec2["pushed"]), json.dumps(rec2["pushed"])[:300])
        try:
            promote(b, connector=Capture(), approver="bob", approval_token=tok, ledger=ledger,
                    secret_store=store)
            check("S6.replay_still_denied", False, "replayed")
        except PromoteDenied as e:
            check("S6.replay_still_denied", "single-use" in str(e), str(e))
    finally:
        os.environ.pop("AEGIS_APPROVE_KEY", None)


def postchange() -> None:
    from ..core.postchange import verify_postchange
    store = MemoryStore(KEY)
    jun = 'set protocols bgp group G authentication-key "hunter2hunter2"\nset vlans v10 vlan-id 10'
    tok, _, _ = tokenize_text(jun, run_id="r", store=store)
    bundle = {"run_id": "r", "change": {"generated_configs": [
        {"device": "mx1", "vendor": "junos", "config": tok}]}, "integrity": {"sha256": "x"}}
    running = ('set protocols bgp group G authentication-key "$9$Re-encrypted.By.Device"\n'
               "set vlans v10 vlan-id 10")
    r = verify_postchange(bundle, [{"device": "mx1", "config": running}], secret_store=store)
    check("S7.junos_reencrypted_is_partial_not_verified", r["status"] == "partial"
          and r["devices"][0]["secrets"]["unverifiable"], json.dumps(r["devices"]))
    wrong = running.replace("group G", "group H")
    r = verify_postchange(bundle, [{"device": "mx1", "config": wrong}], secret_store=store)
    check("S7.wrong_structure_is_drift", r["status"] == "drift", json.dumps(r["devices"]))
    ios = "tacacs-server key 0 cisco\nhostname r1"
    itok, _, _ = tokenize_text(ios, run_id="r", store=store)
    ib = {"run_id": "r", "change": {"generated_configs": [
        {"device": "r1", "vendor": "ios", "config": itok}]}, "integrity": {"sha256": "x"}}
    for name, run, want in (("type7_decoded_match", "tacacs-server key 7 0822455D0A16", "verified"),
                            ("clear_match", "tacacs-server key 0 cisco", "verified"),
                            ("wrong_key_is_drift", "tacacs-server key 0 stale-key", "drift"),
                            ("type7_other_seed_match", "tacacs-server key 7 060506324F41",
                             "verified"),
                            ("type7_wrong_key_is_drift", "tacacs-server key 7 051C14002F4B450C00",
                             "drift")):
        r = verify_postchange(ib, [{"device": "r1", "config": run + "\nhostname r1"}],
                              secret_store=store)
        check(f"S7.{name}", r["status"] == want, f"{r['status']} {json.dumps(r['devices'])}")
    r = verify_postchange(ib, [{"device": "r1", "config": "tacacs-server key 0 cisco\nhostname r1"}])
    check("S7.no_store_is_partial", r["status"] == "partial", r["status"])


def configuration() -> None:
    from ..core import runtime
    saved = {k: os.environ.get(k) for k in ("AEGIS_SECRET_STORE", "AEGIS_SECRET_KEY")}
    try:
        os.environ["AEGIS_SECRET_STORE"] = "s3://bucket"
        check("S8.bad_spec", "must be file:" in (_raises(secretref.store_from_env) or ""))
        os.environ["AEGIS_SECRET_STORE"] = f"file:{_TMP}/cfg"
        os.environ["AEGIS_SECRET_KEY"] = "abcd"
        check("S8.short_key", "64 hex" in (_raises(secretref.store_from_env) or ""))
        os.environ["AEGIS_SECRET_KEY"] = KEY_HEX
        check("S8.file_ok", isinstance(secretref.store_from_env(), FileStore))
        os.environ.pop("AEGIS_SECRET_STORE")
        check("S8.unset_is_off", secretref.store_from_env() is None)
        check("S8.production_requires_store",
              "AEGIS_SECRET_STORE" in runtime._REQUIRED_PRODUCTION_ENV  # noqa: SLF001
              and "AEGIS_SECRET_KEY" in runtime._REQUIRED_PRODUCTION_ENV)  # noqa: SLF001
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def http() -> None:
    from ..serve import app
    c = app.test_client()
    st = c.get("/api/status").get_json()
    check("S9.status_reports_store", st.get("secret_refs") == "file", str(st))
    cfgs, values = _configs(random.Random(11))
    sealed = None
    for i in range(20):
        r = c.post("/api/preflight/run", json={
            "source": "config_import", "lab": "single", "operator": "alice",
            "change_ref": "CHG0012345",
            "configs": [dict(x, device=f"{x['device']}-{i}") for x in cfgs]})
        b = r.get_json() if r.status_code == 200 else {}
        if isinstance(b.get("seal"), dict):
            sealed = b
            break
    check("S9.sealed_referenced_bundle", sealed is not None
          and sealed["change"].get("secret_refs"), str(r.status_code))
    if not sealed:
        return
    check("S9.response_clean", not any(v in json.dumps(sealed) for v in values))
    r = c.post("/api/preflight/evidence/cab", json=sealed)
    check("S9.cab_clean", r.status_code == 200
          and not any(v in r.get_data(as_text=True) for v in values), str(r.status_code))
    r = c.post("/api/preflight/promote", json={"bundle": sealed, "approver": "bob",
                                                "approval_token": "t", "connector": "dry_run"})
    rec = r.get_json() or {}
    check("S9.promote_resolves", r.status_code == 200 and rec.get("status") == "promoted",
          f"{r.status_code} {r.get_data(as_text=True)[:200]}")
    check("S9.promotion_record_clean", not any(v in json.dumps(rec) for v in values))
    files = os.listdir(f"{_TMP}/serve-store")
    check("S9.values_in_store_only", len(files) >= len(values), str(len(files)))


def main() -> int:
    tokenize()
    review_findings()
    property_bundles()
    filestore()
    vault()
    resolve()
    promotion()
    postchange()
    configuration()
    http()
    if FAILS:
        print("\n=== SECRET REFERENCES (D3) TEST: FAIL ===")
        for f in FAILS:
            print("  -", f)
        return 1
    print(f"=== SECRET REFERENCES (D3) TEST: PASS ({CHECKS} checks) ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
