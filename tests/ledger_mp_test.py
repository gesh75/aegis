"""Ledger across PROCESSES: single-use claims and the hash chain hold with many workers.

  M1  6 processes open the same ledger first (stale views), then race to claim ONE token
      and append 25 entries each: exactly one claim wins; the chain verifies with
      contiguous seq; every entry is present
  M2  two instances in one process behave like two workers: a claim by one is a replay
      for the other; alternating appends keep one valid chain
  M3  fail closed: an edited line, a partial trailing line and a truncated file all
      raise LedgerError and nothing is appended after the break
  M4  restart: a new instance sees every claim made by any process
  M5  memory mode is unchanged (in-process only)

Usage:  python3 -m aegis.tests.ledger_mp_test
"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import sys
import tempfile

from ..evidence.ledger import Ledger, LedgerError, verify_chain

FAILS: list[str] = []
CHECKS = 0
WORKERS = 6
APPENDS = 25
TOKEN = "t" * 64


def check(name: str, cond: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(f"{name}: {detail}")


def _worker(path: str, idx: int, barrier, results) -> None:
    led = Ledger(path)                      # opened BEFORE anyone writes: a stale view
    barrier.wait()
    won = False
    for i in range(APPENDS):
        led.append("worker_event", worker=idx, i=i)
        if i == APPENDS // 2:
            won = led.claim_token(TOKEN, worker=idx)
    results.put((idx, won))


def race() -> None:
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ledger.jsonl")
        Ledger(path).append("genesis_marker")
        ctx = mp.get_context("fork")
        barrier, results = ctx.Barrier(WORKERS), ctx.Queue()
        procs = [ctx.Process(target=_worker, args=(path, i, barrier, results))
                 for i in range(WORKERS)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(60)
        outcomes = [results.get(timeout=5) for _ in procs]
        winners = [i for i, won in outcomes if won]
        check("M1.all_workers_exit_clean", all(p.exitcode == 0 for p in procs),
              str([p.exitcode for p in procs]))
        check("M1.exactly_one_claim_wins", len(winners) == 1, str(outcomes))
        ok, n, why = verify_chain(path)
        expected = 1 + WORKERS * APPENDS + 1
        check("M1.chain_valid", ok, f"{n} {why}")
        check("M1.every_entry_present", n == expected, f"{n} != {expected}")
        with open(path, encoding="ascii") as fh:
            entries = [json.loads(x) for x in fh if x.strip()]
        check("M1.seq_contiguous", [e["seq"] for e in entries] == list(range(1, expected + 1)))
        consumed = [e for e in entries if e["kind"] == "approval_consumed"]
        check("M1.one_consumed_entry", len(consumed) == 1, str(len(consumed)))
        try:
            check("M4.restart_sees_claim", Ledger(path).claim_token(TOKEN) is False)
        except LedgerError as exc:
            check("M4.restart_sees_claim", False, f"ledger unreadable after race: {exc}")


def same_process() -> None:
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "l.jsonl")
        a, b = Ledger(path), Ledger(path)
        check("M2.first_claim", a.claim_token("x" * 64) is True)
        check("M2.other_instance_sees_replay", b.claim_token("x" * 64) is False)
        for i in range(10):
            (a if i % 2 else b).append("alt", i=i)
        ok, n, why = verify_chain(path)
        check("M2.alternating_chain_valid", ok and n == 11, f"{ok} {n} {why}")
        check("M2.head_is_shared", a.head()["seq"] == b.head()["seq"] == 11,
              f"{a.head()['seq']} {b.head()['seq']}")


def _edit(path: str, idx: int, value) -> None:
    lines = open(path, encoding="ascii").read().splitlines()
    e = json.loads(lines[idx])
    e["i"] = value                          # edit content, keep the stored hash
    lines[idx] = json.dumps(e, sort_keys=True, ensure_ascii=True)
    with open(path, "w", encoding="ascii") as fh:
        fh.write("\n".join(lines) + "\n")


def fail_closed() -> None:
    # same-length edit: a writer that already verified those bytes cannot see it, but the
    # chain is evidently broken for any new open and for verify_chain (tamper-EVIDENT)
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "l.jsonl")
        led = Ledger(path)
        for i in range(3):
            led.append("e", i=i)
        _edit(path, 1, 7)
        try:
            Ledger(path)
            check("M3.edited_line_refused_on_open", False, "opened")
        except LedgerError:
            check("M3.edited_line_refused_on_open", True)
        ok, n, _ = verify_chain(path)
        check("M3.edit_evident_to_verifier", not ok and n == 2, f"{ok} {n}")

    # length-changing edit: a running writer's verified offset no longer lands on a line
    # boundary, so its next catch-up fails and it refuses to write
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "l.jsonl")
        led = Ledger(path)
        for i in range(3):
            led.append("e", i=i)
        _edit(path, 1, 123456)
        size = os.path.getsize(path)
        try:
            led.append("after_edit")
            check("M3.running_writer_refuses_after_edit", False, "appended")
        except LedgerError:
            check("M3.running_writer_refuses_after_edit", os.path.getsize(path) == size)

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "l.jsonl")
        led = Ledger(path)
        led.append("e")
        with open(path, "a", encoding="ascii") as fh:
            fh.write('{"partial": ')       # a crashed writer
        size = os.path.getsize(path)
        try:
            led.append("next")
            check("M3.partial_line_refused", False, "appended")
        except LedgerError:
            check("M3.partial_line_refused", os.path.getsize(path) == size)
        try:
            led.claim_token("y" * 64)
            check("M3.claim_after_partial_refused", False, "claimed")
        except LedgerError:
            check("M3.claim_after_partial_refused", True)

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "l.jsonl")
        led = Ledger(path)
        for i in range(3):
            led.append("e", i=i)
        with open(path, "r+", encoding="ascii") as fh:
            fh.truncate(10)
        try:
            led.append("after_truncate")
            check("M3.truncation_refused", False, "appended")
        except LedgerError:
            check("M3.truncation_refused", True)


def memory_mode() -> None:
    m = Ledger(None)
    check("M5.memory_claim", m.claim_token("z" * 64) is True and m.claim_token("z" * 64) is False)
    m.append("e")
    check("M5.memory_chain", m.verify()[0] and m.head()["storage"] == "memory")


def main() -> int:
    race()
    same_process()
    fail_closed()
    memory_mode()
    if FAILS:
        print("\n=== LEDGER MULTI-PROCESS TEST: FAIL ===")
        for f in FAILS:
            print("  -", f)
        return 1
    print(f"=== LEDGER MULTI-PROCESS TEST: PASS ({CHECKS} checks, {WORKERS} processes) ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
