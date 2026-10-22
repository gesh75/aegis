"""Append-only, hash-chained audit ledger (A5) + single-use approval tokens (A4).

Every preflight run, promotion, denial, and consumed approval token is appended as one
JSON line. Each entry carries the sha256 of the previous entry, so deleting, reordering,
or editing any line breaks the chain from that point on — `verify_chain` reports the
first bad sequence number.

This is tamper-EVIDENT, not tamper-PROOF: an attacker with write access to the file can
rewrite the whole tail and recompute hashes. Ship the file (or each entry's sha256) to a
WORM store / SIEM to anchor it — see docs/STRATEGY_2026-10.md.

Storage:
  * ``AEGIS_LEDGER_PATH`` set   -> JSONL file, fcntl-locked appends, survives restarts
  * unset (community / tests)   -> in-memory, same API, lost on restart

The ledger also backs replay protection: ``claim_token(token_sha256)`` atomically records
an ``approval_consumed`` entry and returns False if that token hash was already used —
including by an earlier process, because used hashes are re-read from the file on load.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone

try:  # POSIX advisory lock for multi-process appends; absent on Windows
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

GENESIS = "0" * 64
LEDGER_VERSION = 1


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def entry_hash(entry: dict) -> str:
    """sha256 over the entry with its own ``entry_sha256`` removed."""
    body = {k: v for k, v in entry.items() if k != "entry_sha256"}
    return hashlib.sha256(_canonical(body)).hexdigest()


class LedgerError(Exception):
    """The ledger file is unreadable or its chain is broken (fail closed)."""


class Ledger:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or None
        self._lock = threading.Lock()
        self._entries: list[dict] = []      # memory mode only
        self._used: set[str] = set()
        self._head = GENESIS
        self._seq = 0
        if self.path and os.path.exists(self.path):
            ok, n, err = verify_chain(self.path)
            if not ok:
                # never append onto a broken chain — that would launder the break
                raise LedgerError(f"ledger chain broken at entry {n}: {err}")
            for e in _read(self.path):
                self._head, self._seq = e["entry_sha256"], e["seq"]
                if e.get("kind") == "approval_consumed":
                    self._used.add(e.get("token_sha256", ""))

    # ── write ───────────────────────────────────────────────────────────
    def append(self, kind: str, **fields) -> dict:
        with self._lock:
            return self._append_locked(kind, fields)

    def _append_locked(self, kind: str, fields: dict) -> dict:
        entry = {
            "v": LEDGER_VERSION,
            "seq": self._seq + 1,
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            **fields,
            "prev_sha256": self._head,
        }
        entry["entry_sha256"] = entry_hash(entry)
        if self.path:
            line = json.dumps(entry, sort_keys=True, ensure_ascii=True) + "\n"
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                if fcntl:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                os.write(fd, line.encode("ascii"))
                os.fsync(fd)
            finally:
                if fcntl:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
        else:
            self._entries.append(entry)
        self._head, self._seq = entry["entry_sha256"], entry["seq"]
        return entry

    def claim_token(self, token_sha256: str, **context) -> bool:
        """Atomically mark an approval token as used. False = replay."""
        if not token_sha256:
            return False
        with self._lock:
            if token_sha256 in self._used:
                return False
            self._used.add(token_sha256)
            self._append_locked("approval_consumed",
                                {"token_sha256": token_sha256, **context})
            return True

    # ── read ────────────────────────────────────────────────────────────
    def entries(self) -> list[dict]:
        if self.path:
            return list(_read(self.path)) if os.path.exists(self.path) else []
        with self._lock:
            return list(self._entries)

    def head(self) -> dict:
        return {"seq": self._seq, "head_sha256": self._head,
                "storage": "file" if self.path else "memory"}

    def verify(self) -> tuple[bool, int, str]:
        if self.path:
            return verify_chain(self.path) if os.path.exists(self.path) else (True, 0, "empty")
        return verify_entries(self.entries())


def _read(path: str):
    with open(path, encoding="ascii") as fh:
        for raw in fh:
            raw = raw.strip()
            if raw:
                yield json.loads(raw)


def verify_entries(entries) -> tuple[bool, int, str]:
    """(ok, entries_checked_or_bad_seq, reason). Pure — usable offline by an auditor."""
    prev, n = GENESIS, 0
    for n, e in enumerate(entries, start=1):
        if not isinstance(e, dict):
            return False, n, "entry is not an object"
        if e.get("seq") != n:
            return False, n, f"sequence gap (expected {n}, got {e.get('seq')})"
        if e.get("prev_sha256") != prev:
            return False, n, "prev_sha256 does not match the previous entry"
        if e.get("entry_sha256") != entry_hash(e):
            return False, n, "entry_sha256 does not match entry content"
        prev = e["entry_sha256"]
    return True, n, "ok"


def verify_chain(path: str) -> tuple[bool, int, str]:
    try:
        return verify_entries(list(_read(path)))
    except (OSError, ValueError) as exc:
        return False, 0, f"unreadable ledger: {type(exc).__name__}"
