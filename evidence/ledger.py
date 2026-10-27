"""Append-only, hash-chained audit ledger (A5) + single-use approval tokens (A4).

Every preflight run, promotion, denial, and consumed approval token is appended as one
JSON line. Each entry carries the sha256 of the previous entry, so deleting, reordering,
or editing any line breaks the chain from that point on — `verify_chain` reports the
first bad sequence number.

This is tamper-EVIDENT, not tamper-PROOF: an attacker with write access to the file can
rewrite the whole tail and recompute hashes. Anchor it off-box: set
``AEGIS_LEDGER_SYSLOG=host:port[/tcp|/udp]`` and every entry (with its entry_sha256 and
prev_sha256) is also sent to your SIEM as an RFC 5424 message, so a local rewrite no longer
matches the SIEM copy. The sink is best-effort (a SIEM outage never blocks a change);
failures are counted in ``Ledger.sink_failures`` and surfaced on /metrics.

Storage:
  * ``AEGIS_LEDGER_PATH`` set   -> JSONL file, fcntl-locked appends, survives restarts
  * unset (community / tests)   -> in-memory, same API, lost on restart

The ledger also backs replay protection: ``claim_token(token_sha256)`` atomically records
an ``approval_consumed`` entry and returns False if that token hash was already used —
by this process, an earlier one, or a concurrent one: every write re-reads what other
processes appended under the same ``flock`` before deciding (multi-worker safe on POSIX).
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
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


class SyslogSink:
    """RFC 5424 sender (stdlib only). One JSON ledger entry per message."""

    def __init__(self, spec: str) -> None:
        target, _, proto = spec.partition("/")
        host, _, port = target.rpartition(":")
        if not host or not port.isdigit():
            raise SystemExit(f"[aegis.ledger] AEGIS_LEDGER_SYSLOG must be host:port[/tcp|/udp] "
                             f"(got {spec!r})")
        self.host, self.port = host.strip("[]"), int(port)
        self.proto = (proto or "udp").lower()
        if self.proto not in ("udp", "tcp"):
            raise SystemExit("[aegis.ledger] AEGIS_LEDGER_SYSLOG protocol must be tcp or udp")

    def __call__(self, entry: dict) -> None:
        msg = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        # <110> = facility 13 (log audit) * 8 + severity 6 (info)
        line = (f"<110>1 {entry.get('ts_utc', '-')} {socket.gethostname()} aegis - "
                f"{entry.get('kind', '-')} - {msg}")
        data = line.encode("ascii", "replace")
        if self.proto == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(data[:65000], (self.host, self.port))
        else:  # RFC 6587 octet counting
            with socket.create_connection((self.host, self.port), timeout=2) as s:
                s.sendall(f"{len(data)} ".encode() + data)


def sink_from_env():
    spec = (os.environ.get("AEGIS_LEDGER_SYSLOG") or "").strip()
    return SyslogSink(spec) if spec else None


class Ledger:
    """Hash-chained ledger. File-backed instances are safe across PROCESSES: every write
    takes an exclusive ``flock`` on the ledger file, first catches up on entries other
    processes appended since this instance last looked (verifying the chain as it goes),
    and only then checks single-use claims and appends. The head, sequence and used-token
    set are therefore never stale, so a token cannot be claimed twice and the chain
    cannot fork, however many workers or containers share the file.

    A file that does not continue the chain (an edited line, a truncated tail, a partial
    line from a crashed writer) raises ``LedgerError`` and nothing is appended: never
    launder a break by writing after it."""

    def __init__(self, path: str | None = None, sink=None) -> None:
        self.path = path or None
        self.sink = sink
        self.sink_failures = 0
        self._lock = threading.Lock()       # threads; flock covers processes
        self._entries: list[dict] = []      # memory mode only
        self._used: set[str] = set()
        self._head = GENESIS
        self._seq = 0
        self._offset = 0                    # bytes of the file already verified
        if self.path and os.path.exists(self.path):
            with self._lock:
                self._with_file(lambda fd: None)

    # ── cross-process plumbing ──────────────────────────────────────────
    def _with_file(self, fn):
        """Open + exclusively lock the ledger file, catch up, run ``fn(fd)``. Caller holds
        ``self._lock``."""
        fd = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            if fcntl:
                fcntl.flock(fd, fcntl.LOCK_EX)
            self._catch_up(fd)
            return fn(fd)
        finally:
            if fcntl:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _catch_up(self, fd: int) -> None:
        size = os.fstat(fd).st_size
        if size < self._offset:
            raise LedgerError("ledger file shrank below the verified length (truncated?)")
        if size == self._offset:
            return
        os.lseek(fd, self._offset, os.SEEK_SET)
        chunks, left = [], size - self._offset
        while left:
            b = os.read(fd, min(left, 1 << 20))
            if not b:
                break
            chunks.append(b)
            left -= len(b)
        data = b"".join(chunks)
        if not data.endswith(b"\n"):
            raise LedgerError(f"ledger has a partial line after entry {self._seq} "
                              "(interrupted write?)")
        head, seq, used = self._head, self._seq, set()
        for raw in data.decode("ascii").splitlines():
            if not raw.strip():
                continue
            try:
                e = json.loads(raw)
            except ValueError as exc:
                raise LedgerError(f"ledger entry {seq + 1} is not JSON") from exc
            ok, why = _continues(e, seq + 1, head)
            if not ok:
                # never append onto a broken chain — that would launder the break
                raise LedgerError(f"ledger chain broken at entry {seq + 1}: {why}")
            head, seq = e["entry_sha256"], e["seq"]
            if e.get("kind") == "approval_consumed":
                used.add(e.get("token_sha256", ""))
        self._head, self._seq, self._offset = head, seq, size
        self._used |= used

    # ── write ───────────────────────────────────────────────────────────
    def append(self, kind: str, **fields) -> dict:
        with self._lock:
            if self.path:
                return self._with_file(lambda fd: self._append_locked(kind, fields, fd))
            return self._append_locked(kind, fields)

    def _append_locked(self, kind: str, fields: dict, fd: int | None = None) -> dict:
        entry = {
            "v": LEDGER_VERSION,
            "seq": self._seq + 1,
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            **fields,
            "prev_sha256": self._head,
        }
        entry["entry_sha256"] = entry_hash(entry)
        if fd is not None:
            line = (json.dumps(entry, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
            os.write(fd, line)
            os.fsync(fd)
            self._offset += len(line)
        else:
            self._entries.append(entry)
        self._head, self._seq = entry["entry_sha256"], entry["seq"]
        if self.sink is not None:
            try:
                self.sink(entry)
            except Exception:  # noqa: BLE001 — SIEM outage must not block the change path
                self.sink_failures += 1
        return entry

    def claim_token(self, token_sha256: str, **context) -> bool:
        """Atomically mark an approval token as used. False = replay — including a claim
        made by another process sharing the ledger file."""
        if not token_sha256:
            return False

        def claim(fd: int | None) -> bool:
            if token_sha256 in self._used:
                return False
            self._append_locked("approval_consumed",
                                {"token_sha256": token_sha256, **context}, fd)
            self._used.add(token_sha256)
            return True

        with self._lock:
            if self.path:
                return self._with_file(claim)
            return claim(None)

    # ── read ────────────────────────────────────────────────────────────
    def entries(self) -> list[dict]:
        if self.path:
            return list(_read(self.path)) if os.path.exists(self.path) else []
        with self._lock:
            return list(self._entries)

    def head(self) -> dict:
        if self.path and os.path.exists(self.path):
            with self._lock:            # report the shared head, not this process's view
                self._with_file(lambda fd: None)
        return {"seq": self._seq, "head_sha256": self._head,
                "storage": "file" if self.path else "memory",
                "anchor": "syslog" if self.sink is not None else "none",
                "anchor_failures": self.sink_failures}

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


def _continues(e, seq: int, prev: str) -> tuple[bool, str]:
    if not isinstance(e, dict):
        return False, "entry is not an object"
    if e.get("seq") != seq:
        return False, f"sequence gap (expected {seq}, got {e.get('seq')})"
    if e.get("prev_sha256") != prev:
        return False, "prev_sha256 does not match the previous entry"
    if e.get("entry_sha256") != entry_hash(e):
        return False, "entry_sha256 does not match entry content"
    return True, "ok"


def verify_entries(entries) -> tuple[bool, int, str]:
    """(ok, entries_checked_or_bad_seq, reason). Pure — usable offline by an auditor."""
    prev, n = GENESIS, 0
    for n, e in enumerate(entries, start=1):
        ok, why = _continues(e, n, prev)
        if not ok:
            return False, n, why
        prev = e["entry_sha256"]
    return True, n, "ok"


def verify_chain(path: str) -> tuple[bool, int, str]:
    try:
        return verify_entries(list(_read(path)))
    except (OSError, ValueError) as exc:
        return False, 0, f"unreadable ledger: {type(exc).__name__}"
