"""
response_mitigation/blocklist.py

The block list file. The pipeline writes it; the host's apply_blocklist.py reads
it and updates the firewall. This module is the writer.

    {"version": 1, "updated_at": 1790000000,
     "entries": [{"ip": "45.33.32.156", "added_at": ..., "expires_at": ...,
                  "reason": "...", "rule": "repeat_offender", "session_id": "..."}]}

Times are whole seconds since 1970, so the host script needs no date parsing.

Each save goes to a temporary file in the same folder and is then renamed over
the real one, so the host script never reads a half-written file. The file is
made world-readable (mode 644): it holds only IPs and short reasons, and the
host script runs as root with a very small set of powers.

A file that cannot be read is NOT replaced. Replacing it would silently forget
blocks that are still in force, so the writer raises BlocklistCorrupt and the
engine records the DENY as failed.

The pipeline, the command-line tool and the dashboard API can all change this
file, from separate processes. Every change takes a lock file next to it
(blocklist.json.lock) first, so two changes can never overwrite each other.
Reading needs no lock: a save is a rename, so a reader sees the old file or the
new one, never half of one.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
try:
    import fcntl                      # Linux, macOS
except ImportError:                   # Windows
    fcntl = None
    import msvcrt
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

VERSION = 1
_REASON_MAX = 200


class BlocklistCorrupt(ValueError):
    """The file exists but cannot be understood. It is left untouched."""


class BlocklistBusy(OSError):
    """Another process held the lock for too long. Nothing was changed."""


class _ProcessLock:
    """An exclusive lock on <block list>.lock, shared by every process."""

    def __init__(self, path: Path, timeout_s: float = 10.0) -> None:
        self._path, self._timeout = Path(path), timeout_s
        self._fh = None

    def __enter__(self) -> "_ProcessLock":
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._path, "a+b")
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                self._try()
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    self._fh.close()
                    raise BlocklistBusy(f"{self._path.name} is locked by another process") from None
                time.sleep(0.02)

    def _try(self) -> None:
        if fcntl is not None:
            fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        else:
            self._fh.seek(0)
            msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)

    def __exit__(self, *exc) -> None:
        try:
            if fcntl is not None:
                fcntl.flock(self._fh, fcntl.LOCK_UN)
            else:
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            self._fh.close()


@dataclass(frozen=True)
class BlockEntry:
    ip: str
    added_at: int
    expires_at: int
    reason: str
    rule: str
    session_id: str


class BlocklistFile:
    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time,
                 lock_timeout_s: float = 10.0) -> None:
        self.path = Path(path)
        self._clock = clock
        self._lock_timeout_s = lock_timeout_s
        self._lock = threading.Lock()
        self._lock_path = self.path.with_name(self.path.name + ".lock")

    # -- reading ------------------------------------------------------------
    def entries(self) -> List[BlockEntry]:
        """Blocks that are still in force, oldest first."""
        with self._lock:
            return self._live(self._read(), self._clock())

    def get(self, ip: str) -> Optional[BlockEntry]:
        return next((e for e in self.entries() if e.ip == ip), None)

    # -- writing ------------------------------------------------------------
    def add(self, ip: str, *, ttl_s: int, reason: str, rule: str, session_id: str = "") -> BlockEntry:
        """Block `ip` for `ttl_s` seconds. If it is already blocked the existing entry
        is kept as it is (the firewall would not lengthen it anyway)."""
        if isinstance(ttl_s, bool) or not isinstance(ttl_s, int) or ttl_s < 1:
            raise ValueError("ttl_s must be a whole number of seconds, at least 1")
        with self._lock, _ProcessLock(self._lock_path, self._lock_timeout_s):
            now = int(self._clock())
            live = self._live(self._read(), now)
            for entry in live:
                if entry.ip == ip:
                    return entry
            entry = BlockEntry(ip=ip, added_at=now, expires_at=now + ttl_s,
                               reason=_one_line(reason), rule=rule, session_id=session_id)
            self._save(live + [entry], now)
            return entry

    def remove(self, ip: str) -> bool:
        """Lift a block (an operator pressing 'unblock'). True if there was one."""
        with self._lock, _ProcessLock(self._lock_path, self._lock_timeout_s):
            now = int(self._clock())
            live = self._live(self._read(), now)
            kept = [e for e in live if e.ip != ip]
            if len(kept) == len(live):
                return False
            self._save(kept, now)
            return True

    # -- internals ----------------------------------------------------------
    @staticmethod
    def _live(entries: List[BlockEntry], now: float) -> List[BlockEntry]:
        return sorted((e for e in entries if e.expires_at > now), key=lambda e: e.added_at)

    def _read(self) -> List[BlockEntry]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        try:
            doc = json.loads(raw)
            if not isinstance(doc, dict) or doc.get("version") != VERSION:
                raise ValueError("unknown layout")
            return [BlockEntry(**item) for item in doc["entries"]]
        except (ValueError, KeyError, TypeError) as exc:
            raise BlocklistCorrupt(f"{self.path.name} cannot be read ({type(exc).__name__}); "
                                   "fix or move it, then block again") from None

    def _save(self, entries: List[BlockEntry], now: int) -> None:
        doc = {"version": VERSION, "updated_at": now, "entries": [asdict(e) for e in entries]}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".blocklist-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(doc, handle, indent=2, allow_nan=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o644)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def iso_utc(epoch: float) -> str:
    """Whole seconds since 1970 as a readable UTC time, e.g. 2026-11-02T08:00:00Z."""
    import datetime as _dt
    return _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _one_line(text: str) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= _REASON_MAX else text[:_REASON_MAX - 1] + "…"
