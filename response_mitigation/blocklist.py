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

One pipeline process writes this file. The lock below covers threads in that
process, not two separate processes.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

VERSION = 1
_REASON_MAX = 200


class BlocklistCorrupt(ValueError):
    """The file exists but cannot be understood. It is left untouched."""


@dataclass(frozen=True)
class BlockEntry:
    ip: str
    added_at: int
    expires_at: int
    reason: str
    rule: str
    session_id: str


class BlocklistFile:
    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        self._lock = threading.Lock()

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
        with self._lock:
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
        with self._lock:
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


def _one_line(text: str) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= _REASON_MAX else text[:_REASON_MAX - 1] + "…"
