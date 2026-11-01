"""
response_mitigation/audit.py

The decision log: one JSON object per line, appended, never rewritten.
Every decision goes here -- applied, would-apply and skipped -- with the reason.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Dict, Set, Union

from .models import Decision


class AuditLog:
    """Append-only JSON Lines file.

    A failed write raises OSError. Callers must not carry out an action they
    could not record.
    """

    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def write(self, decision: Decision) -> None:
        # allow_nan=False makes sure the line is valid JSON; to_record() has
        # already turned NaN/inf into null.
        line = json.dumps(decision.to_record(), separators=(",", ":"), allow_nan=False)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # newline="\n" keeps one line ending on every OS (Windows would
            # otherwise write CRLF, and the Linux host reads this file too).
            with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    def check_writable(self) -> None:
        """Raise OSError unless a line could be appended right now.

        The engine asks before a firewall block, so it never blocks anyone it
        could not then write down.
        """
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8", newline="\n"):
                pass

    def session_ids_by_ip(self) -> Dict[str, Set[str]]:
        """Sessions already on record, per IP, so a restart keeps its history.

        Lines that cannot be read, and lines with no session id, are skipped.
        That can only undercount, which makes a repeat-offender block later,
        never sooner.
        """
        seen: Dict[str, Set[str]] = {}
        if not self.path.exists():
            return seen
        with open(self.path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                    ip, sid = rec["ip"], rec["session_id"]
                except (ValueError, KeyError, TypeError):
                    continue
                if isinstance(ip, str) and isinstance(sid, str) and sid:
                    seen.setdefault(ip, set()).add(sid)
        return seen
