"""
traffic_gateway/session_tracker.py

Tracks every proxied session with timing, byte counters, and a captured
payload snapshot.

The data collected here feeds the reputation_scorer and is also written
to sessions.jsonl for the ML analytics pipeline.
"""
from __future__ import annotations

import asyncio
import math
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional

from .config import CONFIG
from . import gateway_logger as glog
from .gateway_logger import GatewayEvent


# ── Session record ────────────────────────────────────────────────────────────
@dataclass
class Session:
    session_id:    str
    ip:            str
    target:        str            # "honeypot" | "backend"
    target_addr:   str            # host:port
    started_at:    str            = field(default_factory=lambda: _utcnow())
    ended_at:      Optional[str]  = None
    duration_sec:  float          = 0.0

    bytes_in:      int = 0        # client → target
    bytes_out:     int = 0        # target → client
    payload_snip:  bytes = b""    # first N bytes from client for inspection

    # Derived
    commands_seen: int   = 0
    entropy:       float = 0.0    # Shannon entropy of payload sample

    def close(self) -> None:
        self.ended_at    = _utcnow()
        now = datetime.now(timezone.utc)
        started = datetime.fromisoformat(self.started_at)
        self.duration_sec = (now - started).total_seconds()
        self.entropy      = _shannon_entropy(self.payload_snip)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["payload_snip"] = self.payload_snip.hex()
        return d


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string (0 = uniform, 8 = fully random)."""
    if not data:
        return 0.0
    freq: Dict[int, int] = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ── Per-IP session history ────────────────────────────────────────────────────
class SessionTracker:
    """
    Maintains a rolling window of recent sessions per IP.

    Designed for concurrent access from asyncio tasks — all mutations happen
    in the event loop thread so no locking is needed for pure async code.
    For cross-thread access (e.g. tests) use asyncio.run_coroutine_threadsafe.
    """

    MAX_HISTORY_PER_IP = 50   # keep last 50 sessions per IP in memory

    def __init__(self) -> None:
        # ip → deque of closed Sessions
        self._history:  Dict[str, Deque[Session]] = defaultdict(
            lambda: deque(maxlen=self.MAX_HISTORY_PER_IP)
        )
        # session_id → open Session
        self._active:   Dict[str, Session] = {}

        self._id_counter = 0

    # ── Session lifecycle ──────────────────────────────────────────────────
    def open_session(
        self,
        ip: str,
        *,
        target: str,
        target_addr: str,
    ) -> Session:
        self._id_counter += 1
        sid = f"{ip}_{self._id_counter:06d}"
        session = Session(
            session_id=sid,
            ip=ip,
            target=target,
            target_addr=target_addr,
        )
        self._active[sid] = session
        return session

    def record_data(
        self,
        session: Session,
        *,
        direction: str,    # "in" (client→target) | "out" (target→client)
        data: bytes,
    ) -> None:
        """Accumulate byte counters and capture an initial payload snippet."""
        if direction == "in":
            session.bytes_in += len(data)
            # Capture only the first chunk for later inspection
            if len(session.payload_snip) < CONFIG.MAX_PAYLOAD_LOG_BYTES:
                remaining = CONFIG.MAX_PAYLOAD_LOG_BYTES - len(session.payload_snip)
                session.payload_snip += data[:remaining]
        else:
            session.bytes_out += len(data)

    def close_session(self, session: Session) -> Session:
        """Finalise and archive a session; returns the closed session."""
        session.close()

        if session.session_id in self._active:
            del self._active[session.session_id]

        self._history[session.ip].append(session)

        glog.log_event(
            GatewayEvent.CONN_CLOSED, session.ip,
            extra={
                "session_id":   session.session_id,
                "target":       session.target,
                "target_addr":  session.target_addr,
                "duration_sec": round(session.duration_sec, 3),
                "bytes_in":     session.bytes_in,
                "bytes_out":    session.bytes_out,
                "entropy":      round(session.entropy, 4),
            },
        )
        return session

    # ── Query ──────────────────────────────────────────────────────────────
    def get_history(self, ip: str) -> List[Session]:
        return list(self._history.get(ip, []))

    def get_active_count(self, ip: str) -> int:
        return sum(1 for s in self._active.values() if s.ip == ip)

    def get_active_sessions(self) -> List[Session]:
        return list(self._active.values())

    def recent_stats(self, ip: str, n: int = 10) -> dict:
        """Summarise the last n sessions for an IP."""
        hist = list(self._history.get(ip, []))[-n:]
        if not hist:
            return {}

        honeypot_count = sum(1 for s in hist if s.target == "honeypot")
        avg_bytes_in   = sum(s.bytes_in for s in hist) / len(hist)
        avg_duration   = sum(s.duration_sec for s in hist) / len(hist)
        avg_entropy    = sum(s.entropy for s in hist) / len(hist)

        return {
            "sample_size":    len(hist),
            "honeypot_ratio": round(honeypot_count / len(hist), 3),
            "avg_bytes_in":   round(avg_bytes_in, 1),
            "avg_duration":   round(avg_duration, 3),
            "avg_entropy":    round(avg_entropy, 4),
        }

    def to_dict_list(self, ip: str) -> List[dict]:
        return [s.to_dict() for s in self.get_history(ip)]


# Module-level singleton
session_tracker = SessionTracker()
