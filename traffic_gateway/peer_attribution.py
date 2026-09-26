"""
traffic_gateway/peer_attribution.py

Recovers the real peer IP for a honeypot session. The gateway is a transparent
proxy, so the honeypot only ever sees the gateway (127.0.0.1, or the Docker
bridge 172.x.x.x when Cowrie runs in a container). The gateway's own log knows
who it proxied, so each captured session is matched back by connect time.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import CONFIG

GATEWAY_EVENT_LOG = CONFIG.DATA_DIR / CONFIG.SESSION_LOG_FILE

# How far apart the gateway's PROXY_CONNECTED and the honeypot's session.connect
# may be and still be considered the same connection. Generous on purpose: when
# Cowrie runs in a container its clock can skew seconds from the host, and under
# a burst the honeypot processes sessions a little behind the gateway. A wide
# window is safe in the common single-attacker case (every proxy event carries
# the same peer IP); with several simultaneous peers it can mis-attribute, which
# is documented as a live-demo caveat.
MATCH_WINDOW_SEC = 45.0
_CACHE_TTL_SEC = 2.0

# Addresses that are the proxy itself, never a real peer.
_PROXY_ADDRS = {"127.0.0.1", "::1", "localhost"}


def _is_proxy_addr(ip: str) -> bool:
    ip = str(ip or "")
    return ip in _PROXY_ADDRS or ip.startswith("172.1") or ip.startswith("172.2")


def parse_ts(value) -> Optional[float]:
    """ISO-8601 (with or without Z) -> epoch seconds."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        text = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


class PeerAttributor:
    """Maps a honeypot session's start time back to the IP the gateway proxied."""

    def __init__(self, event_log: Path = GATEWAY_EVENT_LOG,
                 window: float = MATCH_WINDOW_SEC) -> None:
        self.event_log = Path(event_log)
        self.window = float(window)
        self._events: List[Tuple[float, str]] = []   # (ts, ip), ascending
        self._loaded_at = 0.0

    def _load(self) -> None:
        """Re-read the gateway log at most every _CACHE_TTL_SEC."""
        if time.time() - self._loaded_at < _CACHE_TTL_SEC:
            return
        events: List[Tuple[float, str]] = []
        if self.event_log.exists():
            with self.event_log.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or "PROXY_CONNECTED" not in line:
                        continue
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    if e.get("event") != "PROXY_CONNECTED":
                        continue
                    if e.get("type") != "honeypot":
                        continue
                    ts = parse_ts(e.get("ts"))
                    ip = str(e.get("ip", ""))
                    # Never filter by address here: this field is always the
                    # PEER as the gateway saw it, and during a local rehearsal
                    # the peer legitimately is 127.0.0.1.
                    if ts is not None and ip:
                        events.append((ts, ip))
        events.sort()
        self._events = events
        self._loaded_at = time.time()

    def resolve(self, session_start, fallback: str = "") -> str:
        """Peer IP for a honeypot session that began at `session_start`.

        Returns `fallback` (the address the honeypot saw) when nothing matches,
        so a session is never silently attributed to the wrong person.
        """
        ts = parse_ts(session_start)
        if ts is None:
            return fallback
        self._load()
        if not self._events:
            return fallback
        best_ip, best_gap = fallback, self.window
        for ev_ts, ip in self._events:
            gap = abs(ev_ts - ts)
            if gap <= best_gap:
                best_gap, best_ip = gap, ip
            elif ev_ts - ts > self.window:
                break        # sorted: everything later is further away
        return best_ip

    def resolve_map(self, sessions: Dict[str, object]) -> Dict[str, str]:
        """{session_id: start_time} -> {session_id: peer_ip}."""
        return {sid: self.resolve(start) for sid, start in sessions.items()}


# Shared instance -- the API and the pipeline both attribute from one cache.
attributor = PeerAttributor()


def resolve_peer_ip(session_start, fallback: str = "") -> str:
    return attributor.resolve(session_start, fallback)


def looks_like_proxy(ip: str) -> bool:
    """True when this address is the gateway/bridge rather than a real peer."""
    return _is_proxy_addr(ip)
