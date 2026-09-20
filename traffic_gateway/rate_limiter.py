"""
traffic_gateway/rate_limiter.py

Sliding-window rate limiter (per-IP).

Uses a collections.deque of timestamps to track recent connections.
On each new connection the window is trimmed and the count is compared
to CONFIG.RATE_LIMIT_MAX_CONN.

IPs that exceed the threshold are added to a time-limited hard-block set
so subsequent connections are rejected instantly without checking the window.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import DefaultDict, Deque, Dict, Optional, Set

from .config import CONFIG
from . import gateway_logger as glog
from .gateway_logger import GatewayEvent


def _now_ts() -> float:
    return datetime.now(timezone.utc).timestamp()


class RateLimiter:
    """
    Per-IP sliding-window rate limiter.

    Call check(ip) before opening each proxy connection.
    Returns True when the connection is allowed, False when it should be dropped.
    """

    def __init__(self) -> None:
        # ip → timestamps of recent connections within the window
        self._windows: DefaultDict[str, Deque[float]] = defaultdict(deque)
        # ip → unblock_timestamp (hard-block after rate offence)
        self._blocked_until: Dict[str, float] = {}
        # ip → the ceiling that earned the current block. Needed so a block
        # imposed under the strict limit can be reconsidered if the IP is later
        # promoted to a higher one, without weakening an ordinary block.
        self._block_limit: Dict[str, int] = {}

    # ── Public API ─────────────────────────────────────────────────────────
    def check(self, ip: str, *, max_conn: Optional[int] = None) -> bool:
        """
        Return True (allow) or False (rate-limited).
        This is synchronous and safe to call from any asyncio task.

        `max_conn` overrides CONFIG.RATE_LIMIT_MAX_CONN for this call. The
        router passes the higher trusted ceiling for WHITELISTED IPs: they are
        rate-limited like everyone else, just with more headroom.
        """
        now = _now_ts()
        limit = CONFIG.RATE_LIMIT_MAX_CONN if max_conn is None else int(max_conn)

        # ── Sliding window, pruned first so the block re-test sees it ──────
        window = self._windows[ip]
        cutoff = now - CONFIG.RATE_LIMIT_WINDOW_SEC
        while window and window[0] < cutoff:
            window.popleft()

        # ── Hard-block check ──────────────────────────────────────────────
        unblock_at = self._blocked_until.get(ip)
        if unblock_at:
            if now >= unblock_at:
                self._clear_block(ip)            # block expired
            elif limit > self._block_limit.get(ip, CONFIG.RATE_LIMIT_MAX_CONN) \
                    and len(window) < limit:
                # The IP has been promoted to a higher ceiling since this block
                # was applied, and its current rate is inside that ceiling. The
                # block was earned under rules that no longer apply to it.
                # (An IP on its ORIGINAL ceiling never takes this path, so an
                # ordinary hard block still runs its full RATE_LIMIT_BLOCK_SEC
                # even though the 60s window empties sooner.)
                self._clear_block(ip)
                glog.log_event(
                    GatewayEvent.RATE_LIMITED, ip,
                    extra={"reason": "hard_block_lifted_on_promotion",
                           "new_limit": limit,
                           "connections_in_window": len(window)},
                )
            else:
                glog.log_event(
                    GatewayEvent.RATE_LIMITED, ip,
                    extra={"reason": "hard_block",
                           "unblocks_in_sec": round(unblock_at - now, 1)},
                    level=logging.WARNING,
                )
                return False

        # ── Window check ──────────────────────────────────────────────────
        if len(window) >= limit:
            # Exceeded — apply hard block
            self._blocked_until[ip] = now + CONFIG.RATE_LIMIT_BLOCK_SEC
            self._block_limit[ip] = limit
            glog.log_event(
                GatewayEvent.RATE_LIMITED, ip,
                extra={
                    "reason":         "window_exceeded",
                    "connections_in_window": len(window),
                    "limit":          limit,
                    "window_sec":     CONFIG.RATE_LIMIT_WINDOW_SEC,
                    "block_sec":      CONFIG.RATE_LIMIT_BLOCK_SEC,
                },
                level=logging.WARNING,
            )
            return False

        window.append(now)
        return True

    def _clear_block(self, ip: str) -> None:
        self._blocked_until.pop(ip, None)
        self._block_limit.pop(ip, None)

    def is_blocked(self, ip: str) -> bool:
        unblock_at = self._blocked_until.get(ip)
        if unblock_at is None:
            return False
        if _now_ts() < unblock_at:
            return True
        self._clear_block(ip)
        return False

    def current_count(self, ip: str) -> int:
        """How many connections this IP has made in the current window."""
        now = _now_ts()
        cutoff = now - CONFIG.RATE_LIMIT_WINDOW_SEC
        window = self._windows.get(ip, deque())
        return sum(1 for ts in window if ts >= cutoff)

    def unblock(self, ip: str) -> None:
        """Manually lift a rate-limit block (e.g. after admin review)."""
        self._clear_block(ip)
        glog.info("Rate-limit block manually lifted for %s", ip)

    def stats(self) -> dict:
        now = _now_ts()
        return {
            "total_tracked_ips":  len(self._windows),
            "currently_blocked":  sum(
                1 for t in self._blocked_until.values() if t > now
            ),
        }


# Module-level singleton
rate_limiter = RateLimiter()
