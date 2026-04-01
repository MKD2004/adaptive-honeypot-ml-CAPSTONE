"""
traffic_gateway/traffic_router.py

Routing decision engine.

Given an IP address, decide_route() returns:
  - The Target to proxy the connection to
  - A human-readable routing reason

Routing table (highest priority first):
  1. Rate-blocked          → reject outright (no proxy)
  2. WHITELISTED           → real backend
  3. BLACKLISTED           → honeypot (keep observing; useful intel)
  4. PROBATION             → honeypot (still being watched)
  5. SUSPICIOUS            → honeypot
  6. UNKNOWN (zero-trust)  → honeypot

The honeypot selection cycles round-robin across CONFIG.HONEYPOT_TARGETS so
load is balanced across all emulated services.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Iterator, Optional, Tuple

from .config import CONFIG, Target
from .ip_classifier import IPStatus, classifier
from .rate_limiter import rate_limiter
from . import gateway_logger as glog
from .gateway_logger import GatewayEvent


@dataclass(frozen=True)
class RoutingDecision:
    target:      Optional[Target]    # None means reject the connection
    target_type: str                 # "honeypot" | "backend" | "reject"
    reason:      str


class TrafficRouter:
    """
    Stateless (except for the round-robin iterator) routing engine.
    """

    def __init__(self) -> None:
        self._honeypot_cycle: Iterator[Target] = itertools.cycle(
            CONFIG.HONEYPOT_TARGETS
        )

    def decide_route(self, ip: str) -> RoutingDecision:
        """
        Central routing logic.

        Returns a RoutingDecision.  If target is None the caller must close
        the connection without proxying.
        """

        # ── 1. Rate-limit check ───────────────────────────────────────────
        if not rate_limiter.check(ip):
            return RoutingDecision(
                target=None,
                target_type="reject",
                reason="rate_limited",
            )

        # ── 2. Status-based routing ───────────────────────────────────────
        status = classifier.get_status(ip)

        if status == IPStatus.WHITELISTED:
            decision = RoutingDecision(
                target=CONFIG.REAL_BACKEND,
                target_type="backend",
                reason="whitelisted",
            )
        elif status == IPStatus.BLACKLISTED:
            decision = RoutingDecision(
                target=self._next_honeypot(),
                target_type="honeypot",
                reason="blacklisted_honeypot_observation",
            )
        elif status == IPStatus.PROBATION:
            decision = RoutingDecision(
                target=self._next_honeypot(),
                target_type="honeypot",
                reason="probation_honeypot_observation",
            )
        elif status == IPStatus.SUSPICIOUS:
            decision = RoutingDecision(
                target=self._next_honeypot(),
                target_type="honeypot",
                reason="suspicious_redirect",
            )
        else:
            # UNKNOWN — zero-trust default
            decision = RoutingDecision(
                target=self._next_honeypot(),
                target_type="honeypot",
                reason="unknown_zero_trust_redirect",
            )

        glog.log_event(
            GatewayEvent.CONN_ROUTED, ip,
            extra={
                "ip_status":   status.value,
                "target_type": decision.target_type,
                "target":      str(decision.target) if decision.target else "none",
                "reason":      decision.reason,
            },
        )
        return decision

    def _next_honeypot(self) -> Target:
        return next(self._honeypot_cycle)

    def stats(self) -> dict:
        return {
            "honeypot_count": len(CONFIG.HONEYPOT_TARGETS),
            "real_backend":   str(CONFIG.REAL_BACKEND),
        }


# Module-level singleton
router = TrafficRouter()
