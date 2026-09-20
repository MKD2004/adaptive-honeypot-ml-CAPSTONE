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
    # Populated when CONFIG.CLASSIFIER_ROUTING is on; carried into the
    # CONN_ROUTED event so the dashboard can show WHY an IP was routed.
    verdict:     Optional[str]   = None   # MALICIOUS | SUSPICIOUS | BENIGN
    score:       Optional[float] = None   # 0.0 - 1.0
    signals:     tuple           = ()


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

        # ── 1. Resolve trust before rate-limiting ──────────────────────────
        # A WHITELISTED ip is rate-limited against RATE_LIMIT_TRUSTED_MAX_CONN
        # instead of the normal ceiling -- more headroom, not an exemption, so a
        # compromised trusted host still cannot hammer the real backend. The
        # status must be resolved first because a hard block lives ONLY in this
        # process's memory: the dashboard is a separate process and cannot clear
        # one, so a promotion has to be honoured here or not at all.
        status = classifier.get_status(ip)
        trusted = status == IPStatus.WHITELISTED

        # ── 2. Rate-limit check ───────────────────────────────────────────
        if not rate_limiter.check(
            ip, max_conn=CONFIG.RATE_LIMIT_TRUSTED_MAX_CONN if trusted else None
        ):
            return RoutingDecision(
                target=None,
                target_type="reject",
                reason="rate_limited_trusted" if trusted else "rate_limited",
            )

        # ── 3. Signal-based verdict (telemetry always; routing when enabled) ──
        # Only signals 1 and 2 (reputation + behaviour) can fire here: no bytes
        # have been proxied yet, so there is no payload to score. The payload
        # signals run post-session, in the MT3 pipeline.
        verdict = score = None
        signals: tuple = ()
        if CONFIG.CLASSIFIER_ROUTING:
            from .traffic_classifier import traffic_classifier

            result = traffic_classifier.classify(
                {"src_ip": ip, "dst_port": CONFIG.GATEWAY_PORT}
            )
            verdict = result["verdict"]
            score = result["score"]
            signals = tuple(result["signals_fired"])

        # ── 4. Status-based routing (status resolved in step 1) ───────────
        if status == IPStatus.WHITELISTED:
            decision = RoutingDecision(
                target=CONFIG.REAL_BACKEND,
                target_type="backend",
                reason="whitelisted",
                verdict=verdict, score=score, signals=signals,
            )
        elif status == IPStatus.UNKNOWN and CONFIG.CLASSIFIER_ROUTING:
            # An unknown IP the classifier judges harmless reaches the real
            # service; anything scoring SUSPICIOUS or above is diverted.
            if verdict == "BENIGN":
                decision = RoutingDecision(
                    target=CONFIG.REAL_BACKEND,
                    target_type="backend",
                    reason=f"classifier_benign_score_{score:.2f}",
                    verdict=verdict, score=score, signals=signals,
                )
            else:
                decision = RoutingDecision(
                    target=self._next_honeypot(),
                    target_type="honeypot",
                    reason=f"classifier_{str(verdict).lower()}_score_{score:.2f}",
                    verdict=verdict, score=score, signals=signals,
                )
        elif status == IPStatus.BLACKLISTED:
            decision = RoutingDecision(
                target=self._next_honeypot(),
                target_type="honeypot",
                reason="blacklisted_honeypot_observation",
                verdict=verdict, score=score, signals=signals,
            )
        elif status == IPStatus.PROBATION:
            decision = RoutingDecision(
                target=self._next_honeypot(),
                target_type="honeypot",
                reason="probation_honeypot_observation",
                verdict=verdict, score=score, signals=signals,
            )
        elif status == IPStatus.SUSPICIOUS:
            decision = RoutingDecision(
                target=self._next_honeypot(),
                target_type="honeypot",
                reason="suspicious_redirect",
                verdict=verdict, score=score, signals=signals,
            )
        else:
            # UNKNOWN — zero-trust default
            decision = RoutingDecision(
                target=self._next_honeypot(),
                target_type="honeypot",
                reason="unknown_zero_trust_redirect",
                verdict=verdict, score=score, signals=signals,
            )

        glog.log_event(
            GatewayEvent.CONN_ROUTED, ip,
            extra={
                "ip_status":   status.value,
                "target_type": decision.target_type,
                "target":      str(decision.target) if decision.target else "none",
                "reason":      decision.reason,
                "verdict":     decision.verdict,
                "score":       decision.score,
                "signals":     list(decision.signals),
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
