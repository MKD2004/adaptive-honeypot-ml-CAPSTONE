"""
response_mitigation/executors/gateway.py

DIVERT: add the source to the gateway blacklist. A blacklisted IP is still sent
to the honeypot (traffic_router: "keep observing; useful intel") -- this is not
a block. The behaviour, the reason text and the log line are the same as the
inline code in post_session_pipeline.py that this replaces.

The blacklist manager is passed in rather than imported, so this package never
imports traffic_gateway (which imports it).
"""
from __future__ import annotations

import logging
from typing import Optional

from ..models import PlannedAction, Verdict

log = logging.getLogger("response_mitigation.gateway")


class GatewayExecutor:
    def __init__(self, manager) -> None:
        """`manager` needs is_blacklisted(ip) and blacklist(ip, *, reason, source, risk_score)."""
        self._manager = manager

    def skip_reason(self, verdict: Verdict, planned: PlannedAction) -> Optional[str]:
        if self._manager.is_blacklisted(verdict.ip):
            return "already blacklisted"
        return None

    def apply(self, verdict: Verdict, planned: PlannedAction) -> str:
        self._manager.blacklist(
            verdict.ip,
            reason=(f"MT3: {verdict.micro_state} "
                    f"(phase {verdict.phase} {verdict.phase_name}, "
                    f"conf {verdict.confidence:.2f})"),
            source="mt3_pipeline",
            risk_score=float(verdict.confidence),
        )
        log.warning("auto-blacklisted %s: MT3 classified %s (p=%.2f)",
                    verdict.ip, verdict.micro_state, verdict.confidence)
        return "added to the gateway blacklist"
