"""
traffic_gateway/inspection_gateway.py

Traffic Inspection Gateway — Main Server
══════════════════════════════════════════

The gateway is a single asyncio TCP server that:

  1. Accepts every inbound connection on GATEWAY_HOST:GATEWAY_PORT
  2. Rate-checks the source IP                    (rate_limiter)
  3. Looks up the IP's current trust status        (ip_classifier)
  4. Decides where to send the connection          (traffic_router)
       • WHITELISTED  →  real backend
       • Everything else → honeypot  (zero-trust by default)
  5. Transparently proxies bytes in both directions (proxy_handler)
  6. Scores the IP after each session              (reputation_scorer)
  7. Upgrades status if score crosses a threshold  (auto-escalation)
  8. Notifies the promotion engine after session   (whitelist_promoter)

Start the server
─────────────────
    python -m traffic_gateway.inspection_gateway

Or from code:
    from traffic_gateway.inspection_gateway import InspectionGateway
    gw = InspectionGateway()
    asyncio.run(gw.serve_forever())

Admin / monitoring
──────────────────
    gw.status()              # dict snapshot of all subsystems
    await gw.force_review(ip)  # trigger immediate ML review for one IP
"""
from __future__ import annotations

import asyncio
import logging
import signal
import sys
from typing import Optional

from .config import CONFIG
from . import gateway_logger as glog
from .gateway_logger import GatewayEvent
from .ip_classifier import IPStatus, classifier
from .blacklist_manager import blacklist_manager
from .rate_limiter import rate_limiter
from .traffic_router import router, RoutingDecision
from .proxy_handler import ProxyHandler
from .reputation_scorer import ml_risk_assessment
from .whitelist_promoter import promoter
from .session_tracker import session_tracker


class InspectionGateway:
    """
    Async TCP gateway server.
    """

    def __init__(self) -> None:
        self._server: Optional[asyncio.AbstractServer] = None
        self._active_connections = 0
        self._promoter_task: Optional[asyncio.Task] = None

    # ── Public entry point ─────────────────────────────────────────────────
    async def serve_forever(self) -> None:
        """Start the server and run until interrupted."""
        self._install_signal_handlers()

        # Start background promotion engine
        self._promoter_task = asyncio.create_task(
            promoter.run(), name="whitelist_promoter"
        )

        self._server = await asyncio.start_server(
            self._handle_connection,
            CONFIG.GATEWAY_HOST,
            CONFIG.GATEWAY_PORT,
            backlog=256,
        )

        addr = f"{CONFIG.GATEWAY_HOST}:{CONFIG.GATEWAY_PORT}"
        glog.log_event(
            GatewayEvent.GATEWAY_STARTED, "system",
            extra={
                "listening_on":    addr,
                "real_backend":    str(CONFIG.REAL_BACKEND),
                "honeypot_count":  len(CONFIG.HONEYPOT_TARGETS),
                "honeypots":       [str(t) for t in CONFIG.HONEYPOT_TARGETS],
            },
        )

        async with self._server:
            await self._server.serve_forever()

    async def shutdown(self) -> None:
        """Graceful shutdown."""
        glog.log_event(GatewayEvent.GATEWAY_STOPPED, "system")

        if self._promoter_task:
            promoter.stop()
            self._promoter_task.cancel()
            try:
                await self._promoter_task
            except asyncio.CancelledError:
                pass

        if self._server:
            self._server.close()
            await self._server.wait_closed()

    # ── Per-connection handler ─────────────────────────────────────────────
    async def _handle_connection(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """
        Called by asyncio for every accepted TCP connection.
        This is the core of the gateway logic.
        """
        ip = client_writer.get_extra_info("peername", ("0.0.0.0", 0))[0]

        # ── Guard: too many concurrent connections ────────────────────────
        if self._active_connections >= CONFIG.MAX_CONCURRENT_CONNS:
            glog.log_event(
                GatewayEvent.CONN_REJECTED, ip,
                extra={"reason": "max_concurrent_connections_reached"},
                level=logging.WARNING,
            )
            client_writer.close()
            return

        self._active_connections += 1
        classifier.increment_connection(ip, to_honeypot=False)  # will correct below

        glog.log_event(
            GatewayEvent.CONN_RECEIVED, ip,
            extra={
                "active_connections": self._active_connections,
                "ip_status":         classifier.get_status(ip).value,
            },
        )

        try:
            await self._process_connection(ip, client_reader, client_writer)
        finally:
            self._active_connections -= 1

    async def _process_connection(
        self,
        ip: str,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Route, proxy, score, and auto-escalate for a single connection."""

        # ── Routing decision ──────────────────────────────────────────────
        decision: RoutingDecision = router.decide_route(ip)

        if decision.target is None:
            # Rate-limited: close without proxying
            glog.log_event(
                GatewayEvent.CONN_REJECTED, ip,
                extra={"reason": decision.reason},
                level=logging.WARNING,
            )
            client_writer.close()
            return

        # Update the connection counter correctly (router made the call)
        to_honeypot = decision.target_type == "honeypot"
        classifier.increment_connection(ip, to_honeypot=to_honeypot)

        # ── Proxy ─────────────────────────────────────────────────────────
        handler = ProxyHandler(
            client_reader,
            client_writer,
            decision.target,
            ip,
            target_type=decision.target_type,
        )
        await handler.run()

        # ── Post-session: score and auto-escalate ─────────────────────────
        await self._post_session_scoring(ip, decision)

    async def _post_session_scoring(
        self,
        ip: str,
        decision: RoutingDecision,
    ) -> None:
        """
        After a session closes, re-score the IP and apply any automatic
        status escalations.

        Also notifies the whitelist promoter so it can react to probation
        violations in real time.
        """
        score, reasoning = await ml_risk_assessment(ip)
        classifier.update_risk_score(ip, score)

        current_status = classifier.get_status(ip)

        # ── Escalation logic ──────────────────────────────────────────────
        if current_status == IPStatus.UNKNOWN:
            if score >= CONFIG.SCORE_BLACKLIST:
                blacklist_manager.blacklist(
                    ip,
                    reason=f"Auto-blacklisted post-session: score={score:.3f}",
                    source="reputation_scorer",
                    risk_score=score,
                )
                glog.log_event(
                    GatewayEvent.IP_BLACKLISTED, ip,
                    extra={"score": round(score, 4), "reasoning": reasoning},
                    level=logging.WARNING,
                )
            elif score >= CONFIG.SCORE_SUSPICIOUS:
                classifier.set_status(
                    ip, IPStatus.SUSPICIOUS,
                    reason=f"Auto-suspicious post-session: score={score:.3f}",
                    risk_score=score,
                )
                glog.log_event(
                    GatewayEvent.IP_SUSPICIOUS, ip,
                    extra={"score": round(score, 4), "reasoning": reasoning},
                )

        elif current_status == IPStatus.SUSPICIOUS:
            if score >= CONFIG.SCORE_BLACKLIST:
                blacklist_manager.blacklist(
                    ip,
                    reason=f"Escalated from SUSPICIOUS: score={score:.3f}",
                    source="reputation_scorer",
                    risk_score=score,
                )

        elif current_status == IPStatus.WHITELISTED:
            # Even trusted IPs are continuously monitored
            if score >= CONFIG.SCORE_SUSPICIOUS:
                glog.log_event(
                    GatewayEvent.IP_SUSPICIOUS, ip,
                    extra={
                        "score":   round(score, 4),
                        "warning": "Whitelisted IP score elevated — under review.",
                    },
                    level=logging.WARNING,
                )
            if score >= CONFIG.SCORE_BLACKLIST:
                blacklist_manager.blacklist(
                    ip,
                    reason=f"Whitelisted IP re-blacklisted: score={score:.3f}",
                    source="continuous_monitor",
                    risk_score=score,
                )

        # ── Notify promoter (handles PROBATION strikes) ───────────────────
        # Pull the session that was just closed from tracker history
        history = session_tracker.get_history(ip)
        if history:
            latest_session = history[-1]
            await promoter.notify_session_closed(ip, latest_session)

    # ── Admin / monitoring helpers ─────────────────────────────────────────
    def status(self) -> dict:
        """Live snapshot of all gateway subsystems."""
        pipeline = promoter.queue_status()
        rl_stats  = rate_limiter.stats()
        router_st = router.stats()
        all_recs  = classifier.all_records()

        return {
            "active_connections":  self._active_connections,
            "ip_totals": {
                s.value: sum(1 for r in all_recs if r.status == s)
                for s in IPStatus
            },
            "rate_limiter":        rl_stats,
            "promotion_pipeline":  pipeline,
            "routing":             router_st,
        }

    async def force_review(self, ip: str) -> dict:
        """Trigger an immediate ML review for a specific IP (admin use)."""
        return await promoter.force_review(ip)

    # ── Signal handling ────────────────────────────────────────────────────
    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(
                    sig,
                    lambda: asyncio.create_task(self.shutdown()),
                )
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                pass


# ── Module entry point ────────────────────────────────────────────────────────
if __name__ == "__main__":
    gateway = InspectionGateway()
    try:
        asyncio.run(gateway.serve_forever())
    except KeyboardInterrupt:
        glog.info("Gateway stopped by user.")
        sys.exit(0)
