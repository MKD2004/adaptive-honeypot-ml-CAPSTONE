"""
traffic_gateway/proxy_handler.py

Transparent async TCP proxy.

Bidirectionally pipes bytes between the original client and the chosen
target (honeypot or real backend) while:
  - Capturing a payload snippet for the reputation scorer
  - Accumulating byte counters on the Session record
  - Handling timeouts and partial connection failures gracefully

The attacker / legitimate user has NO indication they are being proxied;
from their perspective they are talking directly to the service.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional, Tuple

from .config import CONFIG, Target
from . import gateway_logger as glog
from .gateway_logger import GatewayEvent
from .session_tracker import Session, session_tracker


class ProxyHandler:
    """
    One instance is created per accepted connection.

    Usage:
        handler = ProxyHandler(client_reader, client_writer, target, ip)
        await handler.run()
    """

    def __init__(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target: Target,
        ip: str,
        target_type: str,   # "honeypot" | "backend"
    ) -> None:
        self._client_r = client_reader
        self._client_w = client_writer
        self._target   = target
        self._ip       = ip
        self._target_type = target_type

        self._session: Optional[Session] = None
        self._target_r: Optional[asyncio.StreamReader] = None
        self._target_w: Optional[asyncio.StreamWriter] = None

    # ── Main entry point ───────────────────────────────────────────────────
    async def run(self) -> None:
        """Connect to target and pipe data until either side closes."""
        try:
            await self._connect_to_target()
            await self._pipe_bidirectional()
        except asyncio.TimeoutError:
            glog.log_event(
                GatewayEvent.PROXY_ERROR, self._ip,
                extra={"error": "timeout", "target": str(self._target)},
                level=logging.WARNING,
            )
        except ConnectionRefusedError:
            glog.log_event(
                GatewayEvent.PROXY_ERROR, self._ip,
                extra={"error": "connection_refused", "target": str(self._target)},
                level=logging.WARNING,
            )
        except Exception as exc:
            glog.log_event(
                GatewayEvent.PROXY_ERROR, self._ip,
                extra={"error": str(exc), "target": str(self._target)},
                level=logging.ERROR,
            )
        finally:
            await self._cleanup()

    # ── Internal ───────────────────────────────────────────────────────────
    async def _connect_to_target(self) -> None:
        self._target_r, self._target_w = await asyncio.wait_for(
            asyncio.open_connection(self._target.host, self._target.port),
            timeout=CONFIG.PROXY_CONNECT_TIMEOUT,
        )

        target_addr = f"{self._target.host}:{self._target.port}"
        self._session = session_tracker.open_session(
            self._ip,
            target=self._target_type,
            target_addr=target_addr,
        )

        glog.log_event(
            GatewayEvent.PROXY_CONNECTED, self._ip,
            extra={
                "session_id": self._session.session_id,
                "target":     str(self._target),
                "type":       self._target_type,
            },
        )

    async def _pipe_bidirectional(self) -> None:
        """Run two copy-loops concurrently; stop when either side closes."""
        await asyncio.gather(
            self._pipe(
                self._client_r, self._target_w,
                direction="in",
            ),
            self._pipe(
                self._target_r, self._client_w,
                direction="out",
            ),
            return_exceptions=True,
        )

    async def _pipe(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        direction: str,
    ) -> None:
        """
        Copy bytes from reader → writer until EOF.
        Each chunk is recorded on the session for analysis.
        """
        try:
            while True:
                try:
                    data = await asyncio.wait_for(
                        reader.read(CONFIG.PROXY_BUF_SIZE),
                        timeout=CONFIG.SESSION_TIMEOUT_SEC,
                    )
                except asyncio.TimeoutError:
                    glog.debug(
                        "Session timeout for %s (direction=%s)", self._ip, direction
                    )
                    break

                if not data:
                    break   # EOF

                # Record for scoring before forwarding
                if self._session:
                    session_tracker.record_data(
                        self._session,
                        direction=direction,
                        data=data,
                    )

                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass    # normal when the remote closes abruptly

    async def _cleanup(self) -> None:
        """Close both sides and finalise the session record."""
        for writer in (self._client_w, self._target_w):
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        if self._session:
            session_tracker.close_session(self._session)
