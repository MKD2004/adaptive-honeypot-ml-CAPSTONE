"""
traffic_gateway/gateway_logger.py

Structured event logger.

Every significant gateway event is written as:
  1. A human-readable line  →  logs/gateway.log
  2. A machine-readable JSON record  →  data/sessions.jsonl
     (consumed downstream by the ML analytics pipeline)
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from .config import CONFIG


# ── Event taxonomy ────────────────────────────────────────────────────────────
class GatewayEvent(str, Enum):
    # Connection lifecycle
    CONN_RECEIVED       = "CONN_RECEIVED"
    CONN_ROUTED         = "CONN_ROUTED"
    CONN_CLOSED         = "CONN_CLOSED"
    CONN_REJECTED       = "CONN_REJECTED"       # rate-limit or hard block

    # Classification changes
    IP_CLASSIFIED       = "IP_CLASSIFIED"
    IP_SUSPICIOUS       = "IP_SUSPICIOUS"
    IP_BLACKLISTED      = "IP_BLACKLISTED"

    # Promotion pipeline
    PROMOTION_ELIGIBLE  = "PROMOTION_ELIGIBLE"  # entered review queue
    PROMOTION_DENIED    = "PROMOTION_DENIED"    # ML score still too high
    PROMOTION_PROBATION = "PROMOTION_PROBATION" # moved to probation
    PROMOTION_APPROVED  = "PROMOTION_APPROVED"  # fully whitelisted
    PROBATION_STRIKE    = "PROBATION_STRIKE"    # bad behaviour during probation
    PROBATION_REVOKED   = "PROBATION_REVOKED"   # sent back to blacklist

    # Rate limiting
    RATE_LIMITED        = "RATE_LIMITED"

    # Proxy
    PROXY_CONNECTED     = "PROXY_CONNECTED"
    PROXY_ERROR         = "PROXY_ERROR"
    DATA_CAPTURED       = "DATA_CAPTURED"       # payload snapshot

    # System
    GATEWAY_STARTED     = "GATEWAY_STARTED"
    GATEWAY_STOPPED     = "GATEWAY_STOPPED"
    ML_ASSESSMENT       = "ML_ASSESSMENT"       # result of ML stub call


# ── Internal Python logger ────────────────────────────────────────────────────
def _build_logger() -> logging.Logger:
    logger = logging.getLogger("traffic_gateway")
    logger.setLevel(logging.DEBUG if CONFIG.DEBUG else logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)-8s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    fh = logging.FileHandler(CONFIG.LOG_DIR / CONFIG.GATEWAY_LOG_FILE)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


_log = _build_logger()
_session_log_path = CONFIG.DATA_DIR / CONFIG.SESSION_LOG_FILE


# ── Public API ────────────────────────────────────────────────────────────────
def log_event(
    event: GatewayEvent,
    ip: str,
    *,
    extra: Optional[Dict[str, Any]] = None,
    level: int = logging.INFO,
) -> None:
    """Emit a structured gateway event to both log targets."""
    record: Dict[str, Any] = {
        "ts":    datetime.now(timezone.utc).isoformat(),
        "event": event.value,
        "ip":    ip,
    }
    if extra:
        record.update(extra)

    # Human-readable log
    detail = " ".join(f"{k}={v}" for k, v in (extra or {}).items())
    _log.log(level, "[%s] ip=%-15s %s", event.value, ip, detail)

    # Machine-readable JSONL for ML pipeline
    try:
        with _session_log_path.open("a") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except OSError as exc:
        _log.error("Failed to write session log: %s", exc)


# Convenience wrappers so callers don't import logging directly
def debug(msg: str, *args: Any) -> None:
    _log.debug(msg, *args)

def info(msg: str, *args: Any) -> None:
    _log.info(msg, *args)

def warning(msg: str, *args: Any) -> None:
    _log.warning(msg, *args)

def error(msg: str, *args: Any) -> None:
    _log.error(msg, *args)
