"""
traffic_gateway/config.py

Single source of truth for all gateway parameters.
Edit this file to change behaviour without touching any logic code.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

_MODULE_DIR   = Path(__file__).parent
_PROJECT_ROOT = _MODULE_DIR.parent


# ── Target descriptor ─────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Target:
    host:    str
    port:    int
    service: str   # "ssh" | "web" | "db" | "auth"

    def __str__(self) -> str:
        return f"{self.service}://{self.host}:{self.port}"


# ── Main config ───────────────────────────────────────────────────────────────
@dataclass
class GatewayConfig:

    # ── Listener ────────────────────────────────────────────────────────────
    GATEWAY_HOST: str = "0.0.0.0"
    GATEWAY_PORT: int = 8080          # single port the gateway listens on

    # ── Real backend (only WHITELISTED IPs reach here) ──────────────────────
    REAL_BACKEND: Target = field(
        default_factory=lambda: Target("127.0.0.1", 8000, "web")
    )

    # ── Honeypot targets (all other IPs are silently proxied here) ──────────
    # Gateway round-robins across these so load is spread across emulators.
    HONEYPOT_TARGETS: List[Target] = field(default_factory=lambda: [
        Target("127.0.0.1", 2222, "ssh"),    # Cowrie SSH honeypot
        Target("127.0.0.1", 8081, "web"),    # fake web-app emulator
        Target("127.0.0.1", 8082, "auth"),   # fake auth-portal emulator
        Target("127.0.0.1", 8083, "db"),     # fake database emulator
    ])

    # ── Rate limiting (sliding-window per IP) ────────────────────────────────
    RATE_LIMIT_MAX_CONN:  int = 20     # max new connections within window
    RATE_LIMIT_WINDOW_SEC: int = 60    # window size in seconds
    RATE_LIMIT_BLOCK_SEC:  int = 300   # hard-block duration after rate-offence

    # ── Risk-score thresholds ────────────────────────────────────────────────
    SCORE_SUSPICIOUS:       float = 0.45   # ≥ → SUSPICIOUS
    SCORE_BLACKLIST:        float = 0.70   # ≥ → BLACKLISTED
    SCORE_PROMOTE:          float = 0.25   # < → eligible for promotion
    SCORE_PROBATION_STRIKE: float = 0.55   # ≥ during probation → strike

    # ── Promotion / Probation pipeline ──────────────────────────────────────
    MIN_BLACKLIST_SEC:        int = 600    # minimum time blacklisted before review
    PROBATION_SEC:            int = 3600   # probation duration (1 hour)
    PROBATION_STRIKE_LIMIT:   int = 3      # strikes before re-blacklisting
    REVIEW_INTERVAL_SEC:      int = 60     # how often the promoter loop runs

    # ── Session / proxy ─────────────────────────────────────────────────────
    SESSION_TIMEOUT_SEC:      int   = 300
    PROXY_BUF_SIZE:           int   = 4096
    PROXY_CONNECT_TIMEOUT:    float = 5.0
    MAX_PAYLOAD_LOG_BYTES:    int   = 512  # truncate payload in logs beyond this
    MAX_CONCURRENT_CONNS:     int   = 500

    # ── Persistence ─────────────────────────────────────────────────────────
    DATA_DIR: Path = field(default_factory=lambda: _MODULE_DIR / "data")
    LOG_DIR:  Path = field(default_factory=lambda: _MODULE_DIR / "logs")

    # filenames under DATA_DIR
    BLACKLIST_FILE:   str = "blacklist.json"
    WHITELIST_FILE:   str = "whitelist.json"
    IP_RECORDS_FILE:  str = "ip_records.json"
    SESSION_LOG_FILE: str = "sessions.jsonl"

    # filenames under LOG_DIR
    GATEWAY_LOG_FILE: str = "gateway.log"

    # ── Misc ─────────────────────────────────────────────────────────────────
    DEBUG: bool = bool(os.getenv("GATEWAY_DEBUG", ""))

    def __post_init__(self) -> None:
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.LOG_DIR.mkdir(parents=True, exist_ok=True)


# Module-level singleton — import CONFIG everywhere else
CONFIG = GatewayConfig()
