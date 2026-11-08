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

_TRUE_WORDS  = {"1", "true", "yes", "on"}
_FALSE_WORDS = {"0", "false", "no", "off"}


# ── Environment overrides ─────────────────────────────────────────────────────
# Unset or empty -> the default. A value that is set but wrong raises, so a typo
# in a security setting stops start-up instead of silently using the default.
def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    if raw in _TRUE_WORDS:
        return True
    if raw in _FALSE_WORDS:
        return False
    raise ValueError(f"{name}={raw!r}: expected one of 1/0, true/false, yes/no, on/off")


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name}={raw!r}: expected a whole number") from None
    if not lo <= value <= hi:
        raise ValueError(f"{name}={value}: must be between {lo} and {hi}")
    return value


def _env_float(name: str, default: float, lo: float, hi: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{name}={raw!r}: expected a number") from None
    if not lo <= value <= hi:
        raise ValueError(f"{name}={value}: must be between {lo} and {hi}")
    return value


def _env_path(name: str, default: Path) -> Path:
    raw = os.getenv(name, "").strip()
    return Path(raw) if raw else default


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
    
    #HONEYPOT_TARGETS: List[Target] = field(default_factory=lambda: [
    #    Target("127.0.0.1", 2222, "ssh"),    # Cowrie SSH honeypot
    #    Target("127.0.0.1", 8081, "web"),    # fake web-app emulator
    #    Target("127.0.0.1", 8082, "auth"),   # fake auth-portal emulator
    #    Target("127.0.0.1", 8083, "db"),     # fake database emulator
    #])
    
    HONEYPOT_TARGETS = [
    Target("127.0.0.1", 8081, "web")
    ]

    # ── Rate limiting (sliding-window per IP) ────────────────────────────────
    RATE_LIMIT_MAX_CONN:  int = 20     # max new connections within window
    RATE_LIMIT_WINDOW_SEC: int = 60    # window size in seconds
    RATE_LIMIT_BLOCK_SEC:  int = 300   # hard-block duration after rate-offence

    # WHITELISTED IPs get a higher ceiling, not an exemption: a trusted host can
    # burst far beyond normal traffic without being cut off, but a compromised
    # one still cannot hammer the real backend without limit. A block earned
    # under the strict ceiling is re-evaluated against this one when the IP is
    # promoted, so trusting an IP takes effect on the next connection.
    RATE_LIMIT_TRUSTED_MAX_CONN: int = 100

    # ── Classifier-driven routing ────────────────────────────────────────────
    # OFF by default: the gateway keeps its original zero-trust rule, where
    # everything except a WHITELISTED IP is sent to the honeypot.
    # ON (env GATEWAY_CLASSIFIER_ROUTING=1): traffic_classifier scores each
    # connection and an UNKNOWN ip judged BENIGN reaches the real backend, while
    # SUSPICIOUS/MALICIOUS goes to the honeypot. Explicit BLACKLISTED /
    # WHITELISTED decisions always win over the classifier.
    # This is what the live two-laptop demo runs with.
    CLASSIFIER_ROUTING: bool = bool(os.getenv("GATEWAY_CLASSIFIER_ROUTING", ""))

    # ── MT3-driven response mitigation ───────────────────────────────────────
    # When the MT3 pipeline classifies a captured honeypot session as an actual
    # attack, blacklist the source IP. Recon (phase 0) is exempt; the attacker
    # must reach Initial Access (phase 1) or beyond. This is what auto-blocks a
    # brute-force IP once MT3 has identified it.
    # Env overrides (defaults shown): GATEWAY_MT3_AUTO_BLACKLIST=1,
    # GATEWAY_MT3_AUTO_BLACKLIST_MIN_PHASE=1 (0-8), GATEWAY_MT3_AUTO_BLACKLIST_CONF=0.5.
    MT3_AUTO_BLACKLIST: bool = field(
        default_factory=lambda: _env_bool("GATEWAY_MT3_AUTO_BLACKLIST", True))
    MT3_AUTO_BLACKLIST_MIN_PHASE: int = field(      # >= Initial Access
        default_factory=lambda: _env_int("GATEWAY_MT3_AUTO_BLACKLIST_MIN_PHASE", 1, 0, 8))
    MT3_AUTO_BLACKLIST_CONF: float = field(         # min MT3 confidence
        default_factory=lambda: _env_float("GATEWAY_MT3_AUTO_BLACKLIST_CONF", 0.5, 0.0, 1.0))

    # ── Whose sessions MT3's verdict may ACT on ──────────────────────────────
    # Gated on the SESSION SOURCE (the honeypot that produced it), not on the
    # protocol. The protocol string does not determine the feature shape: a
    # Cowrie telnet session is shell-shaped (commands, bytes, durations) while a
    # Heralding telnet session is credential-shaped (no shell, no byte counts),
    # and MT3 only ever trained on the former.
    #
    # Measured 2026-11-04 (HONEYPOT_AUDIT.md PART 7): on Heralding records MT3
    # agrees with the rule labeller on 0 of 6 scenarios and is CONFIDENTLY
    # wrong -- a bare connect with no auth attempt returns DISC_NETSTAT_SCAN at
    # confidence 1.000, which is phase 3 and so clears MT3_AUTO_BLACKLIST_CONF
    # and would blacklist a user for opening a TCP connection.
    #
    # The verdict is still COMPUTED and LOGGED for every source -- that is the
    # comparison data a retrain needs, and the §7.6 labelling plan depends on it.
    # It may only DRIVE the blacklist and the honeypot reconfiguration for
    # sources listed here. A confidence threshold is not a substitute: the wrong
    # answers are confident.
    #
    # Add a source only after re-running the PART 7 acceptance scenarios against
    # the retrained model and seeing them pass.
    MT3_TRUSTED_SOURCES: frozenset = frozenset({"cowrie_real"})

    # Fail open or closed when a session's source is absent or unrecognised?
    # False = untrusted: verdict logged, but no blacklist and no reconfiguration.
    MT3_TRUST_UNKNOWN_SOURCE: bool = False

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
    # Env overrides GATEWAY_DATA_DIR / GATEWAY_LOG_DIR let a container keep its
    # blacklist and session log on a mounted volume instead of in the code tree.
    DATA_DIR: Path = field(
        default_factory=lambda: _env_path("GATEWAY_DATA_DIR", _MODULE_DIR / "data"))
    LOG_DIR:  Path = field(
        default_factory=lambda: _env_path("GATEWAY_LOG_DIR", _MODULE_DIR / "logs"))

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
