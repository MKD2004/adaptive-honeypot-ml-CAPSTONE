"""
traffic_gateway/traffic_classifier.py

Pre-MT3 traffic filter: scores an inbound connection from IP reputation, live
connection behaviour and payload statistics BEFORE the honeypot engages, and
returns a MALICIOUS / SUSPICIOUS / BENIGN verdict with the routing action.
This runs per-connection and cheap; MT3 runs once per completed session.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Optional, Tuple

from .blacklist_manager import blacklist_manager
from .rate_limiter import rate_limiter
from .ext_paths import ensure_paths

ensure_paths()
# Both names are underscore-private in the extractor but are the project's
# single source of truth for geo risk and tool fingerprints -- imported rather
# than duplicated so the gateway can never drift from the feature schema.
from src.extractors.tls_host import _GEO_RISK, _KNOWN_MALICIOUS_JA3  # type: ignore
from src.extractors.payload import extract_payload  # type: ignore

# -- Payload feature indices (src/extractors/payload.py PAYLOAD_FEATURE_NAMES) --
IDX_ENTROPY_SHANNON = 0
IDX_BASE64_LIKELIHOOD = 10
IDX_PIPE_OPERATOR_COUNT = 22

# -- Decision thresholds ------------------------------------------------------
THRESHOLD_MALICIOUS = 0.5      # >= -> MALICIOUS / ENGAGE (full honeypot)
THRESHOLD_SUSPICIOUS = 0.2     # >= -> SUSPICIOUS / DECOY (low-interaction)
                               # <  -> BENIGN / LOG_ONLY

# -- Signal weights -----------------------------------------------------------
# Signal 1 gives the base reputation score; signals 2 and 3 add to it. Geo risk
# is *weighted down* rather than used raw: _GEO_RISK returns 0.35 for every
# unknown country, and using that raw would put a floor of 0.35 on every
# connection, so nothing could ever be classified BENIGN.
W_GEO = 0.40                   # geo_risk 0.0-0.95 -> contributes 0.00-0.38
W_JA3_MALICIOUS = 0.40         # known attack-tool JA3 fingerprint
W_RATE_LIMITED = 0.30          # currently hard-blocked by the rate limiter

W_CONN_RATE_HIGH = 0.30        # > 10 connections/min
W_CONN_RATE_EXTREME = 0.60     # > 30 connections/min
W_PORT_SCAN = 0.20             # > 3 unique ports in 5 minutes
W_FAILED_AUTH = 0.30           # > 5 failed auth attempts this session

W_ENTROPY = 0.20               # entropy_shannon > 6.5
W_BASE64 = 0.20                # base64_likelihood > 0.7
W_PIPES = 0.10                 # pipe_operator_count > 3

# -- Behaviour-signal trip points ---------------------------------------------
CONN_RATE_HIGH = 10
CONN_RATE_EXTREME = 30
CONN_RATE_WINDOW_SEC = 60
PORT_SCAN_MIN_PORTS = 3
PORT_SCAN_WINDOW_SEC = 300
FAILED_AUTH_LIMIT = 5

ENTROPY_TRIP = 6.5
BASE64_TRIP = 0.7
PIPE_TRIP = 3

VERDICT_ACTION = {
    "MALICIOUS": "ENGAGE",
    "SUSPICIOUS": "DECOY",
    "BENIGN": "LOG_ONLY",
}


@dataclass
class _IPActivity:
    """Rolling per-IP observation window (independent of the rate limiter's)."""
    conn_times: Deque[float]
    port_hits: Deque[Tuple[float, int]]


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


def _payload_fields(info: Dict[str, Any]) -> Tuple[str, str]:
    """Normalise the several shapes a caller may supply a payload in."""
    cmd = str(info.get("command_text", "") or "")
    phex = str(info.get("payload_hex", "") or "")
    raw = info.get("payload")
    if raw and not phex:
        if isinstance(raw, (bytes, bytearray)):
            phex = bytes(raw).hex()
        else:
            phex = str(raw).encode("utf-8", "replace").hex()
    return cmd, phex


class TrafficClassifier:
    """Scores a connection on three signal families and returns a verdict.

    Composition:
        score = signal1_reputation + signal2_behaviour + signal3_payload
    clamped to [0, 1], except that a blacklist hit short-circuits to 1.0 and a
    whitelist hit short-circuits to 0.0 -- both are explicit operator decisions
    and must not be diluted by heuristics.
    """

    def __init__(self, *, track_history: bool = True) -> None:
        self._track = track_history
        self._activity: Dict[str, _IPActivity] = defaultdict(
            lambda: _IPActivity(conn_times=deque(maxlen=512),
                                port_hits=deque(maxlen=512))
        )
        self._verdict_counts: Dict[str, int] = defaultdict(int)

    # -- observation bookkeeping ---------------------------------------------
    def record_connection(self, ip: str, dst_port: Optional[int] = None,
                          now: Optional[float] = None) -> None:
        """Register one connection from `ip` so behaviour signals can see it."""
        now = time.time() if now is None else now
        act = self._activity[ip]
        act.conn_times.append(now)
        if dst_port is not None:
            try:
                act.port_hits.append((now, int(dst_port)))
            except (TypeError, ValueError):
                pass

    def connections_per_minute(self, ip: str, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        cutoff = now - CONN_RATE_WINDOW_SEC
        own = sum(1 for t in self._activity[ip].conn_times if t >= cutoff)
        # The gateway's own sliding window is authoritative when it has seen more.
        return max(own, rate_limiter.current_count(ip))

    def unique_ports(self, ip: str, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        cutoff = now - PORT_SCAN_WINDOW_SEC
        return len({p for t, p in self._activity[ip].port_hits if t >= cutoff})

    # -- signal 1: IP reputation ---------------------------------------------
    def _signal_reputation(self, info: Dict[str, Any], signals: List[str],
                           detail: Dict[str, Any]) -> Optional[float]:
        """Returns a hard 0.0/1.0 verdict score, or None to score additively."""
        ip = str(info.get("src_ip", "") or "")

        if ip and blacklist_manager.is_blacklisted(ip):
            signals.append("blacklist")
            detail["blacklist"] = 1.0
            return 1.0
        if ip and blacklist_manager.is_whitelisted(ip):
            signals.append("whitelist")
            detail["whitelist"] = 0.0
            return 0.0

        score = 0.0
        country = str(info.get("src_country", "") or "").upper()
        geo_risk = _GEO_RISK.get(country, 0.35)
        score += W_GEO * geo_risk
        detail["geo_country"] = country or "??"
        detail["geo_risk"] = round(W_GEO * geo_risk, 4)
        if geo_risk >= 0.5:
            signals.append("geo_risk")

        ja3 = str(info.get("ja3_hash", "") or "")
        if ja3 and ja3 in _KNOWN_MALICIOUS_JA3:
            score += W_JA3_MALICIOUS
            signals.append("ja3_known_malicious")
            detail["ja3_known_malicious"] = W_JA3_MALICIOUS

        if ip and rate_limiter.is_blocked(ip):
            score += W_RATE_LIMITED
            signals.append("rate_limit")
            detail["rate_limit"] = W_RATE_LIMITED

        detail["_signal1"] = score
        return None

    # -- signal 2: connection behaviour --------------------------------------
    def _signal_behaviour(self, info: Dict[str, Any], signals: List[str],
                          detail: Dict[str, Any]) -> float:
        ip = str(info.get("src_ip", "") or "")
        score = 0.0

        cpm = self.connections_per_minute(ip)
        detail["connections_per_min"] = cpm
        if cpm > CONN_RATE_EXTREME:
            score += W_CONN_RATE_EXTREME
            signals.append("conn_rate_extreme")
            detail["conn_rate"] = W_CONN_RATE_EXTREME
        elif cpm > CONN_RATE_HIGH:
            score += W_CONN_RATE_HIGH
            signals.append("conn_rate_high")
            detail["conn_rate"] = W_CONN_RATE_HIGH

        ports = self.unique_ports(ip)
        detail["unique_ports_5min"] = ports
        if ports > PORT_SCAN_MIN_PORTS:
            score += W_PORT_SCAN
            signals.append("port_scan")
            detail["port_scan"] = W_PORT_SCAN

        failed = int(info.get("failed_auth_attempts", 0) or 0)
        detail["failed_auth_attempts"] = failed
        if failed > FAILED_AUTH_LIMIT:
            score += W_FAILED_AUTH
            signals.append("failed_auth")
            detail["failed_auth"] = W_FAILED_AUTH

        detail["_signal2"] = score
        return score

    # -- signal 3: payload statistics ----------------------------------------
    def _signal_payload(self, info: Dict[str, Any], signals: List[str],
                        detail: Dict[str, Any]) -> float:
        """Reuses the Group C extractor so the gateway and the 128-feature
        training schema compute entropy the exact same way."""
        cmd, phex = _payload_fields(info)
        if not cmd and not phex:
            detail["_signal3"] = 0.0
            return 0.0

        feats = extract_payload({"command_text": cmd, "payload_hex": phex})
        entropy = float(feats[IDX_ENTROPY_SHANNON])
        b64 = float(feats[IDX_BASE64_LIKELIHOOD])
        pipes = float(feats[IDX_PIPE_OPERATOR_COUNT])
        detail["entropy_shannon"] = round(entropy, 4)
        detail["base64_likelihood"] = round(b64, 4)
        detail["pipe_operator_count"] = pipes

        score = 0.0
        if entropy > ENTROPY_TRIP:
            score += W_ENTROPY
            signals.append("entropy")
        if b64 > BASE64_TRIP:
            score += W_BASE64
            signals.append("base64")
        if pipes > PIPE_TRIP:
            score += W_PIPES
            signals.append("pipe_operators")

        detail["_signal3"] = score
        return score

    # -- public API -----------------------------------------------------------
    def classify(self, connection_info: Dict[str, Any], *,
                 record: bool = True) -> Dict[str, Any]:
        """Score one connection.

        connection_info keys (all optional except src_ip):
            src_ip (str), dst_port (int), src_country (str, ISO-2),
            ja3_hash (str), failed_auth_attempts (int),
            payload (bytes) | payload_hex (str) | command_text (str)

        Returns {"verdict", "score", "signals_fired", "action", "details"}.
        """
        ip = str(connection_info.get("src_ip", "") or "")
        if record and self._track:
            self.record_connection(ip, connection_info.get("dst_port"))

        signals: List[str] = []
        detail: Dict[str, Any] = {}

        hard = self._signal_reputation(connection_info, signals, detail)
        if hard is not None:
            score = hard
        else:
            score = _clamp(
                float(detail.get("_signal1", 0.0))
                + self._signal_behaviour(connection_info, signals, detail)
                + self._signal_payload(connection_info, signals, detail)
            )

        if score >= THRESHOLD_MALICIOUS:
            verdict = "MALICIOUS"
        elif score >= THRESHOLD_SUSPICIOUS:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN"

        self._verdict_counts[verdict] += 1
        return {
            "verdict": verdict,
            "score": round(score, 4),
            "signals_fired": signals,
            "action": VERDICT_ACTION[verdict],
            "details": {k: v for k, v in detail.items() if not k.startswith("_")},
        }

    def stats(self) -> Dict[str, Any]:
        return {
            "tracked_ips": len(self._activity),
            "verdicts": dict(self._verdict_counts),
            "thresholds": {
                "malicious": THRESHOLD_MALICIOUS,
                "suspicious": THRESHOLD_SUSPICIOUS,
            },
        }


# Module-level singleton, matching the rest of traffic_gateway.
traffic_classifier = TrafficClassifier()
