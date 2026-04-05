"""
traffic_gateway/reputation_scorer.py

Behavioural reputation scorer.

Until the CNN-LSTM model is trained and integrated (Phase 3), this module
provides a heuristic risk score in [0.0, 1.0] derived from observable
session attributes.  The scoring logic is designed so it can be swapped out
for a real model call without changing any other file.

Score interpretation:
  0.00 – 0.44  →  Low risk   (below CONFIG.SCORE_SUSPICIOUS)
  0.45 – 0.69  →  Suspicious  (CONFIG.SCORE_SUSPICIOUS ≤ score < CONFIG.SCORE_BLACKLIST)
  0.70 – 1.00  →  High risk   (≥ CONFIG.SCORE_BLACKLIST → blacklist)
"""
from __future__ import annotations

import math
from typing import List, Tuple

from .config import CONFIG
from .session_tracker import Session, session_tracker
from . import gateway_logger as glog
from .gateway_logger import GatewayEvent


# ── Heuristic helpers ─────────────────────────────────────────────────────────
def _clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


def _entropy_signal(avg_entropy: float) -> float:
    """
    Very high entropy payload (≈ encrypted / obfuscated attack tool) scores high.
    Natural human traffic sits around 3–5 bits; tool payloads often hit 6–7.
    """
    if avg_entropy < 3.5:
        return 0.1
    if avg_entropy < 5.0:
        return 0.3
    if avg_entropy < 6.5:
        return 0.55
    return 0.85


def _volume_signal(avg_bytes_in: float) -> float:
    """
    Brute-force / spray attacks flood the honeypot with small identical packets.
    High volumes of tiny payloads are suspicious.
    """
    if avg_bytes_in < 10:      # tiny packets → likely scanner
        return 0.75
    if avg_bytes_in < 100:
        return 0.45
    if avg_bytes_in < 2048:
        return 0.15
    return 0.10                # large payloads → more likely real user traffic


def _honeypot_ratio_signal(ratio: float) -> float:
    """Every session of this IP went to the honeypot → all are suspicious."""
    if ratio >= 1.0:
        return 0.6
    if ratio >= 0.75:
        return 0.4
    return 0.2 * ratio


def _duration_signal(avg_duration: float) -> float:
    """
    Automated scanners tend to have very short sessions.
    Very long sessions could be a human attacker manually exploring.
    """
    if avg_duration < 0.5:     # sub-second → automated scanner
        return 0.7
    if avg_duration < 3.0:
        return 0.4
    if avg_duration < 30.0:
        return 0.2
    return 0.3                 # very long → manual attacker (still a signal)


def _connection_frequency_signal(total_connections: int, history_window: int) -> float:
    """Normalise total connections against the history window size."""
    if history_window == 0:
        return 0.5
    ratio = min(total_connections / max(history_window, 1), 5.0) / 5.0
    return _clamp(ratio * 0.8)


# ── Public API ────────────────────────────────────────────────────────────────
def score_ip(ip: str) -> Tuple[float, str]:
    """
    Compute a heuristic risk score for an IP using its recent session history.

    Returns:
        (score: float, reasoning: str)

    Replace the body of this function with your CNN-LSTM inference call once
    the model is trained.  The signature and return type must stay the same so
    callers don't need to change.
    """
    history = session_tracker.get_history(ip)
    if not history:
        return 0.5, "No session history; defaulting to neutral score."

    stats = session_tracker.recent_stats(ip, n=20)

    # --- individual signals ---
    sig_entropy  = _entropy_signal(stats.get("avg_entropy", 4.0))
    sig_volume   = _volume_signal(stats.get("avg_bytes_in", 500))
    sig_honeypot = _honeypot_ratio_signal(stats.get("honeypot_ratio", 0.0))
    sig_duration = _duration_signal(stats.get("avg_duration", 5.0))
    sig_freq     = _connection_frequency_signal(
                       len(history), stats.get("sample_size", 1)
                   )

    # --- weighted combination ---
    # Weights chosen so entropy + frequency dominate (most reliable signals)
    score = _clamp(
        0.30 * sig_entropy +
        0.20 * sig_volume  +
        0.20 * sig_honeypot +
        0.15 * sig_duration +
        0.15 * sig_freq
    )

    reasoning = (
        f"entropy={sig_entropy:.2f} volume={sig_volume:.2f} "
        f"honeypot={sig_honeypot:.2f} duration={sig_duration:.2f} "
        f"freq={sig_freq:.2f} -> weighted={score:.3f} "
        f"(sample={stats.get('sample_size', 0)} sessions)"
    )

    glog.log_event(
        GatewayEvent.ML_ASSESSMENT, ip,
        extra={"score": round(score, 4), "reasoning": reasoning},
    )

    return score, reasoning


async def ml_risk_assessment(ip: str) -> Tuple[float, str]:
    """
    Async wrapper — will call the real CNN-LSTM model endpoint in Phase 3.

    Current implementation delegates to the synchronous heuristic scorer.
    When the model is ready, replace this body with an aiohttp call to the
    inference server (or a direct torch/tf invocation).
    """
    # ── STUB ─────────────────────────────────────────────────────────────
    # TODO (Phase 3): call CNN-LSTM model here.
    # Example:
    #   features = await extract_feature_vector(ip)
    #   score = await model_client.predict(features)
    #   return score, "CNN-LSTM inference"
    # ─────────────────────────────────────────────────────────────────────
    return score_ip(ip)
