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

AVERAGE **AND** RECENT WORST CASE (fix #3, 2026-11-04)

HONEYPOT_AUDIT.md PART 3 fix #3: every signal here used to be an average over the
last 20 sessions, so one serious session was worth 5% of the score and was
diluted away by history. That made this the weakest part of the whitelist
backstop -- and worse, it meant **the longer an attacker behaved, the safer they
got**, because a longer clean history buried the one session that mattered.

So each signal is now the WORSE of two readings:

  * the average over the last AVG_WINDOW sessions -- unchanged, and still what
    detects sustained bad behaviour;
  * the worst single session in the last WORST_WINDOW -- new, and what stops one
    serious session being averaged into irrelevance.

Why the worst case uses a SHORT window, which is the part that is easy to get
wrong: taken over the whole 50-session history it would be permanently sticky,
and `whitelist_promoter` demotes a blacklisted IP only when the score falls below
CONFIG.SCORE_PROMOTE. One old spike would pin the score forever and nothing could
ever be rehabilitated. With a short window a spike dominates for a few sessions
and then ages out, which keeps the promotion pipeline working.

The worst case is computed by running each signal function over EVERY session in
the window and taking the highest result, rather than by feeding it a min or a max
input. That matters because the signals do not agree on direction -- high entropy
is suspicious but LOW byte counts and SHORT durations are (scanner behaviour) --
so picking the extreme input per signal is easy to get backwards. Taking the max
of the outputs is direction-agnostic and cannot be got backwards.

Two signals are deliberately left alone:

  * honeypot ratio already is a ratio, so its "recent worst" is the same ratio
    over the short window. A per-session max would be 1.0 for any IP that ever
    touched the honeypot, which is every blacklisted IP, and would pin the score.
  * connection frequency is a property of the window, not of one session.
"""
from __future__ import annotations

import math
from typing import List, Tuple

from .config import CONFIG
from .session_tracker import Session, session_tracker
from . import gateway_logger as glog
from .gateway_logger import GatewayEvent


# How many recent sessions each half of the score looks at. See the module
# docstring for why the worst-case window is much shorter than the average one.
AVG_WINDOW = 20
WORST_WINDOW = 5


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
def worst_recent_signals(sessions: List[Session]) -> dict:
    """Highest (worst) value each per-session signal reaches in `sessions`.

    Runs the signal functions over every session and takes the max of the
    OUTPUTS, so a signal whose risky direction is "low" (small payloads, short
    durations -- both scanner-like) is handled without encoding min-or-max per
    signal. Empty input gives 0.0 for everything, which cannot raise the score.
    """
    if not sessions:
        return {"entropy": 0.0, "volume": 0.0, "duration": 0.0}
    return {
        "entropy": max(_entropy_signal(s.entropy) for s in sessions),
        "volume": max(_volume_signal(s.bytes_in) for s in sessions),
        "duration": max(_duration_signal(s.duration_sec) for s in sessions),
    }


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

    stats = session_tracker.recent_stats(ip, n=AVG_WINDOW)
    recent = history[-WORST_WINDOW:]
    worst = worst_recent_signals(recent)

    # --- individual signals: the worse of the average and the recent worst ---
    # max(), not an average of the two: the point of fix #3 is that one serious
    # session must be able to move the score on its own. Averaging the average
    # with the worst case would just dilute it again, more slowly.
    sig_entropy  = max(_entropy_signal(stats.get("avg_entropy", 4.0)),
                       worst["entropy"])
    sig_volume   = max(_volume_signal(stats.get("avg_bytes_in", 500)),
                       worst["volume"])
    sig_duration = max(_duration_signal(stats.get("avg_duration", 5.0)),
                       worst["duration"])

    # A ratio already, so its recent reading is the same ratio over the short
    # window -- see the module docstring for why this is not a per-session max.
    recent_honeypot_ratio = (
        sum(1 for s in recent if s.target == "honeypot") / len(recent)
        if recent else 0.0
    )
    sig_honeypot = max(_honeypot_ratio_signal(stats.get("honeypot_ratio", 0.0)),
                       _honeypot_ratio_signal(recent_honeypot_ratio))

    # A property of the window rather than of one session, so it has no worst case.
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

    # Name the signals the recent worst case raised above the average, so an
    # operator reading the audit log can tell a sustained offender from one bad
    # session in an otherwise clean history. Those are very different situations
    # and the score alone cannot distinguish them.
    spiked = [
        name for name, avg_value, worst_value in (
            ("entropy", _entropy_signal(stats.get("avg_entropy", 4.0)), worst["entropy"]),
            ("volume", _volume_signal(stats.get("avg_bytes_in", 500)), worst["volume"]),
            ("duration", _duration_signal(stats.get("avg_duration", 5.0)), worst["duration"]),
        ) if worst_value > avg_value
    ]
    reasoning = (
        f"entropy={sig_entropy:.2f} volume={sig_volume:.2f} "
        f"honeypot={sig_honeypot:.2f} duration={sig_duration:.2f} "
        f"freq={sig_freq:.2f} -> weighted={score:.3f} "
        f"(avg over {stats.get('sample_size', 0)} sessions, worst of last "
        f"{len(recent)})"
        + (f" [recent worst case raised: {', '.join(spiked)}]" if spiked else "")
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
