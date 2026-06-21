"""
src/extractors/temporal.py
Group A — 24 Temporal Features (fed to LSTM branch)
Captures attack rhythm: automated scanners have inhuman regularity;
humans show natural variance and idle pauses.
"""
from __future__ import annotations
import math
import json
import numpy as np
from typing import List

# ── Feature index map ─────────────────────────────────────────────────────────
# f_000..f_023
TEMPORAL_FEATURE_NAMES = [
    "iat_mean","iat_std","iat_min","iat_max","iat_median",           # 0-4
    "iat_cv","iat_skew","iat_kurt",                                   # 5-7
    "frac_sub100ms","frac_sub1s","frac_over30s",                     # 8-10
    "session_duration_s","log_session_duration","events_per_sec",    # 11-13
    "commands_per_min","burst_count","burst_mean_size",              # 14-16
    "inter_burst_gap_mean","inter_burst_gap_std",                    # 17-18
    "time_to_first_auth_s","time_to_first_cmd_s",                   # 19-20
    "session_day_of_week","session_hour","is_business_hours",        # 21-23
]
assert len(TEMPORAL_FEATURE_NAMES) == 24


def _skew(arr: np.ndarray) -> float:
    if len(arr) < 3: return 0.0
    mu = arr.mean(); s = arr.std()
    if s < 1e-9: return 0.0
    return float(np.mean(((arr - mu) / s) ** 3))


def _kurt(arr: np.ndarray) -> float:
    if len(arr) < 4: return 0.0
    mu = arr.mean(); s = arr.std()
    if s < 1e-9: return 0.0
    return float(np.mean(((arr - mu) / s) ** 4) - 3.0)


def extract_temporal(session: dict) -> np.ndarray:
    """
    Extract 24 temporal features from a session dict.

    Expected keys:
        t_start  (float)  : Unix epoch of first event
        t_end    (float)  : Unix epoch of last event
        n_events (int)
        n_commands (int)
        t_first_auth (float) : epoch of first login attempt (optional)
        t_first_cmd  (float) : epoch of first shell command (optional)
        event_timestamps (List[float]) : per-event timestamps (optional)
    """
    eps = 1e-9
    t_start  = float(session.get("t_start",  0.0) or 0.0)
    t_end    = float(session.get("t_end",    0.0) or 0.0)
    duration = max(eps, t_end - t_start)
    n_events  = int(session.get("n_events",    1) or 1)
    n_cmds    = int(session.get("n_commands",  0) or 0)

    # Inter-arrival times
    ts_list: List[float] = session.get("event_timestamps", [])
    if len(ts_list) >= 2:
        ts  = np.array(sorted(ts_list), dtype=np.float64)
        iat = np.diff(ts)
    else:
        iat = np.array([duration / max(n_events - 1, 1)])

    iat_mean   = float(iat.mean())
    iat_std    = float(iat.std())
    iat_min    = float(iat.min())
    iat_max    = float(iat.max())
    iat_median = float(np.median(iat))
    iat_cv     = iat_std / (iat_mean + eps)
    iat_skew   = _skew(iat)
    iat_kurt   = _kurt(iat)

    frac_sub100ms = float((iat < 0.1).mean())
    frac_sub1s    = float((iat < 1.0).mean())
    frac_over30s  = float((iat > 30.0).mean())

    log_dur      = math.log1p(duration)
    events_ps    = n_events / duration
    cmds_per_min = n_cmds / (duration / 60.0 + eps)

    # Burst detection (runs of IAT < 100ms)
    burst_sizes, cur = [], 0
    for v in iat:
        if v < 0.1: cur += 1
        else:
            if cur > 0: burst_sizes.append(cur); cur = 0
    if cur > 0: burst_sizes.append(cur)

    burst_count      = float(len(burst_sizes))
    burst_mean_size  = float(np.mean(burst_sizes)) if burst_sizes else 0.0
    inter_burst_iats = iat[iat >= 0.1]
    ibg_mean = float(inter_burst_iats.mean()) if len(inter_burst_iats) else 0.0
    ibg_std  = float(inter_burst_iats.std())  if len(inter_burst_iats) else 0.0

    # Time-to-first events
    t_auth = float(session.get("t_first_auth", t_start) or t_start)
    t_cmd  = float(session.get("t_first_cmd",  t_start) or t_start)
    ttfa   = max(0.0, t_auth - t_start)
    ttfc   = max(0.0, t_cmd  - t_start)

    # Calendar context (bots don't sleep; humans do)
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(t_start, tz=timezone.utc)
    dow           = float(dt.weekday())      # 0=Mon
    hour          = float(dt.hour)
    is_biz_hours  = float(9 <= dt.hour <= 17 and dt.weekday() < 5)

    feat = np.array([
        iat_mean, iat_std, iat_min, iat_max, iat_median,
        iat_cv, iat_skew, iat_kurt,
        frac_sub100ms, frac_sub1s, frac_over30s,
        duration, log_dur, events_ps,
        cmds_per_min, burst_count, burst_mean_size,
        ibg_mean, ibg_std,
        ttfa, ttfc,
        dow, hour, is_biz_hours,
    ], dtype=np.float32)

    return np.nan_to_num(feat, nan=0.0, posinf=1e6, neginf=0.0)
