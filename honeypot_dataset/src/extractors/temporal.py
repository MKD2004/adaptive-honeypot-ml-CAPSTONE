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



# -- Temporal provenance: what the session actually supports ------------------
# WHY THIS EXISTS. Until 2026-11-24 this module fabricated a single inter-arrival
# time whenever `event_timestamps` held fewer than two entries:
#
#     iat = np.array([duration / max(n_events - 1, 1)])    # ONE invented value
#
# One value has no spread, no shape and no runs, so `iat_min == iat_mean ==
# iat_median == iat_max` and ten further features collapse to constants. The
# fabricated row is ARITHMETICALLY CONSISTENT, which is exactly why it survived
# three months: every invariant a validator could check passes.
#
# Measured on the 2026-11-24 rebuild: 915,320 of 1,749,809 rows (52.3%) took this
# branch -- every CIC-IDS2017 and UNSW-NB15 row, because a netflow record has no
# event stream. Part 1 fixed the generator; it did nothing for the netflow half,
# which is the majority of the corpus.
#
# A feature that cannot be computed is MISSING, not zero (ERRORS.md 2026-11-11).
# So the extractor declares what the session supports and returns NaN for
# anything it cannot measure. NaN is loud: the validator rejects it and the
# caller has to make an explicit decision.
#
# WHAT THE RAW SOURCES ACTUALLY CARRY, measured 2026-11-24:
#
#   CIC-IDS2017   `Flow IAT Mean/Std/Max/Min` in MICROseconds. 0 non-finite,
#                 2 negatives in 225,745, min<=mean<=max coherent in 100.00%,
#                 and 100% of flows carry >=2 packets so an IAT genuinely exists.
#                 -> mean, std, min, max are REAL MEASUREMENTS. No median, no
#                    skew/kurtosis, no per-gap sequence, so no bursts and no
#                    sub-100ms / over-30s fractions.
#   UNSW-NB15     `sinpkt`/`dinpkt` mean inter-packet time in MILLIseconds
#                 (confirmed: dur/(spkts-1) vs sinpkt ratio is exactly 1000.0),
#                 plus `sjit`/`djit` jitter. 98.5% of flows carry >=2 packets.
#                 -> the MEAN is real. `sjit` is Argus mean-deviation, NOT a
#                    standard deviation, so it is deliberately NOT mapped onto
#                    `iat_std`; doing so would launder a different statistic.
#
# Callers pass what they genuinely have, in SECONDS, under the keys below. The
# extractor stays source-agnostic: the CIC/UNSW unit conversion belongs in
# notebook 01 beside the rest of their column alignment.
PROV_EVENT_STREAM = "event_stream"     # >=2 real timestamps: all 24 computable
PROV_FLOW_STATS   = "flow_stats"       # genuine mean/std/min/max (CIC)
PROV_FLOW_MEAN    = "flow_mean_only"   # genuine mean only (UNSW)
PROV_NONE         = "none"             # nothing measurable

# Features needing an actual sequence of gaps. No flow summary supplies them, so
# they are NaN for anything short of PROV_EVENT_STREAM.
SEQUENCE_ONLY_FEATURES = frozenset({
    "iat_median", "iat_skew", "iat_kurt",
    "frac_sub100ms", "frac_sub1s", "frac_over30s",
    "burst_count", "burst_mean_size",
    "inter_burst_gap_mean", "inter_burst_gap_std",
})

# Features a flow-level summary CAN supply.
FLOW_STAT_FEATURES = frozenset({"iat_mean", "iat_std", "iat_min", "iat_max",
                                "iat_cv"})


def _present(v) -> bool:
    """True when `v` is a real number, not absent.

    A record that came through pandas reports a MISSING value as float NaN, not
    as None -- so `v is not None` is True for an absent column and the session
    would be mis-declared as carrying flow statistics it does not have. Getting
    this wrong is worse than the bug this module exists to fix, because it would
    label fabricated absence as genuine measurement.
    """
    if v is None:
        return False
    try:
        return not math.isnan(float(v))
    except (TypeError, ValueError):
        return False


def _n_timestamps(v) -> int:
    """Length of an event-timestamp list, 0 for anything that is not a sequence.

    Same reason as `_present`: pandas hands back float NaN for a missing list
    column, and `len(nan)` raises.
    """
    if v is None:
        return 0
    try:
        return len(v)
    except TypeError:
        return 0


def temporal_provenance(session: dict) -> str:
    """What temporal evidence this session carries. Never guesses."""
    if _n_timestamps(session.get("event_timestamps")) >= 2:
        return PROV_EVENT_STREAM
    have = [k for k in ("iat_mean_s", "iat_std_s", "iat_min_s", "iat_max_s")
            if _present(session.get(k))]
    if len(have) == 4:
        return PROV_FLOW_STATS
    if "iat_mean_s" in have:
        return PROV_FLOW_MEAN
    return PROV_NONE


def unavailable_features(provenance: str) -> frozenset:
    """Temporal feature names that MUST be NaN at this provenance level."""
    if provenance == PROV_EVENT_STREAM:
        return frozenset()
    if provenance == PROV_FLOW_STATS:
        return SEQUENCE_ONLY_FEATURES
    if provenance == PROV_FLOW_MEAN:
        return SEQUENCE_ONLY_FEATURES | (FLOW_STAT_FEATURES - {"iat_mean"})
    return SEQUENCE_ONLY_FEATURES | FLOW_STAT_FEATURES


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

    # Inter-arrival times. NO FABRICATION -- see the provenance block above.
    _nan = float("nan")
    prov = temporal_provenance(session)
    if prov == PROV_EVENT_STREAM:
        ts  = np.array(sorted(session["event_timestamps"]), dtype=np.float64)
        iat = np.diff(ts)
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
    else:
        # A flow summary carries statistics but no sequence, so the shape and run
        # features are UNMEASURABLE rather than zero.
        iat = np.array([], dtype=np.float64)
        _m = session.get("iat_mean_s")
        iat_mean = float(_m) if _present(_m) else _nan
        if prov == PROV_FLOW_STATS:
            iat_std = float(session.get("iat_std_s"))
            iat_min = float(session.get("iat_min_s"))
            iat_max = float(session.get("iat_max_s"))
            iat_cv  = iat_std / (iat_mean + eps)
        else:
            iat_std = iat_min = iat_max = iat_cv = _nan
        iat_median = iat_skew = iat_kurt = _nan
        frac_sub100ms = frac_sub1s = frac_over30s = _nan

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

    if prov == PROV_EVENT_STREAM:
        burst_count     = float(len(burst_sizes))
        burst_mean_size = float(np.mean(burst_sizes)) if burst_sizes else 0.0
        inter_burst_iats = iat[iat >= 0.1]
        # A session with no slow gap has no INTER-burst gap. That is a measured
        # absence, so it stays 0.0 rather than becoming NaN.
        ibg_mean = float(inter_burst_iats.mean()) if len(inter_burst_iats) else 0.0
        ibg_std  = float(inter_burst_iats.std())  if len(inter_burst_iats) else 0.0
    else:
        burst_count = burst_mean_size = ibg_mean = ibg_std = _nan

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

    # NaN SURVIVES. Replacing it with 0.0 is what hid the fabricated IAT for
    # three months: a zero is indistinguishable from a measured zero. Infinities
    # are still clamped -- those come from division, not from missing input.
    feat = np.where(np.isposinf(feat), np.float32(1e6), feat)
    feat = np.where(np.isneginf(feat), np.float32(0.0), feat)
    return feat.astype(np.float32)
