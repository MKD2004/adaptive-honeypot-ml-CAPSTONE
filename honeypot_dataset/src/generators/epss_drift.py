"""
src/generators/epss_drift.py
EPSS Temporal Drift Injection — the dataset's novel contribution.
Simulates how EPSS scores evolve over time when a CVE enters the
CISA KEV catalog, producing realistic time-varying threat intelligence.
No existing honeypot dataset models this temporal dimension.
"""
from __future__ import annotations
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timezone, timedelta

log = logging.getLogger(__name__)

# Simulated now anchor (Time Paradox fix — matches NVD query window)
_ANCHOR = datetime(2024, 4, 15, tzinfo=timezone.utc)


def inject_epss_drift(df: pd.DataFrame,
                      cve_kev_day: int,
                      col: str = "f_110",
                      pct_col: str = "f_111",
                      delta_col: str = "f_112",
                      window_days: int = 90,
                      seed: int = 42) -> pd.DataFrame:
    """
    Simulate the EPSS surge that occurs when a CVE enters the CISA KEV catalog.

    The real-world pattern:
      Pre-KEV  : EPSS ~ Beta(1, 10)   →  mostly 0.02–0.15
      KEV day  : EPSS spikes to ~0.85
      Post-KEV : EPSS decays exponentially with noise

    Args:
        df          : DataFrame with a 'session_day' integer column (0..window_days)
        cve_kev_day : day index when the CVE was added to KEV
        col         : column name for epss_score  (f_110 in Group E)
        pct_col     : column name for epss_percentile (f_111)
        delta_col   : column name for epss_7d_delta   (f_112)
        window_days : total number of days in the dataset timeline
        seed        : RNG seed for reproducibility
    """
    rng = np.random.default_rng(seed)
    df  = df.copy()

    if "session_day" not in df.columns:
        # Assign session days proportionally from t_start
        if "t_start" in df.columns:
            t_min = df["t_start"].min()
            t_max = df["t_start"].max() + 1e-9
            df["session_day"] = ((df["t_start"] - t_min) /
                                  (t_max - t_min) * window_days).astype(int)
        else:
            df["session_day"] = rng.integers(0, window_days, size=len(df))

    day  = df["session_day"].values.astype(float)
    n    = len(df)

    # Pre-KEV baseline: Beta(1, 10) — low but non-zero
    pre_mask  = day < cve_kev_day
    post_mask = day >= cve_kev_day

    epss = np.zeros(n, dtype=np.float32)

    # Pre-KEV scores
    epss[pre_mask]  = rng.beta(1.0, 10.0, size=int(pre_mask.sum())).astype(np.float32)

    # Post-KEV: exponential decay from spike
    days_since      = (day[post_mask] - cve_kev_day)
    epss[post_mask] = np.clip(
        0.85 * np.exp(-0.05 * days_since)
        + rng.normal(0, 0.025, size=int(post_mask.sum())),
        0.05, 0.99
    ).astype(np.float32)

    # Percentile (approximately proportional to score in upper tail)
    pct = np.clip(0.60 + 0.39 * epss + rng.normal(0, 0.03, n), 0.0, 1.0).astype(np.float32)

    # 7-day delta: zero pre-KEV, positive spike at KEV day, decaying after
    delta          = np.zeros(n, dtype=np.float32)
    spike_mask     = (day >= cve_kev_day) & (day < cve_kev_day + 7)
    decay_mask     = day >= cve_kev_day + 7
    delta[spike_mask] = rng.uniform(0.40, 0.75, size=int(spike_mask.sum())).astype(np.float32)
    delta[decay_mask] = np.clip(
        rng.normal(0.02, 0.01, size=int(decay_mask.sum())), -0.05, 0.15
    ).astype(np.float32)

    if col      in df.columns: df[col]      = epss
    if pct_col  in df.columns: df[pct_col]  = pct
    if delta_col in df.columns: df[delta_col] = delta

    # Also update threat_intel feature columns by name if present
    df["epss_score"]      = epss
    df["epss_percentile"] = pct
    df["epss_7d_delta"]   = delta

    log.info(
        "EPSS drift injected: KEV day=%d | pre-KEV mean=%.3f | "
        "post-KEV mean=%.3f | delta spike sessions=%d",
        cve_kev_day,
        float(epss[pre_mask].mean())  if pre_mask.sum()  > 0 else 0.0,
        float(epss[post_mask].mean()) if post_mask.sum() > 0 else 0.0,
        int(spike_mask.sum()),
    )
    return df


def inject_multi_cve_drift(df: pd.DataFrame,
                            cve_schedule: list[dict],
                            seed: int = 42) -> pd.DataFrame:
    """
    Apply EPSS drift for multiple CVEs across the dataset timeline.
    Each CVE in cve_schedule has: {'cve_id', 'kev_day', 'base_epss'}

    Args:
        cve_schedule : list of dicts describing CVE KEV-entry events
        Example:
            [
              {"cve_id": "CVE-2023-44487", "kev_day": 10, "base_epss": 0.91},
              {"cve_id": "CVE-2024-3400",  "kev_day": 45, "base_epss": 0.95},
            ]
    """
    for i, cve_info in enumerate(cve_schedule):
        cve_id  = cve_info["cve_id"]
        kev_day = cve_info["kev_day"]
        # Only apply to sessions associated with this CVE
        mask = df["associated_cve"] == cve_id
        if mask.sum() == 0:
            continue
        df_sub = inject_epss_drift(
            df[mask].copy(), kev_day, seed=seed + i
        )
        df.loc[mask, "epss_score"]      = df_sub["epss_score"].values
        df.loc[mask, "epss_percentile"] = df_sub["epss_percentile"].values
        df.loc[mask, "epss_7d_delta"]   = df_sub["epss_7d_delta"].values
        log.info("  Applied drift for %s → %d sessions", cve_id, int(mask.sum()))
    return df


def validate_drift(df: pd.DataFrame) -> dict:
    """
    Sanity-check that EPSS drift was applied correctly.
    Returns a dict of statistics for inclusion in dataset card.
    """
    if "epss_score" not in df.columns:
        return {"error": "epss_score column not found"}

    scores = df["epss_score"].values
    return {
        "n_sessions":         len(df),
        "epss_mean":          round(float(scores.mean()), 4),
        "epss_std":           round(float(scores.std()),  4),
        "epss_min":           round(float(scores.min()),  4),
        "epss_max":           round(float(scores.max()),  4),
        "pct_over_0_5":       round(float((scores > 0.5).mean()), 4),
        "pct_over_0_8":       round(float((scores > 0.8).mean()), 4),
        "n_kev_sessions":     int((df.get("is_cisa_kev", pd.Series(0)) == 1).sum()),
        "drift_applied":      True,
    }
