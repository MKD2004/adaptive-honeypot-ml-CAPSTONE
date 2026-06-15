"""
cve_intelligence/analyzers.py

Analytics Layer
═══════════════
Contains all scoring, classification, and filtering logic.
No API calls are made here — this module consumes DataFrames
produced by the pipeline and enriches them.

Responsibilities:
  - EPSS score fetching (real) with simulation fallback
  - CWE / keyword-based attack type classification
  - Priority score computation (CVSS × EPSS × KEV)
  - Severity labelling
  - Trending CVE detection (KEV entries added within N days)
  - Preprocessing / normalisation utilities

Removed vs. notebook:
  - All spacy / bs4 / sklearn imports (dead code — no NLP used)
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
import requests

from cve_intelligence import config

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# EPSS scoring
# ══════════════════════════════════════════════════════════════════════════════
def fetch_epss_scores(
    cve_ids: List[str],
    batch_size: int = config.EPSS_BATCH_SIZE,
) -> dict:
    """
    Fetch real EPSS scores from the FIRST.org API in batches.

    Args:
        cve_ids:    List of CVE ID strings.
        batch_size: Maximum CVE IDs per API request.

    Returns:
        Dict mapping CVE ID → EPSS score (float).
        CVE IDs not found in the response are absent from the dict.
    """
    epss_map: dict = {}
    batches = [cve_ids[i: i + batch_size] for i in range(0, len(cve_ids), batch_size)]
    logger.info(
        "Fetching EPSS scores for %d CVEs in %d batch(es).",
        len(cve_ids),
        len(batches),
    )

    for i, batch in enumerate(batches, start=1):
        try:
            params = {"cve": ",".join(batch)}
            resp = requests.get(
                config.EPSS_API_URL,
                params=params,
                timeout=config.REQUEST_TIMEOUT,
                
            )
            resp.raise_for_status()
            data = resp.json()
            for entry in data.get("data", []):
                cve_id = entry.get("cve", "")
                score  = entry.get("epss", 0.0)
                if cve_id:
                    epss_map[cve_id] = float(score)
        except Exception as exc:
            logger.warning("EPSS batch %d failed: %s", i, exc)

    logger.info(
        "EPSS fetch complete: %d / %d scores retrieved.",
        len(epss_map),
        len(cve_ids),
    )
    return epss_map


def simulate_epss(df: pd.DataFrame) -> pd.Series:
    """
    Simulate EPSS scores using a plausible distribution when live data
    is unavailable.

    Distribution:
      - KEV entries              → Beta(5, 2)  — biased toward 0.5–1.0
      - Critical CVSS (≥ 9.0)   → Beta(3, 3)  — moderate–high
      - Everything else          → Beta(1, 8)  — mostly low

    Args:
        df: DataFrame containing 'is_kev' and 'cvss_score' columns.

    Returns:
        pandas.Series of simulated EPSS scores aligned to df.index.
    """
    rng = np.random.default_rng(seed=42)
    scores: List[float] = []

    for _, row in df.iterrows():
        if row.get("is_kev", 0) == 1:
            s = float(rng.beta(5, 2))
        elif (row.get("cvss_score") or 0.0) >= 9.0:
            s = float(rng.beta(3, 3))
        else:
            s = float(rng.beta(1, 8))
        scores.append(round(s, 4))

    return pd.Series(scores, index=df.index)


def enrich_epss(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add an 'epss_score' column to df.

    Strategy:
      1. Attempt real EPSS fetch.
      2. Simulate scores for any CVE not covered by the real fetch.
      3. Merge real + simulated (real takes priority).

    Args:
        df: DataFrame with at minimum 'cve_id' and 'is_kev' columns.

    Returns:
        df with 'epss_score' column added (float, 0.0 → 1.0).
    """
    df = df.copy()

    real_epss   = fetch_epss_scores(df["cve_id"].tolist())
    simulated   = simulate_epss(df)

    df["epss_score"] = df["cve_id"].map(real_epss)
    df["epss_score"] = df["epss_score"].combine_first(simulated).fillna(0.0)

    real_count = df["cve_id"].isin(real_epss).sum()
    logger.info(
        "EPSS enrichment: %d real / %d simulated out of %d total.",
        real_count,
        len(df) - real_count,
        len(df),
    )
    return df


# ══════════════════════════════════════════════════════════════════════════════
# Attack-type classification
# ══════════════════════════════════════════════════════════════════════════════
def classify_attack_type(
    cwe: Optional[str],
    description: str,
) -> Tuple[str, str]:
    """
    Map a CWE / description to an actionable attack type string.

    Primary lookup:   CWE → config.CWE_ATTACK_MAP
    Fallback:         keyword scan of description → config.KEYWORD_MAP

    Args:
        cwe:         CWE identifier string (e.g. 'CWE-89') or None.
        description: English CVE description text.

    Returns:
        Tuple of (attack_type, method) where method is one of
        'CWE', 'keyword', or 'unknown'.
    """
    # 1. CWE direct lookup
    if cwe and cwe in config.CWE_ATTACK_MAP:
        return config.CWE_ATTACK_MAP[cwe], "CWE"

    # 2. Keyword scan (case-insensitive)
    desc_lower = (description or "").lower()
    for keywords, attack in config.KEYWORD_MAP:
        if any(kw in desc_lower for kw in keywords):
            return attack, "keyword"

    return "Other / Unknown", "unknown"


def apply_attack_classification(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add 'attack_type' and 'classify_method' columns to df.

    Args:
        df: DataFrame with 'cwe' and 'description' columns.

    Returns:
        df with two new columns.
    """
    df = df.copy()
    results = df.apply(
        lambda r: pd.Series(
            classify_attack_type(r.get("cwe"), r.get("description", "")),
            index=["attack_type", "classify_method"],
        ),
        axis=1,
    )
    df[["attack_type", "classify_method"]] = results

    cwe_count     = (df["classify_method"] == "CWE").sum()
    keyword_count = (df["classify_method"] == "keyword").sum()
    unknown_count = (df["classify_method"] == "unknown").sum()
    logger.info(
        "Attack classification: CWE=%d | keyword=%d | unknown=%d",
        cwe_count, keyword_count, unknown_count,
    )
    return df


# ══════════════════════════════════════════════════════════════════════════════
# Pre-processing
# ══════════════════════════════════════════════════════════════════════════════
def cvss_to_severity(score: float) -> str:
    """Map a CVSS v3 base score to a human-readable severity tier."""
    if   score >= 9.0: return "Critical"
    elif score >= 7.0: return "High"
    elif score >= 4.0: return "Medium"
    elif score >  0.0: return "Low"
    return "None"


def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalise and derive additional columns on the merged CVE DataFrame.

    Steps:
      a. Parse 'published' and 'last_modified' to UTC-aware datetimes.
      b. Fill missing CVSS scores with the column median.
      c. Fill missing EPSS scores with 0.0.
      d. Add 'severity' label (CVSS v3 scale).
      e. Strip description whitespace.
      f. Derive 'days_old' (days since published).
      g. Compute normalised 'cvss_norm' and 'epss_norm' for scoring.

    Args:
        df: Merged DataFrame (NVD + KEV + EPSS columns present).

    Returns:
        Enriched DataFrame.
    """
    df = df.copy()

    # a. Dates
    for col in ("published", "last_modified"):
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce", utc=True)

    # b. CVSS fill
    if "cvss_score" in df.columns:
        median = df["cvss_score"].median()
        df["cvss_score"] = df["cvss_score"].fillna(median)
    else:
        df["cvss_score"] = 0.0

    # c. EPSS fill
    df["epss_score"] = df.get("epss_score", pd.Series(0.0, index=df.index)).fillna(0.0)

    # d. Severity
    df["severity"] = df["cvss_score"].apply(cvss_to_severity)

    # e. Description
    if "description" in df.columns:
        df["description"] = df["description"].fillna("").str.strip()

    # f. Days since published
    now = pd.Timestamp.utcnow()
    if "published" in df.columns:
        df["days_old"] = (now - df["published"]).dt.days.fillna(-1).astype(int)
    else:
        df["days_old"] = -1

    # g. Normalised scores
    df["cvss_norm"] = (df["cvss_score"] / 10.0).clip(0.0, 1.0)
    df["epss_norm"] = df["epss_score"].clip(0.0, 1.0)

    logger.info(
        "Preprocessing complete. Severity counts: %s",
        df["severity"].value_counts().to_dict(),
    )
    return df


# ══════════════════════════════════════════════════════════════════════════════
# Priority scoring
# ══════════════════════════════════════════════════════════════════════════════
def priority_tier(score: float) -> str:
    """Map a priority score float to a labelled tier string."""
    if   score >= config.TIER_P1: return "P1 - Immediate"
    elif score >= config.TIER_P2: return "P2 - High"
    elif score >= config.TIER_P3: return "P3 - Medium"
    return "P4 - Low"


def compute_priority(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute composite priority scores and tier labels.

    Formula:
        priority = W_CVSS * cvss_norm + W_EPSS * epss_norm + W_KEV * is_kev

    Weights are defined in config.py and are independently tunable.

    Args:
        df: DataFrame with 'cvss_norm', 'epss_norm', 'is_kev' columns.

    Returns:
        df with 'priority_score' and 'priority_tier' columns added.
    """
    df = df.copy()

    df["priority_score"] = (
        config.W_CVSS * df["cvss_norm"]
        + config.W_EPSS * df["epss_norm"]
        + config.W_KEV  * df["is_kev"].fillna(0).astype(float)
    ).round(4)

    df["priority_tier"] = df["priority_score"].apply(priority_tier)

    logger.info(
        "Priority scoring complete. Tier distribution: %s",
        df["priority_tier"].value_counts().to_dict(),
    )
    return df


def sort_by_priority(df: pd.DataFrame) -> pd.DataFrame:
    """
    Sort DataFrame descending by priority_score, breaking ties with cvss_score.

    Returns a fresh DataFrame with a reset integer index.
    """
    return (
        df.sort_values(
            ["priority_score", "cvss_score"],
            ascending=[False, False],
        )
        .reset_index(drop=True)
    )


# ══════════════════════════════════════════════════════════════════════════════
# Trending CVE detection
# ══════════════════════════════════════════════════════════════════════════════
def _is_recently_exploited(
    row: pd.Series,
    cutoff: datetime,
) -> bool:
    """
    Return True if a CVE is in the KEV catalog AND was added within
    the trending window.

    Args:
        row:    A single DataFrame row with 'is_kev' and 'kev_date_added' columns.
        cutoff: Earliest datetime that counts as "recent".
    """
    if row.get("is_kev", 0) != 1:
        return False
    date_str = row.get("kev_date_added", "")
    if not date_str:
        return False
    try:
        added = datetime.strptime(
            str(date_str)[:10], "%Y-%m-%d"
        ).replace(tzinfo=timezone.utc)
        return added >= cutoff
    except (ValueError, TypeError):
        return False


def filter_trending(
    df: pd.DataFrame,
    window_days: int = config.TRENDING_WINDOW_DAYS,
) -> pd.DataFrame:
    """
    Filter df to only CVEs that are in KEV and were added within the last
    *window_days* days.

    Args:
        df:          DataFrame with 'is_kev' and 'kev_date_added' columns.
        window_days: Look-back window in days.

    Returns:
        Filtered DataFrame (may be empty if no recent KEV entries).
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    mask = df.apply(lambda row: _is_recently_exploited(row, cutoff), axis=1)
    trending = df[mask].copy()

    logger.info(
        "Trending filter (window=%d days, cutoff=%s): %d / %d CVEs.",
        window_days,
        cutoff.strftime("%Y-%m-%d"),
        len(trending),
        len(df),
    )
    return trending
