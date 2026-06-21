"""
src/extractors/pipeline.py
Full 128-feature extraction pipeline — orchestrates all 6 extractors.
Handles both real Cowrie sessions and pre-labelled rows.
"""
from __future__ import annotations
import sys, logging
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from configs.schema import FEATURE_GROUPS, FEAT_NAMES, N_FEATURES, LABEL_TO_IDX
from src.extractors.temporal     import extract_temporal
from src.extractors.network      import extract_network
from src.extractors.payload      import extract_payload
from src.extractors.threat_intel import extract_threat_intel, fetch_epss, get_kev_set
from src.extractors.tls_host     import extract_tls_host

log = logging.getLogger(__name__)


def extract_all(session: dict,
                kev_set: set,
                epss_data: dict,
                semantic_row: Optional[np.ndarray] = None) -> np.ndarray:
    """
    Extract all 128 features for a single session dict.

    Args:
        session      : session metadata dict (from Cowrie parser or simulator)
        kev_set      : set of CISA KEV CVE IDs (pre-fetched)
        epss_data    : dict {cve_id: {score, pct}} (pre-fetched)
        semantic_row : pre-computed 30-d DistilBERT projection (or zeros)

    Returns:
        np.ndarray shape (128,) float32
    """
    buf = np.zeros(N_FEATURES, dtype=np.float32)

    # Group A  [0:24]   temporal
    buf[0:24]   = extract_temporal(session)

    # Group B  [24:52]  network
    buf[24:52]  = extract_network(session)

    # Group C  [52:76]  payload
    buf[52:76]  = extract_payload(session)

    # Group D  [76:106] semantic (pre-computed DistilBERT projection)
    if semantic_row is not None and len(semantic_row) == 30:
        buf[76:106] = semantic_row.astype(np.float32)
    # else stays zero — filled in batch step via semantic.py

    # Group E  [106:120] threat intelligence
    buf[106:120] = extract_threat_intel(session, kev_set, epss_data)

    # Group F  [120:128] TLS / host
    buf[120:128] = extract_tls_host(session)

    return np.nan_to_num(buf, nan=0.0, posinf=1e6, neginf=0.0)


def build_feature_matrix(df: pd.DataFrame,
                         semantic_matrix: Optional[np.ndarray] = None,
                         cache_kev: bool = True) -> tuple[np.ndarray, np.ndarray]:
    """
    Convert a DataFrame of session dicts into (X, y) numpy arrays.

    Args:
        df               : DataFrame with session metadata + 'micro_state' column
        semantic_matrix  : pre-computed (N, 30) DistilBERT projections aligned to df
        cache_kev        : whether to fetch KEV + EPSS once and reuse

    Returns:
        X : (N, 128) float32
        y : (N,)     int64
    """
    N = len(df)
    X = np.zeros((N, N_FEATURES), dtype=np.float32)

    log.info("Fetching KEV catalog...")
    kev_set = get_kev_set() if cache_kev else set()

    log.info("Fetching EPSS scores...")
    all_cves  = df["associated_cve"].dropna().unique().tolist()
    epss_data = fetch_epss(all_cves) if all_cves else {}

    log.info("Extracting features for %d sessions...", N)
    for i, (_, row) in enumerate(df.iterrows()):
        sem = semantic_matrix[i] if semantic_matrix is not None else None
        X[i] = extract_all(row.to_dict(), kev_set, epss_data, sem)
        if (i + 1) % 10_000 == 0:
            log.info("  %d / %d (%.1f%%)", i+1, N, (i+1)/N*100)

    y = df["micro_state"].map(LABEL_TO_IDX).fillna(0).values.astype(np.int64)

    # Clip extreme values
    X = np.clip(X, -100.0, 1e6)
    log.info("Feature matrix: X=%s  y=%s  NaN=%d  Inf=%d",
             X.shape, y.shape, np.isnan(X).sum(), np.isinf(X).sum())
    return X, y


def verify_schema(X: np.ndarray) -> None:
    """Assert feature matrix matches the 128-feature schema."""
    assert X.shape[1] == N_FEATURES, f"Expected 128 features, got {X.shape[1]}"
    assert not np.any(np.isnan(X)), "NaN values found in feature matrix"
    assert not np.any(np.isinf(X)), "Inf values found in feature matrix"
    for grp, info in FEATURE_GROUPS.items():
        slice_ = X[:, info["start"]:info["end"]]
        assert slice_.shape[1] == info["size"], \
            f"Group {grp}: expected {info['size']} features"
    log.info("Schema verification PASSED — all 128 features present and finite")
