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

    # NaN SURVIVES, deliberately. `extract_temporal` returns NaN for anything the
    # session cannot support (see its provenance block), and zero-filling here is
    # precisely what hid a fabricated inter-arrival time across 52.3% of the
    # corpus for three months. Infinities ARE clamped: they come from division by
    # a near-zero duration, not from missing input.
    #
    # Callers therefore get NaN and must decide explicitly. `feature_integrity`
    # rejects it, so the decision cannot be made by accident.
    buf = np.where(np.isposinf(buf), np.float32(1e6), buf)
    buf = np.where(np.isneginf(buf), np.float32(0.0), buf)
    return buf.astype(np.float32)


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

    # Clip extreme values. np.clip propagates NaN, which is what we want.
    X = np.clip(X, -100.0, 1e6)
    n_nan = int(np.isnan(X).sum())
    rows_nan = int(np.isnan(X).any(axis=1).sum())
    log.info("Feature matrix: X=%s  y=%s  NaN=%d (%d rows)  Inf=%d",
             X.shape, y.shape, n_nan, rows_nan, int(np.isinf(X).sum()))
    if rows_nan:
        log.warning(
            "%d of %d rows (%.1f%%) carry NaN -- features their session cannot "
            "support. Resolve explicitly before training; do NOT zero-fill. "
            "See extractors/temporal.temporal_provenance.",
            rows_nan, len(X), 100.0 * rows_nan / max(len(X), 1))
    return X, y


def verify_schema(X: np.ndarray) -> None:
    """Assert feature matrix matches the 128-feature schema."""
    assert X.shape[1] == N_FEATURES, f"Expected 128 features, got {X.shape[1]}"
    assert not np.any(np.isinf(X)), "Inf values found in feature matrix"
    # NaN is NOT an error here any more -- it is how a feature says "this session
    # cannot support me". It must be confined to the temporal block, though:
    # NaN anywhere else means an extractor broke rather than abstained.
    nan_cols = np.where(np.isnan(X).any(axis=0))[0]
    outside = [int(c) for c in nan_cols if not (0 <= c < 24)]
    assert not outside, (
        f"NaN outside A_temporal at columns {outside} -- only the temporal "
        f"extractor is allowed to abstain")
    for grp, info in FEATURE_GROUPS.items():
        slice_ = X[:, info["start"]:info["end"]]
        assert slice_.shape[1] == info["size"], \
            f"Group {grp}: expected {info['size']} features"
    log.info("Schema verification PASSED — all 128 features present and finite")
