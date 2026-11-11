"""
src/validators/feature_integrity.py

Does a feature matrix contain rows that could not exist?

`quality_checks.py` already covers DISTRIBUTIONAL quality -- shape, class
balance, Wasserstein distance, adversarial AUC, a TSTR baseline. None of it
would have caught either of the two defects found on 2026-11-11:

  1. 45 of 128 features were CONSTANT across X_train, including all 14 of
     E_threat_intel and all 8 of F_tls_host. The extractor silently substituted
     a fabricated value for missing input, so the zeros were indistinguishable
     from measured zeros.
  2. 47% of TabSyn rows were ARITHMETICALLY IMPOSSIBLE -- `iat_mean` greater
     than `iat_max`, `iat_cv == 0` while `iat_min != iat_max`. TabSyn models
     each column's distribution and knows nothing of the identities between
     columns.

Both survived three months of training runs because nothing checked. This module
is the check. See `DATA_INTEGRITY.md`.

USAGE. Invariants are stated over RAW feature values, so un-scale first --
`data/final/*.npy` is already scaled:

    sc = joblib.load("data/final/feature_scaler.pkl")   # joblib, NOT pickle
    X_raw = sc.inverse_transform(X_scaled)
    report = validate(X_raw)
    print(format_report(report))
    assert_valid(X_raw)        # raises IntegrityError on any failure

Invariants are looked up BY NAME from each extractor's own name list rather than
by hardcoded index, so they survive a reordering of the schema.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import numpy as np

__all__ = [
    "IntegrityError", "Violation", "Report",
    "validate", "assert_valid", "format_report", "tolerance_from_scaler",
    "FEATURE_INDEX", "INVARIANTS", "EXPECTED_CONSTANT",
]


class IntegrityError(AssertionError):
    """A feature matrix contains rows that could not have been measured."""


# ── Feature index, built from the extractors' own name lists ────────────────
def _build_index() -> Dict[str, int]:
    from src.extractors.temporal import TEMPORAL_FEATURE_NAMES
    from src.extractors.network import NETWORK_FEATURE_NAMES
    from src.extractors.payload import PAYLOAD_FEATURE_NAMES
    from src.extractors.threat_intel import TI_FEATURE_NAMES
    from src.extractors.tls_host import TLS_FEATURE_NAMES

    index: Dict[str, int] = {}
    offset = 0
    for names in (TEMPORAL_FEATURE_NAMES, NETWORK_FEATURE_NAMES,
                  PAYLOAD_FEATURE_NAMES):
        for i, n in enumerate(names):
            index[n] = offset + i
        offset += len(names)
    offset += 30                        # D_semantic: 30 PCA dims, unnamed
    for names in (TI_FEATURE_NAMES, TLS_FEATURE_NAMES):
        for i, n in enumerate(names):
            index[n] = offset + i
        offset += len(names)
    if offset != 128:
        raise RuntimeError(f"feature index covers {offset} columns, expected 128")
    return index


FEATURE_INDEX = _build_index()


# ── Invariants ──────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Invariant:
    """One property every row must satisfy. `test` returns a per-row bool mask
    that is True where the row is VALID."""
    name: str
    needs: Tuple[str, ...]
    test: Callable[..., np.ndarray]
    why: str


# TOLERANCE. Every test takes a trailing `tol`, a PER-COLUMN absolute tolerance,
# because a naive fixed epsilon produces false positives that look exactly like
# findings. `data/final/*.npy` is stored as float32 and then un-scaled by a
# StandardScaler, so a value that was truly 0.0 comes back as
# +/- eps_float32 * scale_. For `commands_per_min`, scale_ is 157.8, giving a
# residue near 1.9e-5 -- a hundred times a 1e-6 epsilon. Measured before this was
# fixed: "commands_per_min >= 0" appeared to fail on 99.3% of X_test_real, and
# every one of those rows was a true zero rendered as -0.0000. See `validate`.
def _in_range(lo: float, hi: float):
    return lambda c, tol: (c >= lo - tol) & (c <= hi + tol)


def _nonneg(c, tol):
    return c >= -tol


def _binary(c, tol):
    t = max(float(np.max(tol)) if np.ndim(tol) else tol, 1e-6)
    return np.isclose(c, 0.0, atol=t) | np.isclose(c, 1.0, atol=t)


def _ordered(a, b, tol):
    """a <= b"""
    return a <= b + tol


def _log1p_of(primitive, derived, tol):
    return np.isclose(derived, np.log1p(np.maximum(primitive, -0.999999)),
                      rtol=1e-3, atol=np.maximum(tol, 1e-3))


def _ratio_of(num, den, derived, tol, eps=1e-9):
    return np.isclose(derived, num / (den + eps), rtol=1e-2,
                      atol=np.maximum(tol, 1e-2))


INVARIANTS: List[Invariant] = [
    # ── A_temporal: ordering of the inter-arrival summary ──────────────────
    Invariant("iat_min <= iat_mean", ("iat_min", "iat_mean"), _ordered,
              "a mean cannot be below the minimum it was taken over"),
    Invariant("iat_mean <= iat_max", ("iat_mean", "iat_max"), _ordered,
              "a mean cannot exceed the maximum it was taken over"),
    Invariant("iat_min <= iat_median", ("iat_min", "iat_median"), _ordered,
              "a median cannot be below the minimum"),
    Invariant("iat_median <= iat_max", ("iat_median", "iat_max"), _ordered,
              "a median cannot exceed the maximum"),
    Invariant("iat_std >= 0", ("iat_std",), _nonneg,
              "a standard deviation is non-negative"),
    Invariant("iat_cv == iat_std / iat_mean", ("iat_std", "iat_mean", "iat_cv"),
              _ratio_of, "cv is defined as std / mean"),
    Invariant("spread implies cv > 0", ("iat_min", "iat_max", "iat_cv"),
              lambda lo, hi, cv, tol: np.isclose(lo, hi, atol=np.maximum(tol, 1e-6)) | (np.abs(cv) > 1e-9),
              "if min != max the gaps varied, so the coefficient of variation "
              "cannot be zero -- THE TABSYN FAILURE"),
    # ── A_temporal: fractions, bursts, calendar ───────────────────────────
    Invariant("frac_sub100ms in [0,1]", ("frac_sub100ms",), _in_range(0, 1),
              "a fraction of observations lies in [0,1]"),
    Invariant("frac_sub1s in [0,1]", ("frac_sub1s",), _in_range(0, 1), "same"),
    Invariant("frac_over30s in [0,1]", ("frac_over30s",), _in_range(0, 1), "same"),
    Invariant("frac_sub100ms <= frac_sub1s", ("frac_sub100ms", "frac_sub1s"),
              _ordered, "gaps under 100ms are a subset of gaps under 1s"),
    Invariant("burst_count >= 0", ("burst_count",), _nonneg, "a count"),
    Invariant("burst_mean_size >= 0", ("burst_mean_size",), _nonneg, "a size"),
    Invariant("bursts agree", ("burst_count", "burst_mean_size"),
              lambda c, s, tol: (c > tol) == (s > tol),
              "burst_mean_size is 0 exactly when there are no bursts"),
    Invariant("no sub-100ms gap implies no burst",
              ("frac_sub100ms", "burst_count"),
              lambda f, c, tol: (f > tol) | (np.abs(c) <= tol),
              "a burst IS a run of sub-100ms gaps"),
    Invariant("inter_burst_gap_std >= 0", ("inter_burst_gap_std",), _nonneg, "a std"),
    Invariant("inter_burst_gap_mean >= 0", ("inter_burst_gap_mean",), _nonneg,
              "a mean of non-negative gaps"),
    Invariant("session_duration_s >= 0", ("session_duration_s",), _nonneg,
              "time does not run backwards"),
    Invariant("log_session_duration == log1p(duration)",
              ("session_duration_s", "log_session_duration"), _log1p_of,
              "declared as log1p of the duration"),
    Invariant("events_per_sec >= 0", ("events_per_sec",), _nonneg, "a rate"),
    Invariant("commands_per_min >= 0", ("commands_per_min",), _nonneg, "a rate"),
    Invariant("time_to_first_auth_s >= 0", ("time_to_first_auth_s",), _nonneg,
              "clamped to 0 in the extractor"),
    Invariant("time_to_first_cmd_s >= 0", ("time_to_first_cmd_s",), _nonneg, "same"),
    Invariant("session_day_of_week in [0,6]", ("session_day_of_week",),
              _in_range(0, 6), "a weekday index"),
    Invariant("session_hour in [0,23]", ("session_hour",), _in_range(0, 23),
              "an hour of the day"),
    Invariant("is_business_hours is 0 or 1", ("is_business_hours",), _binary,
              "a flag"),

    # ── B_network ──────────────────────────────────────────────────────────
    Invariant("bytes_in >= 0", ("bytes_in",), _nonneg, "a byte count"),
    Invariant("bytes_out >= 0", ("bytes_out",), _nonneg, "a byte count"),
    Invariant("log_bytes_in == log1p(bytes_in)", ("bytes_in", "log_bytes_in"),
              _log1p_of, "declared as log1p"),
    Invariant("log_bytes_out == log1p(bytes_out)", ("bytes_out", "log_bytes_out"),
              _log1p_of, "declared as log1p"),
    Invariant("packets_in >= 0", ("packets_in",), _nonneg, "a count"),
    Invariant("packets_out >= 0", ("packets_out",), _nonneg, "a count"),
    Invariant("log_pkts_in == log1p(packets_in)", ("packets_in", "log_pkts_in"),
              _log1p_of, "declared as log1p"),
    Invariant("log_pkts_out == log1p(packets_out)", ("packets_out", "log_pkts_out"),
              _log1p_of, "declared as log1p"),
    Invariant("bytes_ratio in [0,1]", ("bytes_ratio",), _in_range(0, 1),
              "bo / (bi + bo + eps)"),
    Invariant("bytes_asymmetry in [0,1]", ("bytes_asymmetry",), _in_range(0, 1),
              "|bi - bo| / (bi + bo + eps)"),
    Invariant("mean_pkt_size_in >= 0", ("mean_pkt_size_in",), _nonneg, "a size"),
    Invariant("std_pkt_size_in >= 0", ("std_pkt_size_in",), _nonneg, "a std"),
    Invariant("mean_pkt_size_in <= max_pkt_size_in",
              ("mean_pkt_size_in", "max_pkt_size_in"), _ordered,
              "a mean cannot exceed the maximum"),
    Invariant("dst_port_norm in [0,1]", ("dst_port_norm",), _in_range(0, 1),
              "a port divided by 65535"),
    Invariant("src_is_ephemeral is 0 or 1", ("src_is_ephemeral",), _binary, "a flag"),
    Invariant("is_wellknown_port is 0 or 1", ("is_wellknown_port",), _binary, "a flag"),
    Invariant("is_ssh_port is 0 or 1", ("is_ssh_port",), _binary, "a flag"),
    Invariant("is_http_port is 0 or 1", ("is_http_port",), _binary, "a flag"),
    Invariant("is_db_port is 0 or 1", ("is_db_port",), _binary, "a flag"),
    Invariant("port flags are mutually exclusive",
              ("is_ssh_port", "is_http_port", "is_db_port"),
              lambda a, b, c, tol: (a + b + c) <= 1 + 3 * np.maximum(tol, 1e-6),
              "one port cannot be SSH and HTTP and a database at once"),
    Invariant("login_attempts >= 0", ("login_attempts",), _nonneg, "a count"),
    Invariant("unique_dst_ports >= 0", ("unique_dst_ports",), _nonneg, "a count"),

    # ── C_payload ──────────────────────────────────────────────────────────
    Invariant("entropy_shannon in [0,8]", ("entropy_shannon",), _in_range(0, 8),
              "Shannon entropy over a byte alphabet maxes at log2(256) = 8"),
    Invariant("entropy_renyi2 in [0,8]", ("entropy_renyi2",), _in_range(0, 8), "same"),
    Invariant("bigram_entropy >= 0", ("bigram_entropy",), _nonneg, "an entropy"),
    Invariant("trigram_entropy >= 0", ("trigram_entropy",), _nonneg, "an entropy"),
    Invariant("unique_byte_ratio in [0,1]", ("unique_byte_ratio",), _in_range(0, 1),
              "a ratio of distinct bytes to total"),
    Invariant("mean_byte_val in [0,255]", ("mean_byte_val",), _in_range(0, 255),
              "a mean over byte values"),
    Invariant("std_byte_val >= 0", ("std_byte_val",), _nonneg, "a std"),
    Invariant("mean_token_len <= max_token_len",
              ("mean_token_len", "max_token_len"), _ordered,
              "a mean cannot exceed the maximum"),
    Invariant("token_count >= 0", ("token_count",), _nonneg, "a count"),
    Invariant("log_payload_len >= 0", ("log_payload_len",), _nonneg,
              "log1p of a non-negative length"),
    Invariant("rle_compression_ratio >= 0", ("rle_compression_ratio",), _nonneg,
              "a ratio of lengths"),
    Invariant("pipe_operator_count >= 0", ("pipe_operator_count",), _nonneg, "a count"),
    Invariant("redirect_operator_count >= 0", ("redirect_operator_count",), _nonneg,
              "a count"),
] + [
    Invariant(f"{n} in [0,1]", (n,), _in_range(0, 1), "a fraction of characters")
    for n in ("frac_printable", "frac_hex_chars", "frac_uppercase",
              "frac_lowercase", "frac_digit", "frac_special", "frac_null_bytes",
              "frac_url_encoded", "base64_likelihood")
] + [
    # ── E_threat_intel ─────────────────────────────────────────────────────
    Invariant("cvss_v3_base in [0,10]", ("cvss_v3_base",), _in_range(0, 10),
              "the CVSS v3 base score scale"),
    Invariant("cvss_v3_norm in [0,1]", ("cvss_v3_norm",), _in_range(0, 1),
              "the base score over 10"),
    Invariant("cvss_v3_norm == cvss_v3_base / 10",
              ("cvss_v3_base", "cvss_v3_norm"),
              lambda b, n, tol: np.isclose(n, b / 10.0, rtol=1e-3, atol=np.maximum(tol, 1e-3)),
              "declared as base / 10"),
    Invariant("epss_score in [0,1]", ("epss_score",), _in_range(0, 1),
              "EPSS is a probability"),
    Invariant("epss_percentile in [0,1]", ("epss_percentile",), _in_range(0, 1),
              "a percentile expressed as a fraction"),
    Invariant("is_cisa_kev is 0 or 1", ("is_cisa_kev",), _binary, "a flag"),
    Invariant("has_metasploit is 0 or 1", ("has_metasploit",), _binary, "a flag"),
    Invariant("has_nuclei is 0 or 1", ("has_nuclei",), _binary, "a flag"),
    Invariant("exploit_db_count >= 0", ("exploit_db_count",), _nonneg, "a count"),
    Invariant("cve_refs_count >= 0", ("cve_refs_count",), _nonneg, "a count"),
    Invariant("cve_age_days >= 0", ("cve_age_days",), _nonneg,
              "a CVE cannot be published in the future"),

    # ── F_tls_host ─────────────────────────────────────────────────────────
    Invariant("ja3_is_known_malicious is 0 or 1", ("ja3_is_known_malicious",),
              _binary, "a flag"),
    Invariant("cipher_suite_count >= 0", ("cipher_suite_count",), _nonneg, "a count"),
    Invariant("cipher_suite_entropy >= 0", ("cipher_suite_entropy",), _nonneg,
              "an entropy"),
    Invariant("sni_domain_entropy >= 0", ("sni_domain_entropy",), _nonneg,
              "an entropy"),
    Invariant("geo_risk_score in [0,1]", ("geo_risk_score",), _in_range(0, 1),
              "a normalised risk score"),
]


# Features that are legitimately constant for an SSH-only corpus. Listing them
# explicitly is the point: an allow-list is a decision on the record, whereas a
# silently-constant column is the bug this module exists to catch. Anything NOT
# in here that comes back constant is reported.
EXPECTED_CONSTANT: Dict[str, str] = {
    "std_pkt_size_in": "the extractor sets it to 0.0 whenever pkt_sizes_in is "
                       "absent, which is every session without packet captures",
}


# ── Report ──────────────────────────────────────────────────────────────────
@dataclass
class Violation:
    kind: str              # "arithmetic" | "dead_column" | "not_finite"
    detail: str
    n_rows: int = 0
    frac: float = 0.0
    why: str = ""


@dataclass
class Report:
    n_rows: int
    n_cols: int
    violations: List[Violation] = field(default_factory=list)
    dead_columns: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations

    @property
    def rows_affected(self) -> int:
        return max((v.n_rows for v in self.violations if v.kind == "arithmetic"),
                   default=0)


def _column(X: np.ndarray, name: str) -> Optional[np.ndarray]:
    i = FEATURE_INDEX.get(name)
    if i is None or i >= X.shape[1]:
        return None
    return X[:, i]


def check_arithmetic(X: np.ndarray,
                    atol: Optional[np.ndarray] = None) -> List[Violation]:
    """Rows violating a relationship that holds by definition.

    `atol` is a per-column absolute tolerance; see `validate`. Each invariant
    receives the LARGEST tolerance among the columns it reads, so a comparison
    between a precise column and a coarse one is judged at the coarse one.
    """
    out: List[Violation] = []
    for inv in INVARIANTS:
        idx = [FEATURE_INDEX.get(n) for n in inv.needs]
        cols = [_column(X, n) for n in inv.needs]
        if any(c is None for c in cols):
            continue
        if atol is None:
            tol = 1e-6
        else:
            tol = float(max(atol[i] for i in idx if i is not None))
        with np.errstate(invalid="ignore", divide="ignore"):
            valid = np.asarray(inv.test(*cols, tol))
        bad = int((~valid).sum())
        if bad:
            out.append(Violation("arithmetic", inv.name, bad,
                                 bad / max(len(X), 1), inv.why))
    return out


def check_dead_columns(X: np.ndarray, *, min_distinct: int = 4,
                       max_identical: float = 0.98,
                       names: Optional[Sequence[str]] = None
                       ) -> Tuple[List[Violation], List[str]]:
    """Columns that cannot inform a classifier.

    This is the check that would have caught the original bug, and it is about
    twenty lines. A feature with three or fewer distinct values across tens of
    thousands of sessions is a constant wearing a feature's name.
    """
    by_index = {i: n for n, i in FEATURE_INDEX.items()}
    out: List[Violation] = []
    dead: List[str] = []
    for i in range(X.shape[1]):
        col = X[:, i]
        finite = col[np.isfinite(col)]
        if len(finite) == 0:
            continue
        distinct = len(np.unique(np.round(finite, 6)))
        vals, counts = np.unique(np.round(finite, 6), return_counts=True)
        modal = counts.max() / len(finite)
        name = by_index.get(i, f"D_semantic[{i - 76}]" if 76 <= i < 106 else f"feat_{i}")
        if distinct < min_distinct or modal > max_identical:
            dead.append(name)
            if name in EXPECTED_CONSTANT:
                continue                      # a decision on the record
            out.append(Violation(
                "dead_column",
                f"{name} (feat {i}): {distinct} distinct value(s), "
                f"{100 * modal:.1f}% identical",
                why="a constant column cannot inform a classifier"))
    return out, dead


def check_finite(X: np.ndarray) -> List[Violation]:
    nan = int(np.isnan(X).sum())
    inf = int(np.isinf(X).sum())
    out = []
    if nan:
        out.append(Violation("not_finite", f"{nan} NaN cells", why=
                             "a NaN means a feature could not be computed -- "
                             "resolve or drop the row, never zero-fill"))
    if inf:
        out.append(Violation("not_finite", f"{inf} infinite cells", why=
                             "usually an unguarded division"))
    return out


def tolerance_from_scaler(scaler, n_cols: int = 128,
                          storage_dtype=np.float32,
                          safety: float = 8.0) -> np.ndarray:
    """Per-column absolute tolerance for a matrix that was scaled, stored at
    `storage_dtype`, and un-scaled again.

    A value that was exactly 0.0 survives that round trip as
    +/- eps(storage_dtype) * scale_, so the tolerance has to follow `scale_`
    rather than being one global epsilon. Without this the validator reports
    true zeros as negative counts -- it did, on 99.3% of X_test_real.
    """
    eps = float(np.finfo(storage_dtype).eps)
    scale = np.asarray(getattr(scaler, "scale_", np.ones(n_cols)),
                       dtype=np.float64)
    if scale.shape[0] != n_cols:
        scale = np.ones(n_cols)
    return safety * eps * np.maximum(scale, 1.0)


def validate(X: np.ndarray, *, min_distinct: int = 4,
             max_identical: float = 0.98,
             scaler=None, atol: Optional[np.ndarray] = None) -> Report:
    """Full integrity report for a RAW (un-scaled) feature matrix.

    Pass `scaler` (the fitted StandardScaler the data was stored with) so
    tolerances track each column's magnitude, or `atol` directly. With neither,
    a flat 1e-6 is used, which is too tight for un-scaled float32 data and will
    produce false positives on large-magnitude columns.
    """
    X = np.asarray(X, dtype=np.float64)
    if X.ndim != 2:
        raise ValueError(f"expected a 2-D matrix, got shape {X.shape}")
    if atol is None and scaler is not None:
        atol = tolerance_from_scaler(scaler, n_cols=X.shape[1])
    rep = Report(n_rows=X.shape[0], n_cols=X.shape[1])
    rep.violations.extend(check_finite(X))
    rep.violations.extend(check_arithmetic(X, atol))
    dead_v, dead = check_dead_columns(X, min_distinct=min_distinct,
                                      max_identical=max_identical)
    rep.violations.extend(dead_v)
    rep.dead_columns = dead
    return rep


def assert_valid(X: np.ndarray, **kw) -> None:
    """Raise unless the matrix is fit to train on.

    Call this at the TRAINING ENTRY POINT, not in an optional notebook cell. A
    report nobody runs is how 45 constant features survived three months.
    """
    rep = validate(X, **kw)
    if not rep.ok:
        raise IntegrityError(format_report(rep))


def format_report(rep: Report) -> str:
    lines = [f"feature integrity: {rep.n_rows:,} rows x {rep.n_cols} columns",
             ""]
    if rep.ok:
        lines.append("  PASS -- no impossible rows, no constant columns")
        return "\n".join(lines)

    for kind, title in (("not_finite", "NON-FINITE VALUES"),
                        ("arithmetic", "IMPOSSIBLE ROWS"),
                        ("dead_column", "CONSTANT COLUMNS")):
        group = [v for v in rep.violations if v.kind == kind]
        if not group:
            continue
        lines.append(f"  {title}  ({len(group)})")
        for v in group:
            if v.kind == "arithmetic":
                lines.append(f"    {v.detail:<44} {v.n_rows:>8,} rows "
                             f"({100 * v.frac:5.1f}%)")
            else:
                lines.append(f"    {v.detail}")
        lines.append("")
    lines.append(f"  FAIL -- {len(rep.violations)} checks failed; "
                 f"worst single check affects {rep.rows_affected:,} rows")
    return "\n".join(lines)
