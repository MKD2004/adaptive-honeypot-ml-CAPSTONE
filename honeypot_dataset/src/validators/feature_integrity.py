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
    "FEATURE_INDEX", "INVARIANTS", "EXPECTED_CONSTANT", "TRIAGE",
    "triage_summary",
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


# ── Triage of the constant columns (2026-11-11) ─────────────────────────────
# 46 of 128 columns are constant in X_train (modal share > 98%). Each one has a
# decision here, so "how many are left" is a number the validator can report
# rather than a thing someone has to re-derive. DATA_INTEGRITY.md section 3c
# carries the reasoning; this is the machine-readable form.
#
# The decision rule is availability in the REAL capture, measured rather than
# assumed, because that is what separates a fixable gap from a structural one:
#
#   key in a real parsed record   rows with a value   feeds
#   t_first_auth / t_first_cmd    11,328 / 11,328     time_to_first_*
#   src_ip                        11,328 / 11,328     geo_risk_score, repeat_visitor
#   associated_cve                     0 / 11,328     all 14 E_threat_intel
#   pkt_sizes_in / tcp_flags           absent         std_pkt_size_in, tcp_*
#   ja3                                absent         F_tls_host
#
# FIX   the input exists and something upstream is not using it.
# DROP  the input cannot exist for this project, OR populating it would create a
#       train/serve mismatch -- which is WORSE than a dead feature, because the
#       model would lean on a signal that is always absent at inference.
# ALLOW constant for an SSH-only corpus today, genuinely informative once a
#       second protocol lands. Keep in the schema, exclude from training until
#       it varies.
TRIAGE: Dict[str, Tuple[str, str]] = {
    # ── FIX: already repaired in the generator (f9fa918), pending a rebuild ──
    "iat_std":              ("FIX", "single-IAT fallback; timestamps now generated"),
    "iat_cv":               ("FIX", "single-IAT fallback; timestamps now generated"),
    "iat_skew":             ("FIX", "single-IAT fallback; timestamps now generated"),
    "iat_kurt":             ("FIX", "single-IAT fallback; timestamps now generated"),
    "frac_sub100ms":        ("FIX", "single-IAT fallback; timestamps now generated"),
    "frac_over30s":         ("FIX", "single-IAT fallback; timestamps now generated"),
    "burst_count":          ("FIX", "single-IAT fallback; timestamps now generated"),
    "burst_mean_size":      ("FIX", "single-IAT fallback; timestamps now generated"),
    "inter_burst_gap_std":  ("FIX", "single-IAT fallback; timestamps now generated"),

    # ── FIX: the real capture supplies the input, the GENERATOR does not ─────
    "time_to_first_auth_s": ("FIX", "real records carry t_first_auth for every "
                                    "row; the generator never emits it"),
    "time_to_first_cmd_s":  ("FIX", "real records carry t_first_cmd for every "
                                    "row; the generator never emits it"),

    # ── FIX: the generator never emits src_port, so the flag defaults to 0 ──
    # Real records carry src_port in every row and 98.3% of them are ephemeral
    # by the Linux definition (>= 32768). Note the extractor tests
    # `src_port > 49151`, the IANA dynamic/private floor, so real samples like
    # 34958 and 45312 read as NON-ephemeral. Which threshold is right is a
    # judgement call for the rebuild -- 32768 matches Linux-originated traffic,
    # 49151 is the IANA standard -- but either way the generator must emit the
    # port first, because the feature is currently measuring nothing.
    "src_is_ephemeral":     ("FIX", "the generator emits no src_port, so this "
                                    "defaults to 0; real records all have one"),

    # ── DROP: attempted as FIX on 2026-11-11, and both failed on measurement ─
    # Keyed on src_ip, which every real record has, so these looked fixable.
    # They are not, for two different reasons, and both are worth recording
    # because the obvious next person will try the same thing.
    "geo_risk_score":       ("DROP", "needs a country code. There is no GeoIP "
                                     "database or library anywhere in the "
                                     "project (geoip2, maxminddb, pygeoip all "
                                     "absent), so the extractor falls through "
                                     "to its 0.35 default for every row. Add a "
                                     "GeoLite2 dependency and this becomes a "
                                     "FIX; until then it measures nothing."),
    "attacker_repeat_visitor": ("DROP", "near-constant in REALITY, not just in "
                                        "the generator: 98.6% of the 45,648 "
                                        "real sessions come from an "
                                        "already-seen address, because a "
                                        "handful of bots dominate. Fixing the "
                                        "generator took it to 99.2%, which is "
                                        "faithful and still useless. A repeat "
                                        "COUNT or a recency would vary, but "
                                        "that is a schema change, not a fix."),

    # ── FIX: the extractor formula is wrong ─────────────────────────────────
    "rle_compression_ratio": ("FIX", "min(1.0, n_runs*2/len) saturates at 1.0 "
                                     "for ANY text -- measured 1.0000 on every "
                                     "real command. Drop the factor of 2."),

    # ── FIX: the calendar block rests on a fabricated timestamp ─────────────
    # Not strictly constant but effectively so: session_hour is 98.1% at hour 22
    # and session_day_of_week 98.3% at day 1 across 60,000 real-derived rows,
    # because the netflow rows were all given one t_start. The honeypot capture
    # has genuine timestamps spread over 8 days.
    "is_business_hours":    ("FIX", "derived from a shared fabricated t_start; "
                                    "real Cowrie timestamps span 8 days"),

    # ── DROP: populating it only in synthetic data is worse than leaving it ──
    # associated_cve is empty in 100% of real sessions. A model trained with
    # live threat-intel features would lean on a block that is all-zero at
    # inference. Revive this only if a CVE can be inferred from observed
    # behaviour for BOTH real and synthetic sessions.
    **{n: ("DROP", "associated_cve is empty in 100% of real sessions; "
                   "populating it only in synthetic data creates a train/serve "
                   "mismatch")
       for n in ("cvss_v3_base", "cvss_v3_norm", "cvss_exploitability",
                 "cvss_impact", "epss_score", "epss_percentile",
                 "epss_7d_delta", "is_cisa_kev", "kev_days_since_added",
                 "cve_age_days", "exploit_db_count", "has_metasploit",
                 "has_nuclei", "cve_refs_count")},

    # ── DROP: no TLS handshake exists in an SSH session ─────────────────────
    **{n: ("DROP", "SSH has no TLS handshake to fingerprint; structurally "
                   "unavailable until a TLS-speaking honeypot exists")
       for n in ("ja3_hash_bucket", "ja3_is_known_malicious", "tls_version_num",
                 "cipher_suite_count", "cipher_suite_entropy",
                 "sni_domain_entropy")},

    # ── DROP: needs packet capture, which no source provides uniformly ──────
    # Cowrie is application-layer and emits no packet sizes or TCP flags. The
    # CIC/UNSW flow rows DO carry them, so populating these would make them
    # alive for 13 netflow classes and dead for the other 32 -- the same
    # train/serve mismatch as the threat-intel block, by a different route.
    **{n: ("DROP", "Cowrie emits no packet-level data; populating from netflow "
                   "only would make it alive for 13 classes and dead for 32")
       for n in ("std_pkt_size_in", "pkt_size_entropy_in",
                 "tcp_syn", "tcp_ack", "tcp_fin", "tcp_rst")},

    # ── ALLOW: constant for one SSH honeypot, informative with a second ─────
    "is_wellknown_port":    ("ALLOW", "always 1 while the only honeypot is on "
                                      "port 22; varies as soon as Heralding or "
                                      "SNARE listens on a high port"),
    "is_db_port":           ("ALLOW", "no database honeypot deployed yet"),
    "unique_dst_ports":     ("ALLOW", "a single-port honeypot sees one port; "
                                      "varies with the multi-honeypot deploy"),
    "frac_url_encoded":     ("ALLOW", "no URL encoding in shell commands; "
                                      "informative for a web honeypot"),

    # ── ALLOW: genuinely constant for shell text, and that is the truth ─────
    "frac_printable":       ("ALLOW", "shell commands are printable by nature; "
                                      "would vary only for binary payloads"),
    "frac_null_bytes":      ("ALLOW", "shell commands contain no null bytes"),
}

# Constant columns that must NOT be reported as defects: an ALLOW decision is a
# decision on the record. FIX and DROP entries are still reported, because both
# describe work that has not happened yet.
EXPECTED_CONSTANT: Dict[str, str] = {
    name: reason for name, (decision, reason) in TRIAGE.items()
    if decision == "ALLOW"
}


def triage_summary(dead: Sequence[str]) -> Dict[str, List[str]]:
    """Group a list of dead column names by their triage decision.

    `UNTRIAGED` is the one that matters: a constant column nobody has decided
    about is exactly the state this module exists to make visible.
    """
    out: Dict[str, List[str]] = {"FIX": [], "DROP": [], "ALLOW": [],
                                 "UNTRIAGED": []}
    for n in dead:
        decision = TRIAGE.get(n, ("UNTRIAGED", ""))[0]
        out[decision].append(n)
    return out


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


def check_dead_columns(X: np.ndarray, *, min_distinct: int = 2,
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
        # MODAL SHARE is the test, not the distinct count. An earlier version
        # also failed any column with fewer than `min_distinct` values, which
        # flagged every legitimately binary flag -- `is_ssh_port` at a healthy
        # 54/46 split was reported as dead three times. A flag that splits the
        # data informs a classifier; one stuck at a single value does not.
        # `min_distinct` now only catches a genuinely single-valued column,
        # which the modal test already covers, and is kept for callers that
        # want to be stricter about continuous features.
        if modal > max_identical or distinct < min_distinct:
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


def validate(X: np.ndarray, *, min_distinct: int = 2,
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
    if rep.dead_columns:
        groups = triage_summary(rep.dead_columns)
        lines.append(f"  CONSTANT-COLUMN TRIAGE  ({len(rep.dead_columns)} dead)")
        for k in ("UNTRIAGED", "FIX", "DROP", "ALLOW"):
            if groups[k]:
                lines.append(f"    {k:<10} {len(groups[k]):>3}"
                             + ("   <-- nobody has decided about these"
                                if k == "UNTRIAGED" else ""))
        lines.append("")
    lines.append(f"  FAIL -- {len(rep.violations)} checks failed; "
                 f"worst single check affects {rep.rows_affected:,} rows")
    return "\n".join(lines)
