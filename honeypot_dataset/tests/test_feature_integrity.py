"""
honeypot_dataset/tests/test_feature_integrity.py

Tests for the integrity validator. A validator nobody trusts is worse than none,
because a false positive looks exactly like a finding -- that happened during
development and is pinned down in `TestToleranceIsScaleAware` below.

The strongest evidence that it works is not in this file: run it on the frozen
dataset and `X_test_real` reports ZERO impossible rows while `X_test_synth`
reports 14 failing checks. Real-derived rows are arithmetically coherent and
TabSyn rows are not, which is the discrimination the module exists to make and
was not built into it.
"""
import sys
import unittest
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "honeypot_dataset"))

from src.validators.feature_integrity import (                     # noqa: E402
    FEATURE_INDEX, IntegrityError, assert_valid, check_arithmetic,
    check_dead_columns, format_report, tolerance_from_scaler, validate)

I = FEATURE_INDEX


def coherent(n: int = 500, seed: int = 0) -> np.ndarray:
    """A matrix whose every declared relationship holds."""
    rng = np.random.default_rng(seed)
    X = np.zeros((n, 128))
    gaps = rng.lognormal(-0.5, 1.0, size=(n, 9))
    X[:, I["iat_min"]] = gaps.min(axis=1)
    X[:, I["iat_max"]] = gaps.max(axis=1)
    X[:, I["iat_mean"]] = gaps.mean(axis=1)
    X[:, I["iat_median"]] = np.median(gaps, axis=1)
    X[:, I["iat_std"]] = gaps.std(axis=1)
    X[:, I["iat_cv"]] = gaps.std(axis=1) / gaps.mean(axis=1)
    X[:, I["frac_sub1s"]] = (gaps < 1.0).mean(axis=1)
    X[:, I["frac_sub100ms"]] = (gaps < 0.1).mean(axis=1)
    X[:, I["frac_over30s"]] = (gaps > 30).mean(axis=1)
    bursts = (gaps < 0.1).sum(axis=1).astype(float)
    X[:, I["burst_count"]] = bursts
    X[:, I["burst_mean_size"]] = np.where(bursts > 0, 1.0, 0.0)
    dur = gaps.sum(axis=1)
    X[:, I["session_duration_s"]] = dur
    X[:, I["log_session_duration"]] = np.log1p(dur)
    X[:, I["session_day_of_week"]] = rng.integers(0, 7, n)
    X[:, I["session_hour"]] = rng.integers(0, 24, n)
    X[:, I["is_business_hours"]] = rng.integers(0, 2, n)
    bi = rng.lognormal(6, 1.5, n)
    bo = rng.lognormal(5, 1.5, n)
    X[:, I["bytes_in"]], X[:, I["bytes_out"]] = bi, bo
    X[:, I["log_bytes_in"]], X[:, I["log_bytes_out"]] = np.log1p(bi), np.log1p(bo)
    X[:, I["bytes_ratio"]] = bo / (bi + bo + 1e-9)
    X[:, I["bytes_asymmetry"]] = np.abs(bi - bo) / (bi + bo + 1e-9)
    pi_, po_ = rng.integers(1, 50, n).astype(float), rng.integers(1, 50, n).astype(float)
    X[:, I["packets_in"]], X[:, I["packets_out"]] = pi_, po_
    X[:, I["log_pkts_in"]], X[:, I["log_pkts_out"]] = np.log1p(pi_), np.log1p(po_)
    X[:, I["mean_pkt_size_in"]] = bi / pi_
    X[:, I["max_pkt_size_in"]] = bi
    X[:, I["dst_port_norm"]] = 22 / 65535
    X[:, I["is_ssh_port"]] = 1.0
    X[:, I["entropy_shannon"]] = rng.uniform(0, 8, n)
    X[:, I["entropy_renyi2"]] = rng.uniform(0, 8, n)
    X[:, I["mean_byte_val"]] = rng.uniform(0, 255, n)
    X[:, I["unique_byte_ratio"]] = rng.uniform(0, 1, n)
    X[:, I["mean_token_len"]] = rng.uniform(1, 5, n)
    X[:, I["max_token_len"]] = rng.uniform(6, 20, n)
    X[:, I["cvss_v3_base"]] = rng.uniform(0, 10, n)
    X[:, I["cvss_v3_norm"]] = X[:, I["cvss_v3_base"]] / 10.0
    X[:, I["epss_score"]] = rng.uniform(0, 1, n)
    X[:, I["epss_percentile"]] = rng.uniform(0, 1, n)
    X[:, 76:106] = rng.normal(size=(n, 30))          # D_semantic, unconstrained
    return X


class TestItPassesCoherentData(unittest.TestCase):

    def test_no_impossible_rows(self):
        rep = validate(coherent())
        arith = [v for v in rep.violations if v.kind == "arithmetic"]
        self.assertEqual(arith, [], f"false positives:\n{format_report(rep)}")

    def test_assert_valid_still_objects_to_the_constant_columns(self):
        """The fixture leaves most of B/C/E/F zero, so the dead-column check
        must fire -- that check is the one that would have caught the original
        bug and it must not be easy to satisfy by accident."""
        with self.assertRaises(IntegrityError):
            assert_valid(coherent())


class TestItCatchesEachImpossibility(unittest.TestCase):
    """One broken row per invariant. If any of these stops failing, the
    validator has a hole."""

    def _breaks(self, mutate, expect):
        X = coherent(200)
        mutate(X)
        names = [v.detail for v in check_arithmetic(X)]
        self.assertIn(expect, names, f"did not catch {expect}; got {names}")

    def test_mean_above_max(self):
        self._breaks(lambda X: X.__setitem__((0, I["iat_mean"]),
                                             X[0, I["iat_max"]] + 5),
                     "iat_mean <= iat_max")

    def test_mean_below_min(self):
        self._breaks(lambda X: X.__setitem__((0, I["iat_min"]),
                                             X[0, I["iat_mean"]] + 5),
                     "iat_min <= iat_mean")

    def test_the_tabsyn_failure_spread_without_variation(self):
        """The row that started this: min != max yet cv == 0."""
        def m(X):
            X[0, I["iat_min"]] = 14.9
            X[0, I["iat_mean"]] = 17.8
            X[0, I["iat_max"]] = 17.5     # also mean > max, as in the real row
            X[0, I["iat_cv"]] = 0.0
        self._breaks(m, "spread implies cv > 0")

    def test_negative_standard_deviation(self):
        self._breaks(lambda X: X.__setitem__((0, I["iat_std"]), -1.0),
                     "iat_std >= 0")

    def test_fraction_above_one(self):
        self._breaks(lambda X: X.__setitem__((0, I["frac_sub1s"]), 1.5),
                     "frac_sub1s in [0,1]")

    def test_subset_fraction_larger_than_its_superset(self):
        def m(X):
            X[0, I["frac_sub100ms"]] = 0.9
            X[0, I["frac_sub1s"]] = 0.2
        self._breaks(m, "frac_sub100ms <= frac_sub1s")

    def test_broken_log_relation(self):
        self._breaks(lambda X: X.__setitem__((0, I["log_bytes_in"]), 99.0),
                     "log_bytes_in == log1p(bytes_in)")

    def test_broken_duration_log(self):
        self._breaks(lambda X: X.__setitem__((0, I["log_session_duration"]), 42.0),
                     "log_session_duration == log1p(duration)")

    def test_bursts_disagreeing(self):
        def m(X):
            X[0, I["burst_count"]] = 0.0
            X[0, I["burst_mean_size"]] = 3.0
        self._breaks(m, "bursts agree")

    def test_cvss_norm_not_matching_base(self):
        self._breaks(lambda X: X.__setitem__((0, I["cvss_v3_norm"]), 0.99),
                     "cvss_v3_norm == cvss_v3_base / 10")

    def test_a_port_that_is_ssh_and_http_at_once(self):
        def m(X):
            X[0, I["is_ssh_port"]] = 1.0
            X[0, I["is_http_port"]] = 1.0
        self._breaks(m, "port flags are mutually exclusive")

    def test_mean_packet_larger_than_max(self):
        self._breaks(lambda X: X.__setitem__((0, I["mean_pkt_size_in"]),
                                             X[0, I["max_pkt_size_in"]] + 10),
                     "mean_pkt_size_in <= max_pkt_size_in")

    def test_out_of_range_hour(self):
        self._breaks(lambda X: X.__setitem__((0, I["session_hour"]), 25.0),
                     "session_hour in [0,23]")


class TestDeadColumnDetection(unittest.TestCase):
    """~20 lines that would have caught the original bug."""

    def test_a_constant_column_is_reported(self):
        X = coherent()
        X[:, I["iat_cv"]] = 0.0
        viol, dead = check_dead_columns(X)
        self.assertIn("iat_cv", dead)

    def test_the_burst_count_signature_is_caught(self):
        """Exactly how it looked in the frozen set: two values, {0, 1}."""
        X = coherent()
        X[:, I["burst_count"]] = 0.0
        X[:300, I["burst_count"]] = 0.0
        X[300:, I["burst_count"]] = 1.0
        viol, dead = check_dead_columns(X, min_distinct=4)
        self.assertIn("burst_count", dead)

    def test_a_varied_column_is_not_reported(self):
        X = coherent()
        viol, dead = check_dead_columns(X)
        self.assertNotIn("iat_mean", dead)
        self.assertNotIn("bytes_in", dead)

    def test_the_allow_list_suppresses_a_known_constant(self):
        """std_pkt_size_in is 0.0 by construction without packet captures. It
        is listed, so it must not be reported as a defect -- while still being
        counted as dead."""
        X = coherent()
        viol, dead = check_dead_columns(X)
        self.assertIn("std_pkt_size_in", dead)
        self.assertNotIn("std_pkt_size_in",
                         " ".join(v.detail for v in viol))


class TestToleranceIsScaleAware(unittest.TestCase):
    """The false-positive bug, pinned.

    data/final is float32 and un-scaled by a StandardScaler, so a true 0.0 comes
    back as +/- eps32 * scale_. With scale_ = 157.8 that is ~1.9e-5, which a
    1e-6 epsilon reads as a negative rate. Before this was fixed the validator
    reported `commands_per_min >= 0` failing on 99.3% of X_test_real -- every
    one a true zero.
    """

    def test_a_float32_round_trip_does_not_look_like_breakage(self):
        """Take coherent data, scale it, store it as float32, un-scale it. Every
        relationship still holds in principle, so a validator must report
        nothing -- but with a flat epsilon it reports violations, because the
        residue is eps32 * scale_ and scale_ can be in the hundreds.

        The assertion is about the MECHANISM, not a particular column: which
        invariant trips depends on which way the last bit rounded, and an
        earlier version of this test pinned `commands_per_min` and failed
        because its residue happened to come out positive.
        """
        from sklearn.preprocessing import StandardScaler
        rng = np.random.default_rng(3)
        raw = coherent(400)
        # a mostly-zero column with a large scale_, as in the real data
        raw[:, I["commands_per_min"]] = 0.0
        raw[:8, I["commands_per_min"]] = rng.uniform(2000, 4000, 8)
        raw[:, I["events_per_sec"]] = rng.uniform(0, 500, 400)
        sc = StandardScaler().fit(raw)
        round_tripped = sc.inverse_transform(
            sc.transform(raw).astype(np.float32).astype(np.float64))

        flat = [v.detail for v in check_arithmetic(round_tripped)]
        self.assertTrue(flat, "the fixture is not reproducing any float32 "
                              "residue, so the rest of this test would prove "
                              "nothing")

        aware = [v.detail for v in check_arithmetic(
            round_tripped, tolerance_from_scaler(sc, n_cols=128))]
        self.assertEqual(aware, [],
                         f"scale-aware tolerance should absorb all of it, "
                         f"still reported: {aware}")

    def test_tolerance_follows_the_column_scale(self):
        class S:
            scale_ = np.concatenate([np.full(64, 1.0), np.full(64, 1000.0)])
        tol = tolerance_from_scaler(S(), n_cols=128)
        self.assertLess(tol[0], tol[100])

    def test_a_genuine_violation_still_fails_under_loose_tolerance(self):
        """The tolerance must not be so generous that real breakage passes."""
        X = coherent(200)
        X[0, I["iat_std"]] = -50.0
        tol = np.full(128, 1e-3)
        self.assertIn("iat_std >= 0",
                      [v.detail for v in check_arithmetic(X, tol)])


class TestReporting(unittest.TestCase):

    def test_nan_and_inf_are_reported(self):
        X = coherent(100)
        X[0, 0] = np.nan
        X[1, 1] = np.inf
        kinds = [v.kind for v in validate(X).violations]
        self.assertIn("not_finite", kinds)

    def test_a_clean_report_says_pass(self):
        rep = validate(coherent(), min_distinct=1, max_identical=1.01)
        self.assertTrue(rep.ok, format_report(rep))
        self.assertIn("PASS", format_report(rep))

    def test_rejects_a_non_matrix(self):
        with self.assertRaises(ValueError):
            validate(np.zeros(128))


if __name__ == "__main__":
    unittest.main(verbosity=2)
