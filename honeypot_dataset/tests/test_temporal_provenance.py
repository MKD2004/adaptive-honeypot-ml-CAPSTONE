"""
honeypot_dataset/tests/test_temporal_provenance.py

Guards Part 0 of DATA_INTEGRITY.md section 4: a feature that cannot be computed
must be MISSING, not fabricated.

WHAT WENT WRONG, AND WHY IT SURVIVED. `extract_temporal` used to invent a single
inter-arrival time when a session carried no event stream:

    iat = np.array([duration / max(n_events - 1, 1)])

One value has no spread, no shape and no runs, so `iat_min == iat_mean ==
iat_median == iat_max` and ten more features collapse. The row it produces is
ARITHMETICALLY CONSISTENT -- min <= mean <= max holds with equality, cv ==
std/mean holds at 0/x, every fraction is in [0, 1] -- so every invariant a
validator could check passed. It went unnoticed for three months and affected
915,320 of 1,749,809 rows (52.3%) of the 2026-11-24 rebuild: every CIC-IDS2017
and UNSW-NB15 row, because a netflow record has no event stream.

So these tests check a second axis that arithmetic cannot: could this value have
been MEASURED? `test_a_consistent_fabrication_is_still_rejected` is the one that
matters -- it builds a row that passes every arithmetic invariant and asserts the
validator refuses it anyway.
"""
import math
import sys
import unittest
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "honeypot_dataset"))

from src.extractors.temporal import (                              # noqa: E402
    FLOW_STAT_FEATURES, PROV_EVENT_STREAM, PROV_FLOW_MEAN, PROV_FLOW_STATS,
    PROV_NONE, SEQUENCE_ONLY_FEATURES, TEMPORAL_FEATURE_NAMES,
    extract_temporal, temporal_provenance, unavailable_features)
from src.validators.feature_integrity import (                     # noqa: E402
    FEATURE_INDEX, degenerate_iat_mask, fabricated_iat_mask,
    provenance_from_nan, validate_provenance)

IDX = {n: i for i, n in enumerate(TEMPORAL_FEATURE_NAMES)}

STREAM = {"t_start": 0.0, "t_end": 10.0, "n_events": 5, "n_commands": 2,
          "event_timestamps": [0.0, 1.0, 2.5, 6.0, 10.0]}
FLOW = {"t_start": 0.0, "t_end": 10.0, "n_events": 5, "n_commands": 0,
        "iat_mean_s": 0.5, "iat_std_s": 0.2, "iat_min_s": 0.1, "iat_max_s": 0.9}
MEAN_ONLY = {"t_start": 0.0, "t_end": 10.0, "n_events": 5, "n_commands": 0,
             "iat_mean_s": 0.5}
NOTHING = {"t_start": 0.0, "t_end": 10.0, "n_events": 5, "n_commands": 0}


class TestProvenanceClassification(unittest.TestCase):
    def test_each_level_is_recognised(self):
        self.assertEqual(temporal_provenance(STREAM), PROV_EVENT_STREAM)
        self.assertEqual(temporal_provenance(FLOW), PROV_FLOW_STATS)
        self.assertEqual(temporal_provenance(MEAN_ONLY), PROV_FLOW_MEAN)
        self.assertEqual(temporal_provenance(NOTHING), PROV_NONE)

    def test_one_timestamp_is_not_a_stream(self):
        """A single timestamp yields no gap, so it is NOT event_stream.

        This is the exact input that used to trigger the fabrication.
        """
        self.assertEqual(temporal_provenance({**NOTHING,
                                              "event_timestamps": [5.0]}),
                         PROV_NONE)

    def test_a_pandas_missing_value_is_absent_not_present(self):
        """Records arriving via pandas report absence as float NaN, not None.

        `v is not None` is True for NaN, so a naive check would declare a netflow
        row to carry flow statistics it does not have -- labelling fabricated
        absence as genuine measurement, which is worse than the original bug.
        """
        self.assertEqual(temporal_provenance({**NOTHING,
                                              "event_timestamps": float("nan")}),
                         PROV_NONE)
        self.assertEqual(temporal_provenance({**NOTHING,
                                              "iat_mean_s": float("nan")}),
                         PROV_NONE)
        partial = {**NOTHING, "iat_mean_s": 0.5, "iat_std_s": float("nan"),
                   "iat_min_s": float("nan"), "iat_max_s": float("nan")}
        self.assertEqual(temporal_provenance(partial), PROV_FLOW_MEAN)


class TestNoFabrication(unittest.TestCase):
    def test_a_session_with_no_stream_reports_nan_not_an_invented_gap(self):
        """The regression guard. Was `duration / (n_events - 1)` = 2.5 s."""
        f = extract_temporal(NOTHING)
        for name in ("iat_mean", "iat_std", "iat_min", "iat_max", "iat_median"):
            self.assertTrue(math.isnan(float(f[IDX[name]])),
                            f"{name} was fabricated instead of reported missing")

    def test_nan_appears_in_exactly_the_unavailable_features(self):
        for sess in (STREAM, FLOW, MEAN_ONLY, NOTHING):
            prov = temporal_provenance(sess)
            f = extract_temporal(sess)
            got = {n for n in TEMPORAL_FEATURE_NAMES
                   if math.isnan(float(f[IDX[n]]))}
            self.assertEqual(got, unavailable_features(prov),
                             f"NaN pattern does not match contract at {prov}")

    def test_what_is_still_measurable_is_still_measured(self):
        """Losing the IAT must not cost the features that never needed it."""
        f = extract_temporal(NOTHING)
        self.assertAlmostEqual(float(f[IDX["session_duration_s"]]), 10.0, places=4)
        for name in ("log_session_duration", "events_per_sec",
                     "session_hour", "session_day_of_week"):
            self.assertFalse(math.isnan(float(f[IDX[name]])), name)

    def test_flow_statistics_are_used_rather_than_discarded(self):
        """CIC ships real Flow IAT Mean/Std/Max/Min -- they must reach the row."""
        f = extract_temporal(FLOW)
        self.assertAlmostEqual(float(f[IDX["iat_mean"]]), 0.5, places=5)
        self.assertAlmostEqual(float(f[IDX["iat_std"]]), 0.2, places=5)
        self.assertAlmostEqual(float(f[IDX["iat_min"]]), 0.1, places=5)
        self.assertAlmostEqual(float(f[IDX["iat_max"]]), 0.9, places=5)
        self.assertAlmostEqual(float(f[IDX["iat_cv"]]), 0.2 / 0.5, places=4)

    def test_sequence_features_stay_missing_even_with_flow_statistics(self):
        """A summary cannot produce a median, a skew or a burst count."""
        f = extract_temporal(FLOW)
        for name in SEQUENCE_ONLY_FEATURES:
            self.assertTrue(math.isnan(float(f[IDX[name]])),
                            f"{name} cannot be derived from a flow summary")

    def test_jitter_is_not_silently_treated_as_a_standard_deviation(self):
        """UNSW `sjit` is a mean deviation. Mapping it to iat_std would launder
        one statistic as another -- the same class of error as the fabrication.
        A mean-only session must leave iat_std missing."""
        f = extract_temporal(MEAN_ONLY)
        self.assertFalse(math.isnan(float(f[IDX["iat_mean"]])))
        for name in FLOW_STAT_FEATURES - {"iat_mean"}:
            self.assertTrue(math.isnan(float(f[IDX[name]])), name)


class TestValidatorCatchesFabrication(unittest.TestCase):
    """Arithmetic consistency must not be accepted as evidence of measurement."""

    def _row(self, sess):
        x = np.full(128, 0.5, dtype=np.float64)
        x[:24] = extract_temporal(sess)
        return x

    def test_a_consistent_fabrication_is_still_rejected(self):
        """THE test. A row that passes every arithmetic invariant, refused.

        Hand-build the old fabricated shape: 5 events, one uniform gap, so
        min == mean == median == max. Nothing about it is arithmetically wrong.
        """
        uniform = {**STREAM, "event_timestamps": [0.0, 2.5, 5.0, 7.5, 10.0]}
        X = np.vstack([self._row(uniform)])
        # arithmetic: perfectly fine
        lo, me, hi = (X[0, FEATURE_INDEX[k]] for k in ("iat_min", "iat_mean", "iat_max"))
        self.assertLessEqual(lo, me + 1e-9)
        self.assertLessEqual(me, hi + 1e-9)
        # provenance: and yet it is a single-valued IAT across 5 events
        self.assertTrue(degenerate_iat_mask(X)[0])
        self.assertTrue(fabricated_iat_mask(X)[0],
                        "a degenerate IAT over >2 events was not flagged")

    def test_a_genuine_two_event_session_is_not_flagged(self):
        """One gap legitimately makes min == mean == max. Must not false-positive."""
        two = {"t_start": 0.0, "t_end": 4.0, "n_events": 2, "n_commands": 1,
               "event_timestamps": [0.0, 4.0]}
        X = np.vstack([self._row(two)])
        self.assertTrue(degenerate_iat_mask(X)[0])
        self.assertFalse(fabricated_iat_mask(X)[0],
                         "a real one-gap session was called fabricated")

    def test_a_number_where_the_level_forbids_one_is_rejected(self):
        X = np.vstack([self._row(FLOW)])
        rep = validate_provenance(X, [PROV_FLOW_STATS])
        self.assertTrue(rep.ok, "a correctly-abstaining row was rejected")
        X[0, FEATURE_INDEX["iat_median"]] = 0.0        # pretend we measured it
        rep = validate_provenance(X, [PROV_FLOW_STATS])
        self.assertFalse(rep.ok)
        self.assertTrue(any(v.kind == "fabricated" for v in rep.violations))

    def test_a_missing_value_where_the_level_supports_one_is_rejected(self):
        """The other direction: claiming a stream but not having used it."""
        X = np.vstack([self._row(FLOW)])
        rep = validate_provenance(X, [PROV_EVENT_STREAM])
        self.assertFalse(rep.ok, "a row claiming a stream but full of NaN passed")

    def test_provenance_is_recoverable_from_the_nan_signature(self):
        """Lets any saved array be audited without threading a column through."""
        sessions = [STREAM, FLOW, MEAN_ONLY, NOTHING]
        X = np.vstack([self._row(s) for s in sessions])
        got = provenance_from_nan(X)
        want = [temporal_provenance(s) for s in sessions]
        self.assertEqual(list(got), want)
        self.assertNotIn("unknown", got,
                         "NaN counts no longer map 1:1 -- the contract changed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
