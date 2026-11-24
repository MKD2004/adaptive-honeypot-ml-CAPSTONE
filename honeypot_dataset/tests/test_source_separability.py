"""
honeypot_dataset/tests/test_source_separability.py

`separability()` is the measurement every real-vs-generated claim in
DATA_INTEGRITY.md sections 12, 16 and 17 rests on, so its plumbing is checked
here on data whose answer is known by construction: identical distributions must
land near 0.50, a shifted one near 1.0.

The dataset-level control (a random half-split of real rows scoring 0.5040)
lives in the module itself and is the stronger check. These tests only catch the
ways the wiring can break silently -- labels swapped, columns ignored, a dead
column deciding a split.
"""
import sys
import unittest
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "honeypot_dataset"))

from src.validators.source_separability import separability          # noqa: E402


class TestSeparability(unittest.TestCase):
    def setUp(self):
        rng = np.random.RandomState(0)
        self.n = 1_000
        # rows 0..n-1 and n..2n-1 are drawn from the SAME distribution
        self.X = rng.normal(size=(2 * self.n, 6))
        self.a = np.arange(self.n)
        self.b = np.arange(self.n, 2 * self.n)

    def test_identical_distributions_score_near_chance(self):
        auc, n = separability(self.X, self.a, self.b, np.arange(6), cap=self.n)
        self.assertEqual(n, self.n)
        self.assertAlmostEqual(auc, 0.5, delta=0.08)

    def test_a_shifted_column_is_detected(self):
        X = self.X.copy()
        X[self.b, 2] += 8.0
        auc, _ = separability(X, self.a, self.b, np.arange(6), cap=self.n)
        self.assertGreater(auc, 0.95)

    def test_only_the_requested_columns_are_used(self):
        X = self.X.copy()
        X[self.b, 2] += 8.0                      # the giveaway is column 2
        auc, _ = separability(X, self.a, self.b, np.array([0, 1]), cap=self.n)
        self.assertAlmostEqual(auc, 0.5, delta=0.08)

    def test_an_all_constant_column_set_is_unmeasurable(self):
        X = np.zeros((2 * self.n, 3))
        auc, _ = separability(X, self.a, self.b, np.arange(3), cap=self.n)
        self.assertIsNone(auc)

    def test_a_side_too_small_reports_none_rather_than_a_number(self):
        auc, n = separability(self.X, self.a[:10], self.b, np.arange(6))
        self.assertIsNone(auc)
        self.assertEqual(n, 10)


if __name__ == "__main__":
    unittest.main()
