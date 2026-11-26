"""
honeypot_dataset/tests/test_sufficient_support.py

The `sufficient_support` block in classification_metrics (DATA_INTEGRITY.md
section 23). It reports macro-F1 over classes with enough real sessions to
measure, which is only defensible because the threshold comes from a confidence
interval rather than from the results -- so what is tested here is that the
subset is chosen by SUPPORT and nothing else, and that the unrestricted number
never disappears.
"""
import sys
import unittest
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ml_analytics.mt3_pipeline.metrics import (                     # noqa: E402
    MIN_SUPPORT_CI10, classification_metrics,
)


def _y(counts):
    """counts = {class: n_rows} -> y_true."""
    return np.concatenate([np.full(n, c, dtype=np.int64) for c, n in counts.items()])


class TestSufficientSupport(unittest.TestCase):
    def test_threshold_is_the_ci_formula(self):
        # 95% CI half-width 0.10 at the worst case p=0.5
        self.assertEqual(MIN_SUPPORT_CI10,
                         int(np.ceil(0.25 * (1.96 / 0.10) ** 2)))

    def test_it_selects_on_support_not_on_score(self):
        # class 0: big and PERFECTLY WRONG. class 1: tiny and perfect.
        # a subset chosen by score would keep class 1 and drop class 0.
        y = _y({0: 500, 1: 10})
        p = np.concatenate([np.full(500, 1), np.full(10, 1)])
        ss = classification_metrics(y, p, include_confusion=False)["sufficient_support"]
        self.assertEqual(ss["classes"], [n for n in ss["classes"]])
        self.assertEqual(ss["n_classes"], 1)
        self.assertIn(10, ss["excluded"].values(), "the tiny class must be excluded")
        self.assertAlmostEqual(ss["macro_f1"], 0.0, places=6,
                               msg="keeping a big class the model fails is the point")

    def test_unrestricted_macro_f1_is_still_reported(self):
        y = _y({0: 500, 1: 10})
        p = y.copy()
        m = classification_metrics(y, p, include_confusion=False)
        self.assertIn("macro_f1", m)
        self.assertIn("sufficient_support", m)
        self.assertEqual(m["n_classes_present"], 2)
        self.assertEqual(m["sufficient_support"]["n_classes"], 1)

    def test_coverage_is_the_share_of_rows_kept(self):
        y = _y({0: 900, 1: 100, 2: 5})
        m = classification_metrics(y, y.copy(), include_confusion=False)
        ss = m["sufficient_support"]
        self.assertEqual(ss["n_classes"], 2)           # 900 and 100 survive, 5 does not
        self.assertAlmostEqual(ss["coverage"], 1000 / 1005, places=4)

    def test_every_excluded_class_is_named_with_its_support(self):
        y = _y({0: 500, 1: 12, 2: 3})
        m = classification_metrics(y, y.copy(), include_confusion=False)
        self.assertEqual(sorted(m["sufficient_support"]["excluded"].values()), [3, 12])

    def test_absent_when_no_class_clears_the_bar(self):
        y = _y({0: 10, 1: 10})
        m = classification_metrics(y, y.copy(), include_confusion=False)
        self.assertNotIn("sufficient_support", m,
                         "reporting an empty subset would be worse than omitting it")


if __name__ == "__main__":
    unittest.main()
