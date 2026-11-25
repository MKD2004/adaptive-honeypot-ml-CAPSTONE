"""
honeypot_dataset/tests/test_report_donor.py

The paired-by-class donor comparison (DATA_INTEGRITY.md section 22). Its reason
for existing is that a POOLED per-donor score measures class composition rather
than timing quality, so the test that matters is that the paired statistic stays
immune to a composition shift a pooled one would fall for.
"""
import sys
import unittest
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ml_analytics.mt3_pipeline.report_donor import (                # noqa: E402
    paired_by_class, pooled_by_origin,
)


def _case(n_per=200):
    """Class 0 is perfect under both origins; class 1 fails only under per_event."""
    y, d, p = [], [], []
    for cls, (ok_bucket, ok_event) in {0: (1.0, 1.0), 1: (1.0, 0.0)}.items():
        for origin, frac in (("donor_bucket", ok_bucket), ("per_event", ok_event)):
            for i in range(n_per):
                y.append(cls)
                d.append(origin)
                p.append(cls if i < int(frac * n_per) else (cls + 1) % 2)
    return np.array(y), np.array(p), np.array(d)


class TestPaired(unittest.TestCase):
    def test_it_finds_the_class_that_only_fails_under_per_event(self):
        y, p, d = _case()
        out = paired_by_class(y, p, d)
        per = {r["class"]: r for r in out["per_class"]}
        self.assertEqual(out["summary"]["n_classes_paired"], 2)
        deltas = sorted(r["delta"] for r in out["per_class"])
        self.assertAlmostEqual(deltas[0], 0.0, places=6)   # the healthy class
        self.assertAlmostEqual(deltas[1], 1.0, places=6)   # the broken one
        self.assertEqual(out["summary"]["classes_where_donor_bucket_wins"], 1)

    def test_a_class_present_in_only_one_origin_is_excluded(self):
        y, p, d = _case()
        # strip class 1's per_event rows entirely
        keep = ~((y == 1) & (d == "per_event"))
        out = paired_by_class(y[keep], p[keep], d[keep])
        self.assertEqual(out["summary"]["n_classes_paired"], 1,
                         "an unpairable class must not be reported as paired")

    def test_min_rows_is_enforced(self):
        y, p, d = _case(n_per=50)
        self.assertEqual(paired_by_class(y, p, d, min_rows=100)
                         ["summary"]["n_classes_paired"], 0)
        self.assertEqual(paired_by_class(y, p, d, min_rows=10)
                         ["summary"]["n_classes_paired"], 2)

    def test_the_paired_statistic_survives_a_composition_shift(self):
        """The whole point: pooled moves with the class mix, paired does not."""
        y, p, d = _case()
        # flood per_event with easy class-0 rows -- a pooled score now looks
        # BETTER for per_event even though nothing about either class changed
        extra_n = 2_000
        y2 = np.concatenate([y, np.zeros(extra_n, dtype=y.dtype)])
        p2 = np.concatenate([p, np.zeros(extra_n, dtype=p.dtype)])
        d2 = np.concatenate([d, np.array(["per_event"] * extra_n)])

        before = pooled_by_origin(y, p, d)["per_event"]["accuracy"]
        after = pooled_by_origin(y2, p2, d2)["per_event"]["accuracy"]
        self.assertGreater(after, before + 0.2, "composition should move pooled")

        self.assertEqual(paired_by_class(y, p, d)["summary"]["mean_delta"],
                         paired_by_class(y2, p2, d2)["summary"]["mean_delta"],
                         "paired recall must not move with the class mix")


if __name__ == "__main__":
    unittest.main()
