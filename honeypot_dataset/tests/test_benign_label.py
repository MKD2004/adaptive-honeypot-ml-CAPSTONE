"""
honeypot_dataset/tests/test_benign_label.py

BENIGN is label 45 and deliberately NOT a 46th micro-state. The distinction is
load-bearing: `IDX_TO_PHASE`, `KILL_CHAIN_DAG` and every phase lookup are keyed
on the 45 kill-chain states, and BENIGN has no technique, no phase and no DAG
edges. Adding it to `MICRO_STATES` would look harmless and would quietly give
the kill-chain a 46th node.

The second half guards the gate: `ml_analytics/mt3_pipeline/data.py` rejected a
dataset carrying label 45 until 2026-11-25, which is how the closed set stayed
closed. That bound must admit 45 and still reject 46.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "honeypot_dataset"))
sys.path.insert(0, str(REPO_ROOT))

from configs import schema                                          # noqa: E402


class TestBenignLabel(unittest.TestCase):
    def test_benign_is_not_a_micro_state(self):
        labels = [s["label"] for s in schema.MICRO_STATES]
        self.assertNotIn(schema.BENIGN_LABEL, labels)
        self.assertEqual(len(schema.MICRO_STATES), schema.N_CLASSES)

    def test_benign_sits_one_past_the_kill_chain(self):
        self.assertEqual(schema.BENIGN_IDX, schema.N_CLASSES)
        self.assertEqual(schema.N_LABELS, schema.N_CLASSES + 1)

    def test_benign_has_no_phase_and_no_dag_edges(self):
        self.assertNotIn(schema.BENIGN_IDX, schema.IDX_TO_PHASE)
        self.assertNotIn(schema.BENIGN_IDX, schema.KILL_CHAIN_DAG)
        for src, dsts in schema.KILL_CHAIN_DAG.items():
            self.assertNotIn(schema.BENIGN_IDX, dsts,
                             f"state {src} has an edge to BENIGN")

    def test_the_benign_aware_maps_extend_rather_than_replace(self):
        self.assertEqual(len(schema.IDX_TO_LABEL_WITH_BENIGN), schema.N_LABELS)
        self.assertEqual(schema.IDX_TO_LABEL_WITH_BENIGN[schema.BENIGN_IDX],
                         schema.BENIGN_LABEL)
        for idx, label in schema.IDX_TO_LABEL.items():
            self.assertEqual(schema.IDX_TO_LABEL_WITH_BENIGN[idx], label)
        self.assertEqual(schema.LABEL_TO_IDX_WITH_BENIGN[schema.BENIGN_LABEL],
                         schema.BENIGN_IDX)


class TestGateAcceptsBenign(unittest.TestCase):
    """The label-range bound in the training entry point."""

    def test_the_bound_admits_45_and_rejects_46(self):
        from ml_analytics.mt3_pipeline import data as mt3_data

        self.assertEqual(mt3_data.N_LABELS, 46)
        # the check in _validate is `y.max() >= N_LABELS`
        self.assertFalse(45 >= mt3_data.N_LABELS, "BENIGN would still be rejected")
        self.assertTrue(46 >= mt3_data.N_LABELS, "an out-of-range label would pass")

    def test_label_names_cover_every_label_and_end_with_benign(self):
        from ml_analytics.mt3_pipeline import data as mt3_data

        names = mt3_data.load_label_names()
        self.assertEqual(len(names), mt3_data.N_LABELS)
        self.assertEqual(names[schema.BENIGN_IDX], schema.BENIGN_LABEL)


if __name__ == "__main__":
    unittest.main()
