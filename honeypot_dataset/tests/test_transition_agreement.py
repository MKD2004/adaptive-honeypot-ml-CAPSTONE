"""
honeypot_dataset/tests/test_transition_agreement.py

The observed-transition record (DATA_INTEGRITY.md section 20). Its whole job is
to report a disagreement faithfully, so the cases that matter are the ones where
a careless implementation would hide one: a self-loop scored against a DAG that
has no self-edges, a single-state walk counted as compliance, and a backward
phase step filed as an ordinary missing edge.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "honeypot_dataset"))

from src.validators.transition_agreement import (                   # noqa: E402
    agreement, observed_transitions,
)


class TestObservedTransitions(unittest.TestCase):
    def test_single_state_walks_are_not_transitions(self):
        trans, stats = observed_transitions(["ACCESS_BRUTE_SSH", "RECON_IP_SCAN"])
        self.assertEqual(len(trans), 0)
        self.assertEqual(stats["sequences_single_state"], 2)
        self.assertEqual(stats["sequences_multi_state"], 0)

    def test_self_loops_are_counted_apart_not_dropped(self):
        trans, stats = observed_transitions(
            ["EXEC_SHELL_OPEN,EXEC_SHELL_OPEN,EXEC_SHELL_OPEN"])
        self.assertEqual(len(trans), 0, "a self-loop is not a transition")
        self.assertEqual(stats["self_loop"], 2)
        self.assertEqual(stats["sequences_multi_state"], 1)

    def test_transitions_are_counted_per_adjacent_pair(self):
        trans, _ = observed_transitions(
            ["ACCESS_BRUTE_SSH,DISC_ENV_PROBE"] * 3
            + ["ACCESS_BRUTE_SSH,EXEC_SHELL_OPEN"])
        self.assertEqual(trans[("ACCESS_BRUTE_SSH", "DISC_ENV_PROBE")], 3)
        self.assertEqual(trans[("ACCESS_BRUTE_SSH", "EXEC_SHELL_OPEN")], 1)


class TestAgreement(unittest.TestCase):
    def setUp(self):
        trans, _ = observed_transitions(
            ["ACCESS_BRUTE_SSH,DISC_ENV_PROBE"] * 10       # 1->3, forbidden skip
            + ["ACCESS_BRUTE_SSH,EXEC_SHELL_OPEN"] * 5     # 1->2, permitted
            + ["EXFIL_SCP_DATA,PRIVESC_SUDO_ABUSE"])       # 8->4, backward
        self.rep = agreement(trans)
        self.by_pair = {(e["from"], e["to"]): e for e in self.rep["edges"]}

    def test_instance_weighting_is_not_edge_weighting(self):
        # 5 of 16 instances permitted, but 1 of 3 edge types
        self.assertAlmostEqual(self.rep["agreement_by_instance"], 5 / 16, places=4)
        self.assertAlmostEqual(self.rep["agreement_by_edge_type"], 1 / 3, places=4)

    def test_a_forbidden_forward_skip_is_labelled_as_such(self):
        e = self.by_pair[("ACCESS_BRUTE_SSH", "DISC_ENV_PROBE")]
        self.assertFalse(e["in_dag"])
        self.assertEqual(e["kind"], "forward_skip")
        self.assertEqual(e["phase_delta"], 2)

    def test_a_backward_step_is_distinguished_from_a_missing_edge(self):
        e = self.by_pair[("EXFIL_SCP_DATA", "PRIVESC_SUDO_ABUSE")]
        self.assertFalse(e["in_dag"])
        self.assertEqual(e["kind"], "backward")
        self.assertLess(e["phase_delta"], 0)

    def test_a_permitted_edge_is_reported_permitted(self):
        self.assertTrue(self.by_pair[("ACCESS_BRUTE_SSH", "EXEC_SHELL_OPEN")]["in_dag"])

    def test_dag_coverage_counts_the_other_direction(self):
        # only 1 DAG edge type is exercised by this tiny sample
        self.assertEqual(self.rep["dag_edge_types_ever_observed"], 1)
        self.assertGreater(self.rep["dag_edge_types"], 1)
        self.assertLess(self.rep["dag_coverage"], 0.05)

    def test_instances_by_kind_sums_to_every_instance(self):
        self.assertEqual(sum(self.rep["instances_by_kind"].values()),
                         self.rep["observed_instances"])


if __name__ == "__main__":
    unittest.main()
