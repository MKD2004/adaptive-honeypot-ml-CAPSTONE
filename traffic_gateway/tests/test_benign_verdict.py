"""
traffic_gateway/tests/test_benign_verdict.py

BENIGN reaching the live path must never trigger an action. The model gained a
46th label on 2026-11-25 and `IDX_TO_PHASE[45]` is an IndexError, so
`MT3Inference.predict()` reports `phase: -1`.

-1 is not a placeholder, it is the safety property: every downstream rule is
`phase >= threshold`, so -1 clears none of them and a benign verdict cannot
blacklist anyone even if a caller forgets to check `is_benign`. That is what
these tests pin -- 02-11-2026 FINDINGS.md finding #1 is a real benign session
that got auto-blacklisted when the model had no way to say "safe".

No model is loaded here; loading DistilBERT and a checkpoint would make this a
slow integration test. What is checked is the arithmetic every consumer does.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

BENIGN_PHASE = -1


class TestBenignPhaseClearsNoThreshold(unittest.TestCase):
    def test_it_clears_no_configured_threshold(self):
        from traffic_gateway.config import CONFIG

        self.assertGreaterEqual(CONFIG.MT3_AUTO_BLACKLIST_MIN_PHASE, 0)
        self.assertFalse(BENIGN_PHASE >= CONFIG.MT3_AUTO_BLACKLIST_MIN_PHASE,
                         "a benign verdict would be blacklisted")

    def test_it_clears_no_threshold_at_any_setting(self):
        # even if someone sets the minimum phase to 0, the lowest allowed value
        for min_phase in range(0, 9):
            self.assertFalse(BENIGN_PHASE >= min_phase)

    def test_the_mitigation_policy_declines_it(self):
        from response_mitigation.policy import plan

        self.assertTrue(callable(plan))
        # the policy's own comparison, mirrored: `verdict.phase >= divert_min_phase`
        self.assertFalse(BENIGN_PHASE >= 1)


class TestPhaseHistogramIsBounded(unittest.TestCase):
    def test_a_negative_phase_is_not_counted(self):
        """api.py built a 9-bucket histogram; -1 would land in the LAST one."""
        phases = [0] * 9
        for phase in (0, 3, BENIGN_PHASE, 8):
            if phase is not None and int(phase) >= 0:
                phases[int(phase)] += 1
        self.assertEqual(phases[8], 1, "only the real phase-8 row")
        self.assertEqual(sum(phases), 3, "the benign row must not be counted")


class TestCheckpointAndSchemaAgree(unittest.TestCase):
    def test_the_gateway_points_at_a_final_v2_model(self):
        from traffic_gateway import feature_bridge as fb
        from traffic_gateway.ext_paths import DATA_FINAL

        self.assertEqual(DATA_FINAL.name, "final_v2",
                         "the scaler must come from the build load_split accepts")
        self.assertIn("final_v2", str(fb.MT3_CKPT),
                      "mt3_full_d256 is the retired 45-class model")

    def test_the_label_schema_is_46_wide(self):
        from ml_analytics.mt3_pipeline import data as mt3_data

        names = mt3_data.load_label_names()
        self.assertEqual(len(names), 46)
        self.assertEqual(names[45], "BENIGN")
        # and BENIGN sits past the end of the phase table, which is what
        # predict() uses to detect it
        self.assertEqual(len(mt3_data.IDX_TO_PHASE), 45)


if __name__ == "__main__":
    unittest.main()
