"""
response_mitigation/tests/test_mitigation_policy.py

One test per row of the policy table, plus the boundaries. The key check is
test_divert_matches_todays_inline_blacklist: it rebuilds the condition from
traffic_gateway/post_session_pipeline.py and compares it across a grid.
"""
import math
import unittest

from response_mitigation.models import Action, Verdict
from response_mitigation.policy import PolicyConfig, plan


def verdict(phase=1, conf=0.9, sessions=1) -> Verdict:
    return Verdict(ip="45.33.32.156", phase=phase, phase_name=f"Phase{phase}",
                   micro_state="TEST_STATE", confidence=conf,
                   session_id="s1", sessions_seen=sessions)


def actions(v: Verdict, cfg: PolicyConfig = PolicyConfig()):
    return [p.action for p in plan(v, cfg)]


class TestPolicyRows(unittest.TestCase):

    def test_recon_is_only_observed(self):
        self.assertEqual(actions(verdict(phase=0, conf=0.99)), [Action.OBSERVE])

    def test_low_confidence_is_only_observed(self):
        planned = plan(verdict(phase=5, conf=0.3))
        self.assertEqual([p.action for p in planned], [Action.OBSERVE])
        self.assertIn("floor", planned[0].reason)

    def test_nan_confidence_is_only_observed(self):
        self.assertEqual(actions(verdict(phase=8, conf=math.nan, sessions=50)),
                         [Action.OBSERVE])

    def test_attack_is_diverted(self):
        for phase in (1, 2, 3, 6):
            with self.subTest(phase=phase):
                self.assertEqual(actions(verdict(phase=phase)), [Action.DIVERT])

    def test_late_stage_is_diverted_and_alerted(self):
        for phase in (7, 8):
            with self.subTest(phase=phase):
                self.assertEqual(actions(verdict(phase=phase)),
                                 [Action.DIVERT, Action.ALERT])

    def test_repeat_offender_is_also_denied(self):
        self.assertEqual(actions(verdict(phase=4, sessions=3)),
                         [Action.DIVERT, Action.DENY])

    def test_not_enough_sessions_is_not_denied(self):
        self.assertEqual(actions(verdict(phase=4, sessions=2)), [Action.DIVERT])

    def test_early_phase_is_not_denied_however_often_seen(self):
        self.assertEqual(actions(verdict(phase=3, sessions=100)), [Action.DIVERT])

    def test_everything_at_once_is_ordered_least_drastic_first(self):
        self.assertEqual(actions(verdict(phase=8, sessions=5)),
                         [Action.DIVERT, Action.ALERT, Action.DENY])

    def test_only_deny_has_a_lifetime(self):
        for p in plan(verdict(phase=8, sessions=5)):
            if p.action is Action.DENY:
                self.assertEqual(p.ttl_s, 24 * 3600)
            else:
                self.assertIsNone(p.ttl_s)

    def test_reason_names_the_micro_state_and_confidence(self):
        reason = plan(verdict(phase=2, conf=0.876))[0].reason
        self.assertIn("TEST_STATE", reason)
        self.assertIn("0.88", reason)

    def test_there_is_always_at_least_one_action(self):
        for phase in range(0, 9):
            for conf in (0.0, 0.5, 1.0, math.nan):
                with self.subTest(phase=phase, conf=conf):
                    self.assertTrue(plan(verdict(phase=phase, conf=conf)))


class TestPolicyBoundaries(unittest.TestCase):

    def test_confidence_floor_is_inclusive(self):
        self.assertEqual(actions(verdict(conf=0.5)), [Action.DIVERT])
        self.assertEqual(actions(verdict(conf=0.4999)), [Action.OBSERVE])

    def test_thresholds_can_be_changed(self):
        cfg = PolicyConfig(min_confidence=0.9, divert_min_phase=3,
                           alert_min_phase=5, deny_min_phase=6,
                           deny_repeat_sessions=2, deny_ttl_s=3600)
        self.assertEqual(actions(verdict(phase=2, conf=0.95), cfg), [Action.OBSERVE])
        self.assertEqual(actions(verdict(phase=3, conf=0.95), cfg), [Action.DIVERT])
        self.assertEqual(actions(verdict(phase=5, conf=0.95), cfg),
                         [Action.DIVERT, Action.ALERT])
        self.assertEqual(actions(verdict(phase=6, conf=0.95, sessions=2), cfg),
                         [Action.DIVERT, Action.ALERT, Action.DENY])
        self.assertEqual(actions(verdict(phase=6, conf=0.85, sessions=2), cfg),
                         [Action.OBSERVE])
        deny = [p for p in plan(verdict(phase=6, conf=0.95, sessions=2), cfg)
                if p.action is Action.DENY][0]
        self.assertEqual(deny.ttl_s, 3600)

    def test_bad_settings_raise(self):
        for kwargs in ({"min_confidence": 1.5}, {"min_confidence": -0.1},
                       {"divert_min_phase": 9}, {"alert_min_phase": -1},
                       {"deny_min_phase": 10}, {"deny_repeat_sessions": 0},
                       {"deny_ttl_s": 0}):
            with self.subTest(**kwargs):
                with self.assertRaises(ValueError):
                    PolicyConfig(**kwargs)


class TestSameAsToday(unittest.TestCase):

    def test_divert_matches_todays_inline_blacklist(self):
        """post_session_pipeline.py blacklists when
        phase >= MT3_AUTO_BLACKLIST_MIN_PHASE (1) and
        confidence >= MT3_AUTO_BLACKLIST_CONF (0.5). The policy must agree on
        every combination, so switching to it changes nothing."""
        min_phase, min_conf = 1, 0.5
        cfg = PolicyConfig(min_confidence=min_conf, divert_min_phase=min_phase)
        for phase in range(0, 9):
            for conf in (0.0, 0.2, 0.4999, 0.5, 0.5001, 0.9, 1.0):
                with self.subTest(phase=phase, conf=conf):
                    today = phase >= min_phase and conf >= min_conf
                    now = Action.DIVERT in actions(verdict(phase=phase, conf=conf), cfg)
                    self.assertEqual(now, today)


if __name__ == "__main__":
    unittest.main()
