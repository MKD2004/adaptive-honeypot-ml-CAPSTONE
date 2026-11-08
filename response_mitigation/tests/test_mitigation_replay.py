"""
response_mitigation/tests/test_mitigation_replay.py

Replaying recorded sessions through the policy, and scoring it against labels. The numbers in these
tests are small enough to work out by hand.
"""
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from response_mitigation.replay import format_report, read_labels, read_results, replay

T0 = dt.datetime(2026, 11, 2, 8, 0, 0, tzinfo=dt.timezone.utc)
ATTACKER, ATTACKER_2, BENIGN, BENIGN_2, STRANGER = "45.33.32.156", "45.33.32.157", "8.8.8.8", "1.1.1.1", "9.9.9.9"
_n = [0]


def row(ip, phase, conf=0.9, minutes=0.0, state="SOME_STATE"):
    _n[0] += 1
    return {"session_id": f"s{_n[0]}", "src_ip": ip, "processed_at": (T0 + dt.timedelta(minutes=minutes)).isoformat(),
            "mt3_prediction": {"phase": phase, "phase_name": "Phase", "micro_state": state, "confidence": conf}}


def attacker_sessions(ip, count=3, phase=5, start=0.0, gap=1.0):
    return [row(ip, phase, minutes=start + i * gap) for i in range(count)]


class TestWhatTheReplayDoes(unittest.TestCase):

    def test_observe_mode_reports_what_would_happen_and_blocks_nothing(self):
        report = replay(attacker_sessions(ATTACKER), mode="observe")
        self.assertEqual(report["decisions"]["deny/would_apply"], 1)
        self.assertEqual(report["sources_acted_on"]["deny"], [ATTACKER])
        self.assertEqual(report["blocks_still_active_at_the_end"], 0)

    def test_enforce_with_the_firewall_really_blocks_in_the_temporary_list(self):
        report = replay(attacker_sessions(ATTACKER), mode="enforce", firewall=True)
        self.assertEqual(report["decisions"]["deny/applied"], 1)
        self.assertEqual(report["blocks_still_active_at_the_end"], 1)

    def test_a_quiet_source_is_left_alone(self):
        report = replay([row(BENIGN, 0, 0.99)] * 1)
        self.assertEqual(report["sources_acted_on"], {})
        self.assertEqual(report["decisions"], {"observe/applied": 1})

    def test_late_stage_sessions_raise_an_alert(self):
        report = replay([row(ATTACKER, 7)], mode="enforce")
        self.assertEqual(report["sources_acted_on"]["alert"], [ATTACKER])

    def test_off_mode_does_nothing_at_all(self):
        # replay only offers observe and enforce, but the settings can still say off
        report = replay(attacker_sessions(ATTACKER), mode="off")
        self.assertEqual(report["decisions"], {})

    def test_addresses_that_must_not_be_blocked_are_reported_as_skipped(self):
        rows = attacker_sessions("10.0.0.7") + attacker_sessions("172.17.0.1") + attacker_sessions("127.0.0.1")
        report = replay(rows, mode="enforce", firewall=True)
        self.assertNotIn("deny", report["sources_acted_on"])
        self.assertTrue(any(r["action"] == "deny" and "public unicast" in r["why"] for r in report["skipped_because"]))
        self.assertTrue(any("Docker" in r["why"] for r in report["skipped_because"]))

    def test_the_never_block_list_applies(self):
        report = replay(attacker_sessions(ATTACKER), mode="enforce", firewall=True,
                        env={"MITIGATION_NEVER_BLOCK": "45.33.32.0/24"})
        self.assertNotIn("deny", report["sources_acted_on"])
        self.assertTrue(any("never-block" in r["why"] for r in report["skipped_because"]))

    def test_a_trusted_source_is_not_acted_on_for_a_weak_verdict(self):
        """Changed 2026-11-04 with the whitelist-override fix.

        This used to pass a phase-3 verdict and assert the whitelist protected it.
        A phase-3 verdict is now strong enough to override trust for DIVERT (the
        PART 3 bypass fix), so the weak case is tested with the override floors
        raised out of reach, and the strong case gets its own test below.
        """
        report = replay([row(BENIGN, 3)], whitelist=[BENIGN],
                        env={"MITIGATION_WHITELIST_OVERRIDE_MIN_PHASE": "8",
                             "MITIGATION_WHITELIST_OVERRIDE_MIN_CONF": "1.0"})
        self.assertEqual(report["sources_acted_on"], {})
        self.assertTrue(any(r["why"] == "whitelisted" for r in report["skipped_because"]))

    def test_a_strong_verdict_overrides_trust_in_the_replay_too(self):
        report = replay([row(BENIGN, 3)], whitelist=[BENIGN])
        self.assertIn("divert", report["sources_acted_on"],
                      "a strong verdict must override a whitelist for DIVERT")

    def test_policy_settings_can_be_changed(self):
        rows = attacker_sessions(ATTACKER, count=2)
        self.assertNotIn("deny", replay(rows)["sources_acted_on"])                       # needs 3 sessions by default
        self.assertIn("deny", replay(rows, env={"MITIGATION_DENY_REPEAT_SESSIONS": "2"})["sources_acted_on"])


class TestSimulatedTime(unittest.TestCase):
    """The hourly cap and the block time follow the recorded clock, not how fast the replay runs."""

    def test_the_hourly_cap_binds_when_everything_happens_in_one_hour(self):
        rows = [r for k in range(5) for r in attacker_sessions(f"45.33.33.{k + 1}", start=k * 5)]
        report = replay(rows, mode="enforce", firewall=True, env={"MITIGATION_MAX_NEW_BLOCKS_PER_HOUR": "2"})
        self.assertEqual(report["decisions"]["deny/applied"], 2)
        self.assertTrue(any("hourly cap" in r["why"] for r in report["skipped_because"]))

    def test_the_same_sessions_spread_over_hours_are_all_blocked(self):
        rows = [r for k in range(5) for r in attacker_sessions(f"45.33.33.{k + 1}", start=k * 90)]
        report = replay(rows, mode="enforce", firewall=True, env={"MITIGATION_MAX_NEW_BLOCKS_PER_HOUR": "2"})
        self.assertEqual(report["decisions"]["deny/applied"], 5)

    def test_a_block_expires_and_a_returning_attacker_is_blocked_again(self):
        rows = attacker_sessions(ATTACKER) + [row(ATTACKER, 5, minutes=180)]              # 3 hours later
        report = replay(rows, mode="enforce", firewall=True, env={"MITIGATION_DENY_TTL_HOURS": "1"})
        self.assertEqual(report["decisions"]["deny/applied"], 2)
        self.assertEqual(report["blocks_still_active_at_the_end"], 1)

    def test_a_block_still_in_force_is_not_repeated(self):
        rows = attacker_sessions(ATTACKER) + [row(ATTACKER, 5, minutes=60)]
        report = replay(rows, mode="enforce", firewall=True)                              # 24 h block
        self.assertEqual(report["decisions"]["deny/applied"], 1)
        self.assertTrue(any("already on the block list" in r["why"] for r in report["skipped_because"]))

    def test_lines_without_a_time_still_replay_in_order(self):
        rows = attacker_sessions(ATTACKER)
        for r in rows:
            del r["processed_at"]
        self.assertEqual(replay(rows, mode="enforce", firewall=True)["decisions"]["deny/applied"], 1)


class TestScoring(unittest.TestCase):

    def setUp(self):
        self.rows = (attacker_sessions(ATTACKER) + attacker_sessions(ATTACKER_2, phase=3, count=1)
                     + [row(BENIGN, 0, 0.99)]                                    # quiet: left alone (TN)
                     + [row(BENIGN_2, 3, 0.9)]                                   # looks like an attack: diverted (FP)
                     + [row(STRANGER, 3, 0.9)])                                  # nobody labelled it
        self.labels = {ATTACKER: "attack", ATTACKER_2: "attack", BENIGN: "benign", BENIGN_2: "benign"}

    def test_the_counts_work_out_by_hand(self):
        report = replay(self.rows, mode="enforce", firewall=True, labels=self.labels)
        self.assertEqual(report["labelled_sources"], {"attack": 2, "benign": 2, "unlabelled": 1})
        divert = report["scores"]["divert"]
        # diverted: ATTACKER, ATTACKER_2 (true), BENIGN_2 (wrong); BENIGN left alone
        self.assertEqual((divert["tp"], divert["fp"], divert["fn"], divert["tn"]), (2, 1, 0, 1))
        self.assertEqual((divert["precision"], divert["recall"], divert["false_positive_rate"]), (0.6667, 1.0, 0.5))
        self.assertEqual(divert["benign_sources_hit"], [BENIGN_2])
        deny = report["scores"]["deny"]
        # blocked at the firewall: only ATTACKER (3 sessions at phase 5)
        self.assertEqual((deny["tp"], deny["fp"], deny["fn"], deny["tn"]), (1, 0, 1, 2))
        self.assertEqual((deny["precision"], deny["recall"], deny["false_positive_rate"]), (1.0, 0.5, 0.0))

    def test_unlabelled_sources_are_not_counted_either_way(self):
        report = replay(self.rows, labels=self.labels)
        total = sum(report["scores"]["divert"][k] for k in ("tp", "fp", "fn", "tn"))
        self.assertEqual(total, 4)

    def test_nothing_to_divide_gives_none_not_a_crash(self):
        report = replay([row(BENIGN, 0, 0.99)], labels={BENIGN: "benign"})
        self.assertIsNone(report["scores"]["deny"]["precision"])
        self.assertEqual(report["scores"]["deny"]["false_positive_rate"], 0.0)

    def test_in_observe_mode_would_apply_counts_as_acting(self):
        report = replay(self.rows, mode="observe", labels=self.labels)
        self.assertEqual(report["scores"]["deny"]["tp"], 1)

    def test_no_labels_means_no_scores(self):
        self.assertNotIn("scores", replay(self.rows))

    def test_the_report_in_words(self):
        text = format_report(replay(self.rows, mode="enforce", firewall=True, labels=self.labels))
        for part in ("Replayed", "sent to the honeypot", "blocked at the firewall", "false-positive rate 50.0%",
                     "benign sources hit: " + BENIGN_2, "2 attack, 2 benign, 1 unlabelled"):
            self.assertIn(part, text)


class TestReadingTheInput(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def test_unusable_lines_are_counted_and_skipped(self):
        path = self.dir / "r.jsonl"
        good = json.dumps(row(ATTACKER, 3))
        path.write_text("\n".join([good, "not json", "{}", json.dumps({"src_ip": "1.2.3.4"}),
                                   json.dumps({"src_ip": 5, "mt3_prediction": {"phase": 1, "confidence": 1}}),
                                   json.dumps({"src_ip": "1.2.3.4", "mt3_prediction": {"phase": "x", "confidence": 1}}),
                                   "", good]), encoding="utf-8")
        rows, skipped = read_results(path)
        self.assertEqual((len(rows), skipped), (2, 5))

    def test_labels_are_checked(self):
        path = self.dir / "l.json"
        path.write_text(json.dumps({"45.33.32.156": "attack", "::ffff:8.8.8.8": "benign"}), encoding="utf-8")
        self.assertEqual(read_labels(path), {"45.33.32.156": "attack", "8.8.8.8": "benign"})
        for bad in ({"45.33.32.156": "atack"}, {"nope": "attack"}, ["45.33.32.156"], {"45.33.32.156": True}):
            path.write_text(json.dumps(bad), encoding="utf-8")
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                read_labels(path)

    def test_a_replay_leaves_nothing_behind(self):
        before = sorted(p.name for p in Path(tempfile.gettempdir()).glob("mitigation-replay-*"))
        replay(attacker_sessions(ATTACKER), mode="enforce", firewall=True)
        self.assertEqual(sorted(p.name for p in Path(tempfile.gettempdir()).glob("mitigation-replay-*")), before)


if __name__ == "__main__":
    unittest.main()
