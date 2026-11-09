"""
traffic_gateway/tests/test_reputation_worst_case.py

HONEYPOT_AUDIT.md PART 3 fix #3 -- the last of the three.

Every signal in reputation_scorer used to be an average over the last 20
sessions, so one serious session was worth 5% of the score and vanished into
history. That made the scorer the weakest part of the whitelist backstop, and it
had the property the audit called out: **the longer an attacker behaved, the
safer they got**, because a longer clean history buried the session that mattered.

Each signal is now the worse of the long-window average and the worst single
session in a short recent window.

Three properties are tested, and the last two matter as much as the first:

  1. one serious session in a clean history raises the score (the fix);
  2. the all-clean floor and the sustained-attacker ceiling do NOT move (no
     recalibration, no new false positives);
  3. a spike AGES OUT, so whitelist_promoter can still rehabilitate an IP. A
     worst case over the full 50-session history would be permanently sticky and
     would quietly break promotion -- the subtle way to get this fix wrong.
"""
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_tmp = tempfile.mkdtemp()
import traffic_gateway.config as _cfg_mod
_cfg_mod.CONFIG.DATA_DIR = Path(_tmp) / "data"
_cfg_mod.CONFIG.LOG_DIR = Path(_tmp) / "logs"
_cfg_mod.CONFIG.DATA_DIR.mkdir(parents=True, exist_ok=True)
_cfg_mod.CONFIG.LOG_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(REPO_ROOT / "honeypot_dataset"))

from traffic_gateway import reputation_scorer as rs                 # noqa: E402
from traffic_gateway.config import CONFIG                           # noqa: E402
from traffic_gateway.session_tracker import session_tracker         # noqa: E402

# An ordinary user: big payloads, long sessions, low entropy, real backend.
CLEAN = dict(honeypot=False, nbytes=4000, dur=30.0, entropy=4.0)
# A scanner: tiny payloads, sub-second, high-entropy payload, sent to the decoy.
SERIOUS = dict(honeypot=True, nbytes=5, dur=0.2, entropy=7.8)

_counter = [0]


def _fresh_ip() -> str:
    _counter[0] += 1
    return f"10.77.{_counter[0] // 250}.{_counter[0] % 250 + 1}"


def _add(ip, *, honeypot, nbytes, dur, entropy):
    """Append one closed session with the given shape.

    The fields are set AFTER close_session on purpose: Session.close()
    recomputes entropy from payload_snip and duration from the clock, so setting
    them first is silently discarded. An earlier version of this test did exactly
    that and measured a smaller effect than the change really has.
    """
    s = session_tracker.open_session(ip, target="honeypot" if honeypot else "backend",
                                     target_addr="127.0.0.1:2222")
    session_tracker.close_session(s)
    s.bytes_in, s.entropy, s.duration_sec = nbytes, entropy, dur
    return s


def _averages_only(ip: str) -> float:
    """The old score: every signal from the long-window average, nothing else."""
    st = session_tracker.recent_stats(ip, n=rs.AVG_WINDOW)
    hist = session_tracker.get_history(ip)
    return rs._clamp(
        0.30 * rs._entropy_signal(st["avg_entropy"])
        + 0.20 * rs._volume_signal(st["avg_bytes_in"])
        + 0.20 * rs._honeypot_ratio_signal(st["honeypot_ratio"])
        + 0.15 * rs._duration_signal(st["avg_duration"])
        + 0.15 * rs._connection_frequency_signal(len(hist), st["sample_size"]))


class TestOneSeriousSessionIsNotDiluted(unittest.TestCase):

    def test_a_serious_session_in_a_clean_history_raises_the_score(self):
        ip = _fresh_ip()
        for _ in range(19):
            _add(ip, **CLEAN)
        _add(ip, **SERIOUS)

        old, (new, _r) = _averages_only(ip), rs.score_ip(ip)
        self.assertGreater(new, old + 0.2,
                           "one serious session must move the score materially, "
                           "not by a rounding error")

    def test_it_crosses_the_suspicious_threshold(self):
        """The point of the fix: the IP is flagged, not merely nudged."""
        ip = _fresh_ip()
        for _ in range(19):
            _add(ip, **CLEAN)
        _add(ip, **SERIOUS)
        new, _ = rs.score_ip(ip)
        self.assertGreaterEqual(new, CONFIG.SCORE_SUSPICIOUS)

    def test_it_blocks_automatic_promotion(self):
        """This is the harm the audit described: an attacker who behaved long
        enough was promoted to whitelisted despite a serious session."""
        ip = _fresh_ip()
        for _ in range(19):
            _add(ip, **CLEAN)
        _add(ip, **SERIOUS)
        new, _ = rs.score_ip(ip)
        self.assertGreater(new, CONFIG.SCORE_PROMOTE,
                           "a recent serious session must disqualify an IP from "
                           "automatic promotion to whitelisted")

    def test_a_longer_clean_history_no_longer_hides_it(self):
        """Directly the "the longer they behave, the safer they get" property.

        Asserts the score does not FALL as the clean history grows -- not that it
        is identical. Measured [0.542, 0.542, 0.5672] for 5 / 19 / 40 clean
        sessions: the slight rise at 40 is the connection-frequency signal, which
        counts total connections and legitimately grows with history. That is the
        opposite of the harm, so it is allowed; what must never happen is the
        serious session getting cheaper to hide.
        """
        scores = []
        for clean_count in (5, 19, 40):
            ip = _fresh_ip()
            for _ in range(clean_count):
                _add(ip, **CLEAN)
            _add(ip, **SERIOUS)
            scores.append(rs.score_ip(ip)[0])

        self.assertEqual(scores, sorted(scores),
                         f"a longer clean history must not lower the score: {scores}")
        for clean_count, score in zip((5, 19, 40), scores):
            with self.subTest(clean_sessions=clean_count):
                self.assertGreaterEqual(score, CONFIG.SCORE_SUSPICIOUS)


class TestCalibrationIsUnchanged(unittest.TestCase):
    """No recalibration and no new false positives -- the floor and the ceiling
    must be identical to the averages-only score."""

    def test_an_all_clean_history_is_unchanged(self):
        ip = _fresh_ip()
        for _ in range(20):
            _add(ip, **CLEAN)
        old, (new, _r) = _averages_only(ip), rs.score_ip(ip)
        self.assertAlmostEqual(old, new, places=6)

    def test_a_sustained_attacker_is_unchanged(self):
        ip = _fresh_ip()
        for _ in range(20):
            _add(ip, **SERIOUS)
        old, (new, _r) = _averages_only(ip), rs.score_ip(ip)
        self.assertAlmostEqual(old, new, places=6)

    def test_a_clean_history_stays_promotable(self):
        ip = _fresh_ip()
        for _ in range(20):
            _add(ip, **CLEAN)
        new, _ = rs.score_ip(ip)
        self.assertLess(new, CONFIG.SCORE_PROMOTE,
                        "an ordinary user must still be eligible for promotion")

    def test_no_history_is_still_neutral(self):
        score, reason = rs.score_ip(_fresh_ip())
        self.assertAlmostEqual(score, 0.5)
        self.assertIn("No session history", reason)

    def test_the_score_stays_in_range(self):
        for shape in (CLEAN, SERIOUS):
            with self.subTest(shape=shape):
                ip = _fresh_ip()
                for _ in range(25):
                    _add(ip, **shape)
                score, _ = rs.score_ip(ip)
                self.assertGreaterEqual(score, 0.0)
                self.assertLessEqual(score, 1.0)


class TestTheSpikeAgesOut(unittest.TestCase):
    """Rehabilitation must stay possible, or promotion silently stops working."""

    def test_a_spike_decays_after_the_short_window_rolls(self):
        ip = _fresh_ip()
        for _ in range(19):
            _add(ip, **CLEAN)
        _add(ip, **SERIOUS)
        spiked, _ = rs.score_ip(ip)

        for _ in range(rs.WORST_WINDOW + 1):
            _add(ip, **CLEAN)
        aged, _ = rs.score_ip(ip)

        self.assertLess(aged, spiked)
        self.assertLess(aged, CONFIG.SCORE_PROMOTE,
                        "once the spike has aged out the IP must be promotable "
                        "again, or whitelist_promoter can never rehabilitate it")

    def test_the_worst_window_is_short_enough_to_roll(self):
        """A worst case over the full history would never age out. Guards the
        constant itself, since that is the subtle way to break this."""
        self.assertLess(rs.WORST_WINDOW, rs.AVG_WINDOW)
        self.assertLessEqual(rs.WORST_WINDOW, 10)
        from traffic_gateway.session_tracker import SessionTracker
        self.assertLess(rs.WORST_WINDOW, SessionTracker.MAX_HISTORY_PER_IP)


class TestWorstRecentSignals(unittest.TestCase):

    def test_empty_input_cannot_raise_the_score(self):
        self.assertEqual(rs.worst_recent_signals([]),
                         {"entropy": 0.0, "volume": 0.0, "duration": 0.0})

    def test_it_takes_the_max_of_the_outputs_not_of_the_inputs(self):
        """Direction-agnostic by construction: high entropy is risky but LOW
        byte counts and SHORT durations are, so taking an extreme input per
        signal is easy to get backwards."""
        ip = _fresh_ip()
        _add(ip, **CLEAN)
        _add(ip, **SERIOUS)
        sessions = session_tracker.get_history(ip)
        worst = rs.worst_recent_signals(sessions)
        self.assertEqual(worst["entropy"], rs._entropy_signal(SERIOUS["entropy"]))
        self.assertEqual(worst["volume"], rs._volume_signal(SERIOUS["nbytes"]))
        self.assertEqual(worst["duration"], rs._duration_signal(SERIOUS["dur"]))

    def test_a_clean_only_window_matches_the_clean_signals(self):
        ip = _fresh_ip()
        _add(ip, **CLEAN)
        worst = rs.worst_recent_signals(session_tracker.get_history(ip))
        self.assertEqual(worst["entropy"], rs._entropy_signal(CLEAN["entropy"]))


class TestReasoningIsHonest(unittest.TestCase):
    """The audit log has to let an operator tell a sustained offender from one
    bad session in a clean history. The score alone cannot."""

    def test_it_names_the_signals_the_worst_case_raised(self):
        ip = _fresh_ip()
        for _ in range(19):
            _add(ip, **CLEAN)
        _add(ip, **SERIOUS)
        _score, reason = rs.score_ip(ip)
        self.assertIn("recent worst case raised", reason)

    def test_it_says_nothing_extra_when_nothing_spiked(self):
        ip = _fresh_ip()
        for _ in range(20):
            _add(ip, **CLEAN)
        _score, reason = rs.score_ip(ip)
        self.assertNotIn("recent worst case raised", reason)

    def test_it_reports_both_window_sizes(self):
        ip = _fresh_ip()
        for _ in range(8):
            _add(ip, **CLEAN)
        _score, reason = rs.score_ip(ip)
        self.assertIn("avg over", reason)
        self.assertIn("worst of last", reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
