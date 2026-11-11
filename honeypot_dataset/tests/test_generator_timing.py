"""
honeypot_dataset/tests/test_generator_timing.py

Guards the event-timing model in `kill_chain_simulator`.

WHY THIS FILE EXISTS. Until 2026-11-09 the generator emitted `t_start`, `t_end`
and `n_events` but no per-event timestamps. `extractors/temporal.py` falls back to
a single synthetic inter-arrival time when `event_timestamps` has fewer than two
entries, and one value has no spread, no shape and no runs -- so seven of the 24
temporal features were constants across the entire frozen training set:

    burst_count          99.6% zero,   2 distinct values in 18,900 rows
    burst_mean_size      99.6% zero,   2 distinct
    frac_sub100ms        99.6% zero,   2 distinct
    iat_cv               98.2% zero
    iat_skew             98.3% zero
    iat_kurt             98.4% zero
    inter_burst_gap_std  98.2% zero

The LSTM branch learned nothing from them, and on the first real capture they were
all non-zero -- most of why real sessions sat 226x outside the training
distribution. See docs/REAL_DATA_2026-11-09.md.

`test_the_seven_formerly_dead_features_are_alive` is the regression guard. If it
ever fails, the generator has gone back to emitting timing that carries no
information, and retraining on its output would waste the run.
"""
import sys
import unittest
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "honeypot_dataset"))

from src.extractors.temporal import (                      # noqa: E402
    TEMPORAL_FEATURE_NAMES, extract_temporal)
from src.generators.kill_chain_simulator import (           # noqa: E402
    EVENTS_CEILING, IDLE_BUDGET, generate_balanced_sessions,
    generate_event_timestamps, _idle_probability)

IDX = {n: i for i, n in enumerate(TEMPORAL_FEATURE_NAMES)}

# The seven that were dead. Order follows the docstring table.
FORMERLY_DEAD = ["burst_count", "burst_mean_size", "frac_sub100ms",
                 "iat_cv", "iat_skew", "iat_kurt", "inter_burst_gap_std"]


class TestTimestampSeries(unittest.TestCase):
    """Properties of one generated series, independent of the calibration."""

    def setUp(self):
        import random
        self.rng = random.Random(4242)

    def test_it_returns_one_timestamp_per_event(self):
        for n in (2, 3, 8, 41, 64):
            with self.subTest(n_events=n):
                ts = generate_event_timestamps(1_700_000_000.0, n, 30.0, self.rng)
                self.assertEqual(len(ts), n)

    def test_the_series_never_goes_backwards(self):
        for _ in range(200):
            n = self.rng.randint(2, 64)
            ts = generate_event_timestamps(1_700_000_000.0, n,
                                           self.rng.uniform(0.5, 500.0), self.rng)
            self.assertTrue(all(b >= a for a, b in zip(ts, ts[1:])),
                            "timestamps must be ascending")

    def test_the_duration_is_preserved_exactly(self):
        """The whole design rests on this: session_duration_s,
        log_session_duration, events_per_sec and commands_per_min already use the
        duration, so generating timestamps must not move it."""
        for dur in (0.1, 2.13, 63.6, 812.0):
            for n in (2, 9, 64):
                with self.subTest(duration=dur, n_events=n):
                    ts = generate_event_timestamps(1_700_000_000.0, n, dur, self.rng)
                    self.assertAlmostEqual(ts[-1] - ts[0], dur, places=6)

    def test_a_single_event_session_is_a_single_timestamp(self):
        """No gaps exist, so no duration can be represented. Correct, not a bug --
        and the reason a t_end check must skip n_events == 1."""
        ts = generate_event_timestamps(1_700_000_000.0, 1, 99.0, self.rng)
        self.assertEqual(ts, [1_700_000_000.0])

    def test_it_survives_a_degenerate_duration(self):
        for dur in (0.0, -1.0, 1e-9):
            with self.subTest(duration=dur):
                ts = generate_event_timestamps(1_700_000_000.0, 10, dur, self.rng)
                self.assertEqual(len(ts), 10)
                self.assertTrue(all(b >= a for a, b in zip(ts, ts[1:])))

    def test_long_pauses_cannot_eat_the_whole_session(self):
        """Capped at IDLE_BUDGET so the slow gaps keep room and the walk stays
        increasing."""
        self.assertLess(IDLE_BUDGET, 1.0)
        for _ in range(100):
            ts = generate_event_timestamps(0.0, 40, 100.0, self.rng)
            gaps = np.diff(np.array(ts))
            self.assertLessEqual(gaps.max(), 100.0 * IDLE_BUDGET + 1e-6)

    def test_busier_sessions_pause_more_often(self):
        """Measured in the real capture: a session with 0 commands has a gap over
        30 s 3.6% of the time, one with 10+ commands 78.1% of the time. A fixed
        per-gap probability cannot fit both, so it scales with the gap count."""
        self.assertLess(_idle_probability(4), _idle_probability(38))
        self.assertLessEqual(_idle_probability(10_000), 0.15)


class TestTheRegressionGuard(unittest.TestCase):
    """The reason this file exists."""

    @classmethod
    def setUpClass(cls):
        df = generate_balanced_sessions(900, seed=11)
        cls.records = df.to_dict("records")
        cls.F = np.vstack([extract_temporal(r) for r in cls.records])

    def test_the_generator_emits_per_event_timestamps(self):
        for r in self.records[:500]:
            self.assertIn("event_timestamps", r)
            self.assertEqual(len(r["event_timestamps"]), r["n_events"])

    def test_the_seven_formerly_dead_features_are_alive(self):
        """Each was >= 98% zero with as few as 2 distinct values in the frozen
        training set. If this fails, the timing model has regressed and
        retraining on this generator's output would waste the run."""
        for name in FORMERLY_DEAD:
            col = self.F[:, IDX[name]]
            nonzero = float(np.mean(np.abs(col) > 1e-9))
            distinct = len(np.unique(col))
            with self.subTest(feature=name):
                self.assertGreater(nonzero, 0.60,
                                   f"{name} is zero in {100*(1-nonzero):.1f}% of "
                                   f"sessions; it was 98%+ before the fix")
                self.assertGreater(distinct, 10,
                                   f"{name} has only {distinct} distinct values; "
                                   f"burst_count had 2 before the fix")

    def test_burst_structure_resembles_the_real_capture(self):
        """Real medians over 45,648 sessions: burst_count 3.0, frac_sub100ms
        0.429, iat_cv 1.141. Bounds are deliberately loose -- this guards against
        the model drifting away, not against normal sampling noise."""
        self.assertLessEqual(np.median(self.F[:, IDX["burst_count"]]), 8.0)
        self.assertGreaterEqual(np.median(self.F[:, IDX["burst_count"]]), 1.0)
        self.assertLess(abs(np.median(self.F[:, IDX["frac_sub100ms"]]) - 0.43), 0.25)
        self.assertLess(abs(np.median(self.F[:, IDX["iat_cv"]]) - 1.14), 0.80)

    def test_event_counts_stay_in_the_measured_range(self):
        """Floor 2 so every session has a gap; ceiling EVENTS_CEILING because the
        old lognormal tail reached 1,139 events while the busiest of 45,648 real
        sessions had 41."""
        n = np.array([r["n_events"] for r in self.records])
        self.assertGreaterEqual(n.min(), 2)
        self.assertLessEqual(n.max(), EVENTS_CEILING)

    def test_duration_still_scales_with_kill_chain_phase(self):
        """The phase ramp is kept -- real deep sessions genuinely do run longer
        (63.6 s / 41 events) than shallow ones (1.9 s / 5 events)."""
        ph = np.array([r["phase"] for r in self.records])
        dur = self.F[:, IDX["session_duration_s"]]
        shallow, deep = np.median(dur[ph == 0]), np.median(dur[ph == 8])
        self.assertGreater(deep, shallow * 5,
                           "a phase-8 session should be far longer than a phase-0 one")

    def test_the_same_seed_gives_the_same_data(self):
        a = generate_balanced_sessions(450, seed=99).to_dict("records")
        b = generate_balanced_sessions(450, seed=99).to_dict("records")
        self.assertEqual([r["event_timestamps"] for r in a[:50]],
                         [r["event_timestamps"] for r in b[:50]])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestTheKeysTheExtractorsAskFor(unittest.TestCase):
    """2026-11-11: four features were dead purely because the generator never
    emitted the session keys their extractors read. Every one of 11,328 real
    parsed sessions carries all of them."""

    @classmethod
    def setUpClass(cls):
        cls.records = generate_balanced_sessions(900, seed=5).to_dict("records")

    def test_src_port_is_emitted_and_mostly_ephemeral(self):
        """Real: median 46,542, 98.0% >= 32768, 41.1% > 49151."""
        ports = [r["src_port"] for r in self.records]
        self.assertTrue(all(1024 <= p <= 65535 for p in ports))
        frac = sum(p >= 32768 for p in ports) / len(ports)
        self.assertGreater(frac, 0.90, "most source ports should be ephemeral")
        iana = sum(p > 49151 for p in ports) / len(ports)
        self.assertLess(abs(iana - 0.411), 0.10,
                        "share above the IANA dynamic floor should track the "
                        "real capture, since src_is_ephemeral keys on it")

    def test_source_addresses_repeat(self):
        """attacker_repeat_visitor can only ever be true if addresses recur. The
        generator used a fresh random 10.x per session, so none ever did."""
        ips = {r["src_ip"] for r in self.records}
        self.assertLess(len(ips), len(self.records),
                        "a bounded pool must produce reuse")
        self.assertTrue(any(r["seen_before"] for r in self.records))

    def test_addresses_are_documentation_ranges_only(self):
        """Never a routable address in a synthetic corpus. The previous 10.x
        values were RFC 1918 private space, which no internet attacker uses."""
        for r in self.records:
            self.assertTrue(
                r["src_ip"].startswith(("192.0.2.", "198.51.100.", "203.0.113.")),
                f"{r['src_ip']} is outside RFC 5737")

    def test_milestones_are_members_of_the_event_series(self):
        """t_first_auth and t_first_cmd are taken FROM the timestamps rather
        than computed as independent offsets, so they cannot contradict them."""
        for r in self.records[:300]:
            ts = r["event_timestamps"]
            self.assertIn(r["t_first_auth"], ts)
            self.assertIn(r["t_first_cmd"], ts)

    def test_milestones_are_ordered_within_the_session(self):
        for r in self.records[:300]:
            ts = r["event_timestamps"]
            self.assertGreaterEqual(r["t_first_auth"], ts[0])
            self.assertLessEqual(r["t_first_auth"], ts[-1])
            self.assertGreaterEqual(r["t_first_cmd"], ts[0])
            self.assertLessEqual(r["t_first_cmd"], ts[-1])

    def test_every_session_authenticates(self):
        """All 11,328 real sessions carry a t_first_auth; `n_login = 0` for
        non-brute-force labels left time_to_first_auth_s dead in 89% of rows."""
        self.assertTrue(all(r["login_attempts"] >= 1 for r in self.records))

    def test_login_attempts_cannot_exceed_the_events_to_carry_them(self):
        for r in self.records:
            self.assertGreaterEqual(r["n_commands"], 0,
                                    "n_commands = n_events - n_login - 1 must "
                                    "not go negative")

    def test_time_to_first_auth_is_alive(self):
        from src.extractors.temporal import extract_temporal, TEMPORAL_FEATURE_NAMES
        i = TEMPORAL_FEATURE_NAMES.index("time_to_first_auth_s")
        col = np.array([extract_temporal(r)[i] for r in self.records])
        self.assertGreater(float(np.mean(col > 0)), 0.5,
                           "was 0.0 in 89% of rows before the fix")
