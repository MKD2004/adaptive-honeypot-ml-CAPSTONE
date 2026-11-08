"""
traffic_gateway/tests/test_heralding_simulator.py

The synthetic Heralding generator must stay in step with the labeller it is
generating training data for. If they drift, the retrain learns wrong labels and
nothing downstream notices.

`generate_sessions(verify_labels=True)` already asserts this on every record, so
these tests mostly prove the verification itself works and the output is usable.
It has already earned its keep twice:

  - the generator duplicated the parser's DEFAULT_CREDENTIALS set as a smaller
    local copy, so a "brute force" session containing ("admin", "password") was
    labelled ACCESS_DEFAULT_CRED;
  - a "default creds" session drawing ("root", "") was labelled RECON_USER_ENUM,
    which exposed a real precedence flaw -- one username with no password is a
    passwordless default, not enumeration. The labeller now requires >= 2
    distinct usernames for RECON_USER_ENUM.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "honeypot_dataset"))

from src.generators import heralding_simulator as sim          # noqa: E402
from src.parsers import heralding_parser as hp                 # noqa: E402
from src.parsers.session_contract import assert_valid          # noqa: E402


class TestScenarioLabels(unittest.TestCase):

    def test_every_scenario_produces_its_declared_label(self):
        # verify_labels=True raises on any mismatch; a clean run is the assertion
        got = list(sim.generate_sessions(n_per_scenario=40, seed=7))
        self.assertEqual(len(got), 40 * len(sim.SCENARIOS))

    def test_labels_cover_the_scenarios_declared(self):
        labels = {lab for lab, _ in sim.generate_sessions(n_per_scenario=15, seed=11)}
        self.assertEqual(labels, set(sim.SCENARIOS.values()))

    def test_several_seeds_all_stay_in_step(self):
        for seed in (1, 99, 2026):
            with self.subTest(seed=seed):
                list(sim.generate_sessions(n_per_scenario=25, seed=seed))

    def test_verification_actually_catches_a_mismatch(self):
        original = dict(sim.SCENARIOS)
        try:
            sim.SCENARIOS["bare_connect"] = "EXFIL_DNS_TUNNEL"   # a lie
            with self.assertRaises(AssertionError):
                list(sim.generate_sessions(n_per_scenario=1, seed=3,
                                           scenarios=["bare_connect"]))
        finally:
            sim.SCENARIOS.clear()
            sim.SCENARIOS.update(original)

    def test_unknown_scenario_is_rejected(self):
        import random
        with self.assertRaises(ValueError):
            sim.generate_session("not_a_scenario", random.Random(0))


class TestRecordsAreUsable(unittest.TestCase):

    def test_records_parse_and_conform(self):
        for label, rec in sim.generate_sessions(n_per_scenario=10, seed=5):
            with self.subTest(label=label):
                parsed = hp.build_record([rec])
                assert_valid(parsed, where=f"simulated/{label}")
                self.assertEqual(parsed["micro_state"], label)

    def test_no_database_protocols_are_generated(self):
        # the taxonomy has no database-auth micro-state (MULTI_HONEYPOT.md 7.1),
        # so training rows must not be labelled against a class that misfits
        protos = {rec["protocol"] for _, rec in sim.generate_sessions(
            n_per_scenario=40, seed=13)}
        self.assertFalse(protos & {"mysql", "postgres", "postgresql", "mssql"},
                         f"database protocols leaked into training data: {protos}")

    def test_source_addresses_stay_in_documentation_ranges(self):
        for _, rec in sim.generate_sessions(n_per_scenario=20, seed=17):
            ip = rec["source_ip"]
            self.assertTrue(
                ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")),
                f"{ip} is outside the RFC 5737 documentation ranges")

    def test_timestamps_round_trip_through_the_parser(self):
        for _, rec in sim.generate_sessions(n_per_scenario=10, seed=19):
            self.assertGreater(hp._utc_ts(rec["timestamp"]), 0.0)

    def test_deterministic_for_a_given_seed(self):
        a = [r["session_id"] for _, r in sim.generate_sessions(n_per_scenario=5, seed=42)]
        b = [r["session_id"] for _, r in sim.generate_sessions(n_per_scenario=5, seed=42)]
        self.assertEqual(a, b)


class TestAcceptanceHarness(unittest.TestCase):
    """The gate's criteria must be the ones that matter, and must be strict."""

    def test_scenarios_include_the_dangerous_bare_connect(self):
        from ml_analytics.mt3_pipeline.acceptance_heralding import SCENARIOS
        bare = [s for s in SCENARIOS if not s[3]]
        self.assertEqual(len(bare), 1,
                         "exactly one zero-auth scenario is required -- it is the "
                         "one that proves the model will not blacklist innocents")

    def test_phase_ceiling_reflects_what_heralding_can_observe(self):
        from ml_analytics.mt3_pipeline.acceptance_heralding import MAX_PLAUSIBLE_PHASE
        # Heralding has no shell, so Execution (2) and beyond are unreachable
        self.assertEqual(MAX_PLAUSIBLE_PHASE, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
