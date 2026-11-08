"""
response_mitigation/tests/test_mitigation_config.py

Defaults must be the safe ones, and a wrong value must stop start-up with the
variable's name in the message. Settings are passed as a dict, so no real
environment variable is touched.
"""
import ipaddress
import unittest
from pathlib import Path

from response_mitigation.config import load_config
from response_mitigation.models import Mode


class TestDefaults(unittest.TestCase):

    def test_defaults_are_the_safe_ones(self):
        cfg = load_config({})
        self.assertIs(cfg.mode, Mode.OBSERVE)
        self.assertIs(cfg.firewall, False)
        self.assertEqual(cfg.max_new_blocks_per_hour, 50)
        self.assertEqual(cfg.never_block, ())
        self.assertEqual(cfg.policy.deny_ttl_s, 24 * 3600)
        self.assertEqual(cfg.policy.deny_repeat_sessions, 3)
        self.assertEqual(cfg.policy.deny_min_phase, 4)
        self.assertEqual(cfg.policy.alert_min_phase, 7)

    def test_default_paths_sit_inside_the_package(self):
        cfg = load_config({})
        pkg = Path(__file__).resolve().parent.parent
        self.assertEqual(cfg.kill_file.resolve(), pkg / "MITIGATION_DISABLED")
        self.assertEqual(cfg.blocklist_path.resolve(), pkg / "data" / "blocklist.json")
        self.assertEqual(cfg.audit_path.resolve(), pkg / "logs" / "mitigation_audit.jsonl")

    def test_empty_values_mean_default(self):
        cfg = load_config({"MITIGATION_MODE": "", "MITIGATION_FIREWALL": "  ",
                           "MITIGATION_NEVER_BLOCK": "", "MITIGATION_DENY_TTL_HOURS": ""})
        self.assertIs(cfg.mode, Mode.OBSERVE)
        self.assertIs(cfg.firewall, False)
        self.assertEqual(cfg.policy.deny_ttl_s, 24 * 3600)


class TestOverrides(unittest.TestCase):

    def test_mode_is_case_insensitive(self):
        for word, mode in (("off", Mode.OFF), ("Observe", Mode.OBSERVE), ("ENFORCE", Mode.ENFORCE)):
            with self.subTest(word=word):
                self.assertIs(load_config({"MITIGATION_MODE": word}).mode, mode)

    def test_firewall_switch(self):
        for word, expected in (("1", True), ("yes", True), ("0", False), ("Off", False)):
            with self.subTest(word=word):
                self.assertIs(load_config({"MITIGATION_FIREWALL": word}).firewall, expected)

    def test_numbers_and_ttl_hours(self):
        cfg = load_config({"MITIGATION_MAX_NEW_BLOCKS_PER_HOUR": "10",
                           "MITIGATION_DENY_TTL_HOURS": "2",
                           "MITIGATION_DENY_REPEAT_SESSIONS": "5",
                           "MITIGATION_DENY_MIN_PHASE": "6",
                           "MITIGATION_ALERT_MIN_PHASE": "8"})
        self.assertEqual(cfg.max_new_blocks_per_hour, 10)
        self.assertEqual(cfg.policy.deny_ttl_s, 2 * 3600)
        self.assertEqual(cfg.policy.deny_repeat_sessions, 5)
        self.assertEqual(cfg.policy.deny_min_phase, 6)
        self.assertEqual(cfg.policy.alert_min_phase, 8)

    def test_a_cap_of_zero_is_allowed_and_means_block_nothing(self):
        self.assertEqual(load_config({"MITIGATION_MAX_NEW_BLOCKS_PER_HOUR": "0"})
                         .max_new_blocks_per_hour, 0)

    def test_paths(self):
        cfg = load_config({"MITIGATION_KILL_FILE": "/etc/honeypot/STOP",
                           "MITIGATION_BLOCKLIST_PATH": "/srv/hp/blocklist.json",
                           "MITIGATION_AUDIT_PATH": "/var/log/hp/audit.jsonl"})
        self.assertEqual(cfg.kill_file, Path("/etc/honeypot/STOP"))
        self.assertEqual(cfg.blocklist_path, Path("/srv/hp/blocklist.json"))
        self.assertEqual(cfg.audit_path, Path("/var/log/hp/audit.jsonl"))

    def test_never_block_takes_addresses_and_networks(self):
        cfg = load_config({"MITIGATION_NEVER_BLOCK": " 1.2.3.4, 10.0.0.0/8 ,2001:db8::/32,"})
        self.assertEqual(cfg.never_block, (ipaddress.ip_network("1.2.3.4/32"),
                                           ipaddress.ip_network("10.0.0.0/8"),
                                           ipaddress.ip_network("2001:db8::/32")))


class TestBadValuesStopStartUp(unittest.TestCase):

    def assertRejects(self, name, value):
        with self.subTest(name=name, value=value):
            with self.assertRaises(ValueError) as ctx:
                load_config({name: value})
            self.assertIn(name, str(ctx.exception))

    def test_bad_values(self):
        for name, value in (
            ("MITIGATION_MODE", "enforcing"),
            ("MITIGATION_FIREWALL", "maybe"),
            ("MITIGATION_MAX_NEW_BLOCKS_PER_HOUR", "-1"),
            ("MITIGATION_MAX_NEW_BLOCKS_PER_HOUR", "1001"),
            ("MITIGATION_MAX_NEW_BLOCKS_PER_HOUR", "fifty"),
            ("MITIGATION_DENY_TTL_HOURS", "0"),
            ("MITIGATION_DENY_TTL_HOURS", "721"),
            ("MITIGATION_DENY_TTL_HOURS", "1.5"),
            ("MITIGATION_DENY_REPEAT_SESSIONS", "0"),
            ("MITIGATION_DENY_MIN_PHASE", "9"),
            ("MITIGATION_ALERT_MIN_PHASE", "-1"),
            ("MITIGATION_NEVER_BLOCK", "1.2.3.4, not-an-ip"),
            ("MITIGATION_NEVER_BLOCK", "10.0.0.0/33"),
        ):
            self.assertRejects(name, value)

    def test_the_message_names_the_bad_entry(self):
        with self.assertRaises(ValueError) as ctx:
            load_config({"MITIGATION_NEVER_BLOCK": "1.2.3.4, not-an-ip"})
        self.assertIn("not-an-ip", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
