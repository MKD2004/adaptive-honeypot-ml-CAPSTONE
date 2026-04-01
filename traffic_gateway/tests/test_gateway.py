"""
traffic_gateway/tests/test_gateway.py

Unit tests for ip_classifier, rate_limiter, and blacklist_manager.
Runs without network access — no real proxying or ML calls.
"""
import sys
import os
import unittest
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

# ── Redirect persistence to a temp dir so tests don't pollute real data ───────
_tmp = tempfile.mkdtemp()

# Patch CONFIG before any gateway module is imported
import importlib
import traffic_gateway.config as _cfg_mod

_cfg_mod.CONFIG.DATA_DIR = Path(_tmp) / "data"
_cfg_mod.CONFIG.LOG_DIR  = Path(_tmp) / "logs"
_cfg_mod.CONFIG.DATA_DIR.mkdir(parents=True, exist_ok=True)
_cfg_mod.CONFIG.LOG_DIR.mkdir(parents=True, exist_ok=True)

from traffic_gateway.ip_classifier  import IPStatus, IPRecord, IPClassifier
from traffic_gateway.rate_limiter   import RateLimiter
from traffic_gateway.blacklist_manager import BlacklistManager
from traffic_gateway.config import CONFIG


class TestIPRecord(unittest.TestCase):

    def test_default_status(self):
        rec = IPRecord(ip="1.2.3.4")
        self.assertEqual(rec.status, IPStatus.UNKNOWN)
        self.assertEqual(rec.probation_strikes, 0)
        self.assertFalse(rec.review_eligible)

    def test_blacklist_review_eligibility_not_yet(self):
        rec = IPRecord(ip="1.2.3.4")
        rec.status = IPStatus.BLACKLISTED
        # Just blacklisted — not enough time elapsed
        rec.blacklisted_at = datetime.now(timezone.utc).isoformat()
        self.assertFalse(rec.is_blacklist_review_eligible())

    def test_blacklist_review_eligibility_elapsed(self):
        rec = IPRecord(ip="1.2.3.4")
        rec.status = IPStatus.BLACKLISTED
        # Pretend it was blacklisted a long time ago
        old = datetime.now(timezone.utc) - timedelta(seconds=CONFIG.MIN_BLACKLIST_SEC + 60)
        rec.blacklisted_at = old.isoformat()
        self.assertTrue(rec.is_blacklist_review_eligible())

    def test_probation_complete_true(self):
        rec = IPRecord(ip="1.2.3.4")
        rec.status = IPStatus.PROBATION
        old = datetime.now(timezone.utc) - timedelta(seconds=CONFIG.PROBATION_SEC + 60)
        rec.promoted_to_probation_at = old.isoformat()
        rec.probation_strikes = 0
        self.assertTrue(rec.is_probation_complete())

    def test_probation_complete_false_strikes(self):
        rec = IPRecord(ip="1.2.3.4")
        rec.status = IPStatus.PROBATION
        old = datetime.now(timezone.utc) - timedelta(seconds=CONFIG.PROBATION_SEC + 60)
        rec.promoted_to_probation_at = old.isoformat()
        rec.probation_strikes = CONFIG.PROBATION_STRIKE_LIMIT  # hit the limit
        self.assertFalse(rec.is_probation_complete())


class TestIPClassifier(unittest.TestCase):

    def setUp(self):
        self.clf = IPClassifier()

    def test_get_creates_unknown_record(self):
        rec = self.clf.get("10.0.0.1")
        self.assertEqual(rec.ip, "10.0.0.1")
        self.assertEqual(rec.status, IPStatus.UNKNOWN)

    def test_set_status_blacklist(self):
        self.clf.set_status("10.0.0.2", IPStatus.BLACKLISTED, reason="test")
        self.assertEqual(self.clf.get_status("10.0.0.2"), IPStatus.BLACKLISTED)
        rec = self.clf.get("10.0.0.2")
        self.assertIsNotNone(rec.blacklisted_at)
        self.assertEqual(rec.blacklist_reason, "test")

    def test_set_status_probation_resets_strikes(self):
        ip = "10.0.0.3"
        # Simulate prior strikes
        self.clf.set_status(ip, IPStatus.BLACKLISTED)
        self.clf.add_probation_strike(ip)
        self.clf.add_probation_strike(ip)
        # Now move to probation — strikes should reset
        self.clf.set_status(ip, IPStatus.PROBATION)
        rec = self.clf.get(ip)
        self.assertEqual(rec.probation_strikes, 0)

    def test_increment_connection(self):
        ip = "10.0.0.4"
        self.clf.increment_connection(ip, to_honeypot=True)
        self.clf.increment_connection(ip, to_honeypot=True)
        self.clf.increment_connection(ip, to_honeypot=False)
        rec = self.clf.get(ip)
        self.assertEqual(rec.total_connections, 3)
        self.assertEqual(rec.honeypot_sessions, 2)
        self.assertEqual(rec.backend_sessions, 1)

    def test_add_probation_strike(self):
        ip = "10.0.0.5"
        n1 = self.clf.add_probation_strike(ip)
        n2 = self.clf.add_probation_strike(ip)
        self.assertEqual(n1, 1)
        self.assertEqual(n2, 2)

    def test_records_by_status(self):
        self.clf.set_status("192.168.1.1", IPStatus.BLACKLISTED)
        self.clf.set_status("192.168.1.2", IPStatus.BLACKLISTED)
        self.clf.set_status("192.168.1.3", IPStatus.WHITELISTED)
        blacklisted = self.clf.records_by_status(IPStatus.BLACKLISTED)
        whitelisted = self.clf.records_by_status(IPStatus.WHITELISTED)
        bl_ips = {r.ip for r in blacklisted}
        self.assertIn("192.168.1.1", bl_ips)
        self.assertIn("192.168.1.2", bl_ips)
        self.assertEqual(len([r for r in whitelisted if r.ip == "192.168.1.3"]), 1)


class TestRateLimiter(unittest.TestCase):

    def setUp(self):
        self.rl = RateLimiter()

    def test_allows_within_limit(self):
        ip = "5.5.5.5"
        for _ in range(CONFIG.RATE_LIMIT_MAX_CONN - 1):
            self.assertTrue(self.rl.check(ip))

    def test_blocks_after_limit(self):
        ip = "6.6.6.6"
        # Exhaust the window
        for _ in range(CONFIG.RATE_LIMIT_MAX_CONN):
            self.rl.check(ip)
        # Next one should be blocked
        self.assertFalse(self.rl.check(ip))

    def test_is_blocked_after_rate_offence(self):
        ip = "7.7.7.7"
        for _ in range(CONFIG.RATE_LIMIT_MAX_CONN + 1):
            self.rl.check(ip)
        self.assertTrue(self.rl.is_blocked(ip))

    def test_unblock_manually(self):
        ip = "8.8.8.8"
        for _ in range(CONFIG.RATE_LIMIT_MAX_CONN + 1):
            self.rl.check(ip)
        self.rl.unblock(ip)
        self.assertFalse(self.rl.is_blocked(ip))

    def test_current_count(self):
        ip = "9.9.9.9"
        self.rl.check(ip)
        self.rl.check(ip)
        self.assertEqual(self.rl.current_count(ip), 2)

    def test_different_ips_independent(self):
        ip_a, ip_b = "11.0.0.1", "11.0.0.2"
        for _ in range(CONFIG.RATE_LIMIT_MAX_CONN + 1):
            self.rl.check(ip_a)
        # ip_b should still be allowed
        self.assertTrue(self.rl.check(ip_b))


class TestBlacklistManager(unittest.TestCase):

    def setUp(self):
        self.mgr = BlacklistManager()

    def test_blacklist_and_query(self):
        self.mgr.blacklist("20.0.0.1", reason="test_bl")
        self.assertTrue(self.mgr.is_blacklisted("20.0.0.1"))

    def test_remove_from_blacklist(self):
        self.mgr.blacklist("20.0.0.2")
        removed = self.mgr.remove_from_blacklist("20.0.0.2")
        self.assertTrue(removed)
        self.assertFalse(self.mgr.is_blacklisted("20.0.0.2"))

    def test_remove_nonexistent(self):
        result = self.mgr.remove_from_blacklist("99.99.99.99")
        self.assertFalse(result)

    def test_whitelist(self):
        self.mgr.whitelist("20.0.0.3", reason="manual_trust")
        self.assertTrue(self.mgr.is_whitelisted("20.0.0.3"))

    def test_whitelist_removes_from_blacklist(self):
        ip = "20.0.0.4"
        self.mgr.blacklist(ip)
        self.mgr.whitelist(ip, reason="cleared")
        self.assertFalse(self.mgr.is_blacklisted(ip))
        self.assertTrue(self.mgr.is_whitelisted(ip))

    def test_promote_to_probation(self):
        ip = "20.0.0.5"
        self.mgr.blacklist(ip)
        self.mgr.promote_to_probation(ip, ml_score=0.15, reasoning="looks_clean")
        self.assertFalse(self.mgr.is_blacklisted(ip))
        from traffic_gateway.ip_classifier import classifier
        self.assertEqual(classifier.get_status(ip), IPStatus.PROBATION)

    def test_promote_to_whitelist(self):
        ip = "20.0.0.6"
        self.mgr.promote_to_whitelist(ip, ml_score=0.10, reasoning="clean_probation")
        self.assertTrue(self.mgr.is_whitelisted(ip))
        from traffic_gateway.ip_classifier import classifier
        self.assertEqual(classifier.get_status(ip), IPStatus.WHITELISTED)

    def test_revoke_probation(self):
        ip = "20.0.0.7"
        self.mgr.promote_to_probation(ip, ml_score=0.20, reasoning="test")
        self.mgr.revoke_probation(ip, reason="caught_scanning")
        from traffic_gateway.ip_classifier import classifier
        self.assertEqual(classifier.get_status(ip), IPStatus.BLACKLISTED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
