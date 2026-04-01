"""
traffic_gateway/tests/test_router.py

Unit tests for traffic_router and reputation_scorer.
No network I/O — the router is tested against different IP states directly.
"""
import asyncio
import sys
import os
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch, AsyncMock

# Redirect persistence to temp dir
_tmp = tempfile.mkdtemp()
import traffic_gateway.config as _cfg_mod
_cfg_mod.CONFIG.DATA_DIR = Path(_tmp) / "data"
_cfg_mod.CONFIG.LOG_DIR  = Path(_tmp) / "logs"
_cfg_mod.CONFIG.DATA_DIR.mkdir(parents=True, exist_ok=True)
_cfg_mod.CONFIG.LOG_DIR.mkdir(parents=True, exist_ok=True)

from traffic_gateway.traffic_router  import TrafficRouter
from traffic_gateway.ip_classifier   import IPStatus, classifier
from traffic_gateway.blacklist_manager import blacklist_manager
from traffic_gateway.config          import CONFIG


class TestTrafficRouter(unittest.TestCase):

    def setUp(self):
        self.router = TrafficRouter()

    def _set_ip_status(self, ip: str, status: IPStatus) -> None:
        classifier.set_status(ip, status, reason="test")

    # ── Routing decisions ─────────────────────────────────────────────────
    def test_unknown_routes_to_honeypot(self):
        ip = "30.0.0.1"
        decision = self.router.decide_route(ip)
        self.assertEqual(decision.target_type, "honeypot")
        self.assertIsNotNone(decision.target)
        self.assertIn("zero_trust", decision.reason)

    def test_whitelisted_routes_to_backend(self):
        ip = "30.0.0.2"
        self._set_ip_status(ip, IPStatus.WHITELISTED)
        decision = self.router.decide_route(ip)
        self.assertEqual(decision.target_type, "backend")
        self.assertEqual(decision.target, CONFIG.REAL_BACKEND)

    def test_blacklisted_routes_to_honeypot(self):
        ip = "30.0.0.3"
        self._set_ip_status(ip, IPStatus.BLACKLISTED)
        decision = self.router.decide_route(ip)
        self.assertEqual(decision.target_type, "honeypot")
        self.assertIn("blacklisted", decision.reason)

    def test_probation_routes_to_honeypot(self):
        ip = "30.0.0.4"
        self._set_ip_status(ip, IPStatus.PROBATION)
        decision = self.router.decide_route(ip)
        self.assertEqual(decision.target_type, "honeypot")
        self.assertIn("probation", decision.reason)

    def test_suspicious_routes_to_honeypot(self):
        ip = "30.0.0.5"
        self._set_ip_status(ip, IPStatus.SUSPICIOUS)
        decision = self.router.decide_route(ip)
        self.assertEqual(decision.target_type, "honeypot")
        self.assertIn("suspicious", decision.reason)

    def test_rate_limited_routes_to_reject(self):
        ip = "30.0.0.6"
        # Force rate limiter to block this IP
        from traffic_gateway.rate_limiter import rate_limiter
        for _ in range(CONFIG.RATE_LIMIT_MAX_CONN + 1):
            rate_limiter.check(ip)
        decision = self.router.decide_route(ip)
        self.assertEqual(decision.target_type, "reject")
        self.assertIsNone(decision.target)

    # ── Round-robin honeypot selection ────────────────────────────────────
    def test_honeypot_round_robin(self):
        """Unknown IPs should cycle across all honeypot targets."""
        seen_targets = set()
        for i in range(len(CONFIG.HONEYPOT_TARGETS) * 2):
            ip = f"31.0.0.{i}"
            decision = self.router.decide_route(ip)
            if decision.target:
                seen_targets.add(str(decision.target))
        # Should have hit multiple different honeypots
        self.assertGreater(len(seen_targets), 1)

    # ── Stats ─────────────────────────────────────────────────────────────
    def test_stats_has_expected_keys(self):
        stats = self.router.stats()
        self.assertIn("honeypot_count", stats)
        self.assertIn("real_backend", stats)
        self.assertEqual(stats["honeypot_count"], len(CONFIG.HONEYPOT_TARGETS))


class TestReputationScorer(unittest.TestCase):

    def test_no_history_returns_neutral(self):
        from traffic_gateway.reputation_scorer import score_ip
        score, reason = score_ip("40.0.0.1")
        self.assertAlmostEqual(score, 0.5)
        self.assertIn("No session history", reason)

    def test_score_in_range(self):
        from traffic_gateway.reputation_scorer import score_ip
        from traffic_gateway.session_tracker import session_tracker, Session

        ip = "40.0.0.2"
        # Inject a few fake sessions
        for i in range(5):
            sess = session_tracker.open_session(ip, target="honeypot",
                                                target_addr="127.0.0.1:2222")
            session_tracker.record_data(sess, direction="in",
                                        data=b"\x00" * 50)
            session_tracker.close_session(sess)

        score, reason = score_ip(ip)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_async_wrapper(self):
        from traffic_gateway.reputation_scorer import ml_risk_assessment

        async def _run():
            return await ml_risk_assessment("40.0.0.3")

        score, reason = asyncio.run(_run())
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)


class TestSessionTracker(unittest.TestCase):

    def setUp(self):
        from traffic_gateway.session_tracker import SessionTracker
        self.tracker = SessionTracker()

    def test_open_and_close_session(self):
        sess = self.tracker.open_session("50.0.0.1",
                                         target="honeypot",
                                         target_addr="127.0.0.1:2222")
        self.assertIn(sess.session_id, self.tracker._active)
        self.tracker.record_data(sess, direction="in", data=b"hello world")
        self.tracker.record_data(sess, direction="out", data=b"OK")
        closed = self.tracker.close_session(sess)
        self.assertEqual(closed.bytes_in, 11)
        self.assertEqual(closed.bytes_out, 2)
        self.assertIsNotNone(closed.ended_at)
        self.assertNotIn(sess.session_id, self.tracker._active)

    def test_payload_captured(self):
        sess = self.tracker.open_session("50.0.0.2",
                                         target="honeypot",
                                         target_addr="127.0.0.1:2222")
        payload = b"A" * 1000
        self.tracker.record_data(sess, direction="in", data=payload)
        # Should be truncated to MAX_PAYLOAD_LOG_BYTES
        self.assertLessEqual(len(sess.payload_snip), CONFIG.MAX_PAYLOAD_LOG_BYTES)

    def test_history_preserved(self):
        ip = "50.0.0.3"
        for i in range(3):
            s = self.tracker.open_session(ip, target="honeypot",
                                           target_addr="127.0.0.1:2222")
            self.tracker.close_session(s)
        self.assertEqual(len(self.tracker.get_history(ip)), 3)

    def test_recent_stats(self):
        ip = "50.0.0.4"
        for _ in range(5):
            s = self.tracker.open_session(ip, target="honeypot",
                                           target_addr="127.0.0.1:2222")
            self.tracker.record_data(s, direction="in", data=b"x" * 200)
            self.tracker.close_session(s)
        stats = self.tracker.recent_stats(ip, n=5)
        self.assertEqual(stats["sample_size"], 5)
        self.assertIn("avg_bytes_in", stats)
        self.assertIn("avg_entropy", stats)


if __name__ == "__main__":
    unittest.main(verbosity=2)
