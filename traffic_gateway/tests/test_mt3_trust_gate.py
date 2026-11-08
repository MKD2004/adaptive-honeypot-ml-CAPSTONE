"""
traffic_gateway/tests/test_mt3_trust_gate.py

MT3's verdict is computed for every source but may only ACT on trusted ones.

Why this gate exists (HONEYPOT_AUDIT.md PART 7): on Heralding records MT3 agrees
with the rule labeller on 0 of 6 scenarios and is *confidently* wrong -- a bare
connect with no authentication attempt comes back DISC_NETSTAT_SCAN at confidence
1.000, which is phase 3 and therefore clears MT3_AUTO_BLACKLIST_CONF. Ungated,
deploying Heralding would blacklist users for opening a TCP connection and
escalate the honeypot off the same verdict.

The gate is on `source`, not `protocol`: a Cowrie telnet session is shell-shaped
and a Heralding telnet session is credential-shaped, and only the former is what
MT3 trained on.
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

from traffic_gateway.config import CONFIG                               # noqa: E402
from traffic_gateway.feature_bridge import group_d_mode                 # noqa: E402
from traffic_gateway.post_session_pipeline import mt3_is_trusted_for    # noqa: E402


class TestTrustGate(unittest.TestCase):

    def test_cowrie_is_trusted(self):
        self.assertTrue(mt3_is_trusted_for({"source": "cowrie_real"}))

    def test_heralding_is_not_trusted(self):
        self.assertFalse(mt3_is_trusted_for({"source": "heralding"}))

    def test_case_and_whitespace_do_not_grant_trust(self):
        self.assertTrue(mt3_is_trusted_for({"source": "  COWRIE_REAL "}))
        self.assertFalse(mt3_is_trusted_for({"source": "Heralding"}))

    def test_unknown_source_fails_closed_by_default(self):
        self.assertFalse(CONFIG.MT3_TRUST_UNKNOWN_SOURCE,
                         "default must be fail-closed")
        for rec in ({}, {"source": ""}, {"source": None}, {"source": "dionaea"}):
            with self.subTest(record=rec):
                self.assertFalse(mt3_is_trusted_for(rec))

    def test_fail_open_is_respected_when_explicitly_enabled(self):
        original = CONFIG.MT3_TRUST_UNKNOWN_SOURCE
        try:
            CONFIG.MT3_TRUST_UNKNOWN_SOURCE = True
            self.assertTrue(mt3_is_trusted_for({"source": "something-new"}))
        finally:
            CONFIG.MT3_TRUST_UNKNOWN_SOURCE = original

    def test_trusted_set_does_not_silently_include_heralding(self):
        # a regression guard: adding heralding here without re-running the PART 7
        # acceptance scenarios is exactly the mistake this gate prevents
        self.assertNotIn("heralding", CONFIG.MT3_TRUSTED_SOURCES)


class TestGroupDMode(unittest.TestCase):
    """Phase 1b's zero-fill decision, now actually wired."""

    def test_cowrie_gets_the_live_encoder(self):
        self.assertEqual(group_d_mode({"source": "cowrie_real"}), "live")

    def test_heralding_is_zero_filled(self):
        self.assertEqual(group_d_mode({"source": "heralding"}), "zero-filled")

    def test_unknown_source_is_zero_filled(self):
        for rec in ({}, {"source": ""}, {"source": "tanner"}, {"source": "dionaea"}):
            with self.subTest(record=rec):
                self.assertEqual(group_d_mode(rec), "zero-filled")

    def test_mode_is_independent_of_protocol(self):
        # protocol must not override source: a Heralding ssh session is still
        # credential-shaped, so its Group D stays off
        self.assertEqual(
            group_d_mode({"source": "heralding", "protocol": "ssh"}), "zero-filled")


class TestGateAndModeAgree(unittest.TestCase):
    """Both gates key off `source`; they must not disagree for known sources."""

    def test_trusted_sources_also_get_live_group_d(self):
        for src in CONFIG.MT3_TRUSTED_SOURCES:
            with self.subTest(source=src):
                rec = {"source": src}
                self.assertTrue(mt3_is_trusted_for(rec))
                self.assertEqual(group_d_mode(rec), "live",
                                 "a source MT3 is trusted for should also be "
                                 "in-domain for the semantic encoder")


if __name__ == "__main__":
    unittest.main(verbosity=2)
