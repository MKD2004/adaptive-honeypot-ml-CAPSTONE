"""
traffic_gateway/tests/test_benign_corroboration.py

02-11-2026 FINDINGS.md #1 — the Critical one. MT3 is a closed-set classifier over
45 **attack** labels. There is no benign class (benign rows were dropped from the
real datasets in notebook 01), so its softmax must return some attack for any
input, and a harmless session can never come back "safe". Measured on real Cowrie
sessions: four genuinely benign ones were all labelled attacks, one at confidence
0.995, and one was auto-blacklisted.

**A confidence threshold cannot fix it, and that is measured rather than assumed.**
Across those sessions:

    confidence         benign 0.301-0.995   attack 0.637-0.828
    top1-top2 margin   benign 0.087-0.992   attack 0.421-0.698
    mahalanobis        benign 425-553       attack 424-642

Every candidate overlaps, and benign reaches higher confidence than any of the
attacks. So the fix is not abstention but CORROBORATION: MT3 may not drive the
blacklist or the reconfiguration while the gateway's own connect-time classifier
independently judged the source BENIGN.

**This mitigates the finding; it does not close it.** A benign user whom the
gateway also finds suspicious is still exposed — `test_the_residual_risk_is_real`
pins that down deliberately, so nobody reads this file as "#1 is fixed".
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

from traffic_gateway.config import CONFIG                                 # noqa: E402
from traffic_gateway.post_session_pipeline import gateway_benign_veto     # noqa: E402

BENIGN_GW = {"verdict": "BENIGN", "score": 0.14, "signals_fired": []}
SUSPICIOUS_GW = {"verdict": "SUSPICIOUS", "score": 0.44,
                 "signals_fired": ["conn_rate_high"]}
MALICIOUS_GW = {"verdict": "MALICIOUS", "score": 1.0, "signals_fired": ["blacklist"]}
# The circular one: an already-blacklisted IP makes the gateway's own classifier
# return a derived verdict. Finding #1b.
CIRCULAR_GW = {"verdict": "BENIGN", "score": 1.0, "signals_fired": ["blacklist"]}


class TestTheVeto(unittest.TestCase):

    def test_an_independent_benign_verdict_vetoes_mt3(self):
        why = gateway_benign_veto(BENIGN_GW)
        self.assertIsNotNone(why)
        self.assertIn("BENIGN", why)
        self.assertIn("FINDINGS #1", why,
                      "the reason must point at the finding, so an operator "
                      "reading the log can find out why")

    def test_the_reason_quotes_the_score(self):
        self.assertIn("0.14", gateway_benign_veto(BENIGN_GW))

    def test_a_suspicious_verdict_does_not_veto(self):
        self.assertIsNone(gateway_benign_veto(SUSPICIOUS_GW))

    def test_a_malicious_verdict_does_not_veto(self):
        self.assertIsNone(gateway_benign_veto(MALICIOUS_GW))

    def test_no_gateway_verdict_does_not_veto(self):
        for value in (None, {}):
            with self.subTest(value=value):
                self.assertIsNone(gateway_benign_veto(value))

    def test_the_verdict_is_read_case_insensitively(self):
        self.assertIsNotNone(gateway_benign_veto(
            {"verdict": "benign", "score": 0.1, "signals_fired": []}))

    def test_a_missing_score_is_tolerated(self):
        why = gateway_benign_veto({"verdict": "BENIGN", "signals_fired": []})
        self.assertIsNotNone(why)
        self.assertIn("n/a", why)


class TestCircularCorroborationIsRefused(unittest.TestCase):
    """Finding #1b: once an IP is blacklisted the gateway returns
    score=1.0 signals=['blacklist'] for it. That is derived from the earlier
    block, so treating it as independent evidence would let MT3's first false
    positive endorse all its later ones."""

    def test_a_benign_verdict_carrying_the_blacklist_signal_is_not_evidence(self):
        self.assertIsNone(gateway_benign_veto(CIRCULAR_GW),
                          "a verdict derived from an existing blacklist entry "
                          "must not count as independent corroboration")

    def test_the_blacklist_signal_is_what_disqualifies_it(self):
        # identical but for the signal, and this one DOES veto
        clean = dict(CIRCULAR_GW, signals_fired=[])
        self.assertIsNotNone(gateway_benign_veto(clean))


class TestTheSwitch(unittest.TestCase):

    def test_it_is_on_by_default(self):
        self.assertTrue(CONFIG.MT3_RESPECT_GATEWAY_BENIGN)

    def test_turning_it_off_restores_the_old_behaviour(self):
        original = CONFIG.MT3_RESPECT_GATEWAY_BENIGN
        try:
            CONFIG.MT3_RESPECT_GATEWAY_BENIGN = False
            self.assertIsNone(gateway_benign_veto(BENIGN_GW))
        finally:
            CONFIG.MT3_RESPECT_GATEWAY_BENIGN = original


class TestEndToEnd(unittest.TestCase):
    """The measured cases from the finding, through the real pipeline and the real
    model. Skipped when the checkpoint is absent (it is gitignored)."""

    @classmethod
    def setUpClass(cls):
        ckpt = REPO_ROOT / "ml_analytics" / "artifacts" / "mt3_full_d256" / "best.pt"
        if not ckpt.exists():
            raise unittest.SkipTest(f"MT3 checkpoint not present: {ckpt}")
        from traffic_gateway.post_session_pipeline import PostSessionPipeline
        cls.tmp = Path(tempfile.mkdtemp())
        cls.pipe = PostSessionPipeline(results_path=cls.tmp / "r.jsonl")
        cls.pipe.startup()

    @staticmethod
    def _record(cmds, ip, sid):
        from src.parsers.cowrie_parser import build_record
        evs = [
            {"eventid": "cowrie.session.connect", "session": sid, "src_ip": ip,
             "src_port": 44000, "dst_port": 2222, "protocol": "ssh", "sensor": "c1",
             "timestamp": "2026-11-04T09:00:00.000000Z"},
            {"eventid": "cowrie.login.success", "session": sid, "src_ip": ip,
             "username": "deploy", "password": "x",
             "timestamp": "2026-11-04T09:00:01.000000Z"},
        ]
        for i, c in enumerate(cmds):
            evs.append({"eventid": "cowrie.command.input", "session": sid,
                        "src_ip": ip, "input": c,
                        "timestamp": f"2026-11-04T09:00:{2 + i * 3:02d}.000000Z"})
        evs.append({"eventid": "cowrie.session.closed", "session": sid, "src_ip": ip,
                    "timestamp": "2026-11-04T09:01:30.000000Z"})
        return build_record(evs)

    def _run(self, cmds, ip, sid, gw):
        return self.pipe.process_session(self._record(cmds, ip, sid),
                                         gateway_verdict=gw, write=False)

    def test_a_benign_session_is_still_labelled_an_attack(self):
        """The finding itself, unchanged: nothing here gives MT3 a benign class."""
        r = self._run(["whoami", "uptime", "ls", "exit"], "198.51.100.41", "e1",
                      BENIGN_GW)
        self.assertNotIn("BENIGN", r["mt3_prediction"]["micro_state"])

    def test_but_it_is_no_longer_auto_blacklisted(self):
        from traffic_gateway.blacklist_manager import blacklist_manager
        ip = "198.51.100.42"
        r = self._run(["whoami", "uptime", "ls", "exit"], ip, "e2", BENIGN_GW)
        self.assertFalse(r["mt3_trusted"])
        self.assertIsNotNone(r["mt3_veto"])
        self.assertFalse(r["auto_blacklisted"])
        self.assertFalse(blacklist_manager.is_blacklisted(ip))

    def test_a_high_confidence_benign_session_is_also_protected(self):
        """The audit's worst case: `df -h ; free -m` came back DISC_PROC_ENUM at
        0.995, which clears every confidence threshold there is."""
        from traffic_gateway.blacklist_manager import blacklist_manager
        ip = "198.51.100.43"
        r = self._run(["df -h", "free -m", "exit"], ip, "e3", BENIGN_GW)
        self.assertGreater(r["mt3_prediction"]["confidence"], 0.9,
                           "if this is no longer confident the case has changed")
        self.assertFalse(blacklist_manager.is_blacklisted(ip))

    def test_a_real_attack_is_still_blocked(self):
        """The fix must not disarm the system -- this is the demo's headline."""
        from traffic_gateway.blacklist_manager import blacklist_manager
        ip = "198.51.100.44"
        r = self._run(["uname -a", "cat /etc/shadow", "rm -rf /var/log/auth.log",
                       "history -c"], ip, "e4", SUSPICIOUS_GW)
        self.assertTrue(r["mt3_trusted"])
        self.assertTrue(blacklist_manager.is_blacklisted(ip))

    def test_the_residual_risk_is_real(self):
        """DELIBERATE: a benign user the gateway ALSO finds suspicious is still
        blocked. Recorded as a test so this file cannot be read as "#1 is fixed".
        Closing it needs a benign class and a retrain."""
        from traffic_gateway.blacklist_manager import blacklist_manager
        ip = "198.51.100.45"
        r = self._run(["df -h", "free -m", "exit"], ip, "e5", SUSPICIOUS_GW)
        self.assertTrue(r["mt3_trusted"])
        self.assertTrue(blacklist_manager.is_blacklisted(ip),
                        "if this ever stops being true the residual risk has "
                        "been closed -- update FINDINGS #1 and this docstring")

    def test_the_distance_to_training_data_is_reported(self):
        r = self._run(["whoami", "exit"], "198.51.100.46", "e6", BENIGN_GW)
        self.assertIsNotNone(r["ood_distance"])
        self.assertIsNotNone(r["ood_p95_train"])
        self.assertGreater(r["ood_distance"], r["ood_p95_train"],
                           "live sessions measured 425-642 against a training "
                           "p95 of 15.4; if that has changed, re-measure before "
                           "quoting the published macro-F1 as representative")


if __name__ == "__main__":
    unittest.main(verbosity=2)
