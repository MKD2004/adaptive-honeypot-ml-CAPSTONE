"""
response_mitigation/tests/test_mitigation_same_as_today.py

The promise behind the whole switch-over: with default settings, the engine
adds exactly the same IPs to the gateway blacklist, with exactly the same
reason text, as the inline code it replaced in
traffic_gateway/post_session_pipeline.py.

`todays_inline_block` below is that old condition, copied from the file as it
was at commit 49b97fd. Every combination is run through both and compared.
"""
import unittest

from response_mitigation.config import load_config
from response_mitigation.engine import build_engine
from response_mitigation.models import Verdict
from traffic_gateway.peer_attribution import is_docker_bridge_addr   # used by the old code

MIN_PHASE, MIN_CONF = 1, 0.5

IPS = ["45.33.32.156", "172.217.14.206", "172.1.2.3", "172.32.0.1",     # public
       "127.0.0.1", "192.168.1.5", "10.0.0.7",                          # demo peers
       "172.17.0.1", "172.16.5.5", "172.31.255.255"]                    # Docker range
PHASES = range(0, 9)
CONFS = [0.0, 0.3, 0.4999, 0.5, 0.75, 1.0]
STATES = [(False, False), (True, False), (False, True)]   # (whitelisted, blacklisted)


class FakeManager:
    """Same three methods the pipeline used on the real blacklist manager."""

    def __init__(self, whitelisted=False, blacklisted=False):
        self._wl, self._bl = whitelisted, blacklisted
        self.calls = []

    def is_whitelisted(self, ip):
        return self._wl

    def is_blacklisted(self, ip):
        return self._bl

    def blacklist(self, ip, *, reason, source, risk_score):
        self.calls.append((ip, reason, source, risk_score))
        self._bl = True


class NullAudit:
    """These tests are about decisions, so the log is out of the picture."""

    def write(self, decision):
        pass

    def check_writable(self):
        pass

    def session_ids_by_ip(self):
        return {}


def todays_inline_block(manager, *, ip, phase, conf, micro_state, phase_name):
    """The old condition and call, verbatim in logic (MT3_AUTO_BLACKLIST on)."""
    if (ip
            and phase >= MIN_PHASE
            and float(conf) >= MIN_CONF
            and not is_docker_bridge_addr(ip)
            and not manager.is_whitelisted(ip)
            and not manager.is_blacklisted(ip)):
        manager.blacklist(
            ip,
            reason=(f"MT3: {micro_state} "
                    f"(phase {phase} {phase_name}, "
                    f"conf {conf:.2f})"),
            source="mt3_pipeline",
            risk_score=float(conf),
        )


class TestSameAsToday(unittest.TestCase):

    def engine_for(self, manager, mode):
        cfg = load_config({"MITIGATION_MODE": mode})
        return build_engine(blacklist_manager=manager, divert_min_phase=MIN_PHASE,
                            min_confidence=MIN_CONF, config=cfg, audit=NullAudit())

    def test_same_blacklist_calls_on_every_combination(self):
        checked = 0
        for mode in ("observe", "enforce"):
            for ip in IPS:
                for phase in PHASES:
                    for conf in CONFS:
                        for wl, bl in STATES:
                            args = dict(ip=ip, phase=phase, conf=conf,
                                        micro_state="BRUTE_FORCE", phase_name="Initial Access")
                            old = FakeManager(wl, bl)
                            todays_inline_block(old, **args)

                            new = FakeManager(wl, bl)
                            self.engine_for(new, mode).handle(Verdict(
                                ip=ip, phase=phase, phase_name="Initial Access",
                                micro_state="BRUTE_FORCE", confidence=conf, session_id="s1"))

                            with self.subTest(mode=mode, ip=ip, phase=phase, conf=conf,
                                              whitelisted=wl, blacklisted=bl):
                                self.assertEqual(new.calls, old.calls)
                            checked += 1
        self.assertEqual(checked, 2 * len(IPS) * len(PHASES) * len(CONFS) * len(STATES))

    def test_at_least_some_combinations_really_blacklist(self):
        """Guards the test itself: if nothing ever blacklisted, 'equal' would mean nothing."""
        manager = FakeManager()
        self.engine_for(manager, "observe").handle(Verdict(
            ip="45.33.32.156", phase=3, phase_name="Discovery",
            micro_state="SYSTEM_INFO", confidence=0.9, session_id="s1"))
        self.assertEqual(manager.calls, [(
            "45.33.32.156", "MT3: SYSTEM_INFO (phase 3 Discovery, conf 0.90)",
            "mt3_pipeline", 0.9)])

    def test_the_only_deliberate_difference_is_text_that_is_not_an_ip(self):
        """The old code would have blacklisted any non-empty text. The new code
        will not, because that text could end up inside a firewall command."""
        old, new = FakeManager(), FakeManager()
        todays_inline_block(old, ip="not-an-ip", phase=3, conf=0.9,
                            micro_state="X", phase_name="Y")
        self.engine_for(new, "observe").handle(Verdict(
            ip="not-an-ip", phase=3, phase_name="Y", micro_state="X",
            confidence=0.9, session_id="s1"))
        self.assertEqual(len(old.calls), 1)
        self.assertEqual(new.calls, [])


if __name__ == "__main__":
    unittest.main()
