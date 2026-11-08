"""
response_mitigation/tests/test_mitigation_engine.py

The engine end to end with stand-in executors: each mode, the safety checks, the
hourly cap, the kill switch, and the ways things can fail. Everything is written
into a temp folder and nothing touches a real blacklist or firewall.
"""
import dataclasses
import json
import tempfile
import unittest
from pathlib import Path

from response_mitigation.audit import AuditLog
from response_mitigation.config import load_config
from response_mitigation.engine import MitigationEngine
from response_mitigation.models import Action, Outcome, Verdict
from response_mitigation.safelist import Safelist

PUBLIC_IP = "45.33.32.156"


class FakeExecutor:
    def __init__(self, skip=None, fail=None):
        self.applied = []
        self._skip = skip
        self._fail = fail

    def skip_reason(self, verdict, planned):
        return self._skip

    def apply(self, verdict, planned):
        if self._fail:
            raise self._fail
        self.applied.append((verdict.ip, planned.action, planned.ttl_s))
        return "fake applied"


class _UnreadableKillFile:
    def exists(self):
        raise PermissionError("no access")


def verdict(ip=PUBLIC_IP, phase=5, conf=0.9, sid="s1") -> Verdict:
    return Verdict(ip=ip, phase=phase, phase_name=f"Phase{phase}",
                   micro_state="TEST_STATE", confidence=conf, session_id=sid)


def by_action(decisions):
    return {d.planned.action: d for d in decisions}


class EngineCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.audit_path = self.tmp / "audit.jsonl"
        self.kill_file = self.tmp / "STOP"
        self.now = 1_000_000.0
        self.divert, self.alert, self.deny = FakeExecutor(), FakeExecutor(), FakeExecutor()

    def make(self, mode="observe", firewall="0", cap="50", whitelisted=(),
             divert_enabled=True, executors=None, audit=None, env=None):
        cfg = load_config({
            "MITIGATION_MODE": mode,
            "MITIGATION_FIREWALL": firewall,
            "MITIGATION_MAX_NEW_BLOCKS_PER_HOUR": cap,
            "MITIGATION_KILL_FILE": str(self.kill_file),
            "MITIGATION_AUDIT_PATH": str(self.audit_path),
            **(env or {}),          # per-test overrides, e.g. the whitelist-override floors
        })
        self.audit = audit or AuditLog(self.audit_path)
        if executors is None:
            executors = {Action.DIVERT: self.divert, Action.ALERT: self.alert,
                         Action.DENY: self.deny}
        return MitigationEngine(
            cfg, safelist=Safelist(
                is_whitelisted=lambda ip: ip in whitelisted,
                # Mirror build_engine: the whitelist-override floors come from the
                # policy. Omitting them here silently pinned the Safelist to its
                # own defaults and made MITIGATION_WHITELIST_OVERRIDE_* inert in
                # these tests.
                override_min_phase=cfg.policy.whitelist_override_min_phase,
                override_min_confidence=cfg.policy.whitelist_override_min_confidence),
            audit=self.audit, executors=executors, divert_enabled=divert_enabled,
            clock=lambda: self.now)

    def sessions(self, engine, ip=PUBLIC_IP, n=3, phase=5, first=1):
        """n sessions from one IP, each a different session id. Returns the last result."""
        last = []
        for i in range(first, first + n):
            last = engine.handle(verdict(ip=ip, phase=phase, sid=f"{ip}-{i}"))
        return last

    def audit_lines(self):
        return [json.loads(x) for x in self.audit_path.read_text(encoding="utf-8").splitlines()]


class TestModes(EngineCase):

    def test_off_does_nothing_at_all(self):
        engine = self.make(mode="off")
        self.assertEqual(engine.handle(verdict(phase=8)), [])
        self.assertFalse(self.audit_path.exists())
        self.assertEqual(self.divert.applied, [])

    def test_observe_diverts_but_only_logs_the_rest(self):
        engine = self.make(mode="observe", firewall="1")
        result = by_action(self.sessions(engine, phase=8))
        self.assertEqual(result[Action.DIVERT].outcome, Outcome.APPLIED)
        self.assertEqual(result[Action.ALERT].outcome, Outcome.WOULD_APPLY)
        self.assertEqual(result[Action.DENY].outcome, Outcome.WOULD_APPLY)
        self.assertIn("observe", result[Action.DENY].detail)
        self.assertEqual(len(self.divert.applied), 3)   # one per session
        self.assertEqual(self.alert.applied, [])
        self.assertEqual(self.deny.applied, [])

    def test_enforce_without_firewall_alerts_but_does_not_deny(self):
        engine = self.make(mode="enforce", firewall="0")
        result = by_action(self.sessions(engine, phase=8))
        self.assertEqual(result[Action.ALERT].outcome, Outcome.APPLIED)
        self.assertEqual(result[Action.DENY].outcome, Outcome.WOULD_APPLY)
        self.assertIn("MITIGATION_FIREWALL", result[Action.DENY].detail)
        self.assertEqual(self.deny.applied, [])

    def test_enforce_with_firewall_denies_with_a_lifetime(self):
        engine = self.make(mode="enforce", firewall="1")
        result = by_action(self.sessions(engine, phase=8))
        self.assertEqual(result[Action.DENY].outcome, Outcome.APPLIED)
        self.assertEqual(self.deny.applied, [(PUBLIC_IP, Action.DENY, 24 * 3600)])

    def test_the_mode_is_written_on_every_audit_line(self):
        self.make(mode="enforce", firewall="1").handle(verdict(phase=8))
        self.assertEqual({r["mode"] for r in self.audit_lines()}, {"enforce"})

    def test_a_missing_executor_is_a_skip_not_a_crash(self):
        engine = self.make(mode="enforce", firewall="1",
                           executors={Action.DIVERT: self.divert})
        result = by_action(engine.handle(verdict(phase=8)))
        self.assertEqual(result[Action.ALERT].outcome, Outcome.SKIPPED)
        self.assertIn("alert executor", result[Action.ALERT].detail)

    def test_observe_mode_reports_would_apply_even_with_no_executor(self):
        engine = self.make(mode="observe", executors={Action.DIVERT: self.divert})
        result = by_action(self.sessions(engine, phase=8))
        self.assertEqual(result[Action.DENY].outcome, Outcome.WOULD_APPLY)


class TestKillSwitch(EngineCase):

    def test_kill_file_stops_everything_and_is_checked_every_call(self):
        engine = self.make(mode="enforce", firewall="1")
        self.kill_file.write_text("stop")
        self.assertEqual(engine.handle(verdict(phase=8)), [])
        self.assertEqual(self.divert.applied, [])
        self.kill_file.unlink()
        self.assertTrue(engine.handle(verdict(phase=8)))
        self.kill_file.write_text("stop")
        self.assertEqual(engine.handle(verdict(phase=8, sid="s2")), [])

    def test_if_the_kill_file_cannot_be_checked_the_engine_stops(self):
        engine = self.make(mode="enforce", firewall="1")
        engine.config = dataclasses.replace(engine.config, kill_file=_UnreadableKillFile())
        self.assertEqual(engine.handle(verdict(phase=8)), [])
        self.assertEqual(self.divert.applied, [])


class TestSafety(EngineCase):

    def test_private_address_is_diverted_but_never_denied(self):
        engine = self.make(mode="enforce", firewall="1")
        result = by_action(self.sessions(engine, ip="192.168.1.5"))
        self.assertEqual(result[Action.DIVERT].outcome, Outcome.APPLIED)   # the demo case
        self.assertEqual(result[Action.DENY].outcome, Outcome.SKIPPED)
        self.assertIn("not a public", result[Action.DENY].detail)
        self.assertEqual(self.deny.applied, [])

    def test_docker_bridge_is_neither_diverted_nor_denied(self):
        engine = self.make(mode="enforce", firewall="1")
        result = by_action(self.sessions(engine, ip="172.17.0.1"))
        for action in (Action.DIVERT, Action.DENY):
            self.assertEqual(result[action].outcome, Outcome.SKIPPED)
            self.assertIn("Docker bridge", result[action].detail)
        self.assertEqual(self.divert.applied, [])
        self.assertEqual(self.deny.applied, [])

    def test_public_172_address_is_not_mistaken_for_docker(self):
        engine = self.make(mode="enforce", firewall="1")
        result = by_action(self.sessions(engine, ip="172.217.14.206"))
        self.assertEqual(result[Action.DIVERT].outcome, Outcome.APPLIED)
        self.assertEqual(result[Action.DENY].outcome, Outcome.APPLIED)

    def test_whitelisted_address_is_left_alone_on_a_weak_verdict(self):
        """A whitelist still protects when the evidence is ordinary.

        Changed 2026-11-04: this used to assert the whitelist protects against
        EVERY verdict, at any phase and confidence. That was the bypass
        HONEYPOT_AUDIT.md PART 3 called the most serious finding in the project --
        an attacker who earned a whitelist (about 70 minutes of good behaviour
        through the promoter) became immune to the detection half of the system.
        Now a strong verdict can override it for DIVERT; see the next test.
        """
        engine = self.make(mode="enforce", firewall="1", whitelisted={PUBLIC_IP},
                           env={"MITIGATION_WHITELIST_OVERRIDE_MIN_PHASE": "8",
                                "MITIGATION_WHITELIST_OVERRIDE_MIN_CONF": "1.0"})
        result = by_action(self.sessions(engine))
        self.assertEqual(result[Action.DIVERT].detail, "whitelisted")
        self.assertEqual(result[Action.DENY].detail, "whitelisted")
        self.assertEqual(self.divert.applied + self.deny.applied, [])

    def test_a_strong_verdict_overrides_a_whitelist_for_divert_but_never_for_deny(self):
        """The fix for the PART 3 whitelist bypass.

        DIVERT only re-routes to the honeypot and is reversible, so a confident
        high-phase verdict may override explicit trust. DENY is a firewall drop
        that can cut off admin access, so a whitelist always wins there -- that
        asymmetry is the whole point, and it is why this is one test.
        """
        engine = self.make(mode="enforce", firewall="1", whitelisted={PUBLIC_IP})
        result = by_action(self.sessions(engine))
        self.assertEqual(result[Action.DIVERT].outcome, Outcome.APPLIED,
                         "a strong verdict must be able to divert a trusted address")
        self.assertEqual(result[Action.DENY].detail, "whitelisted",
                         "a whitelist must NEVER be overridden for a firewall drop")
        self.assertEqual(self.deny.applied, [])
        self.assertNotEqual(self.divert.applied, [])

    def test_already_blacklisted_is_a_skip(self):
        self.divert = FakeExecutor(skip="already blacklisted")
        engine = self.make()
        result = by_action(engine.handle(verdict()))
        self.assertEqual(result[Action.DIVERT].outcome, Outcome.SKIPPED)
        self.assertEqual(result[Action.DIVERT].detail, "already blacklisted")

    def test_auto_blacklist_switched_off_skips_divert_only(self):
        engine = self.make(mode="enforce", firewall="1", divert_enabled=False)
        result = by_action(self.sessions(engine, phase=8))
        self.assertEqual(result[Action.DIVERT].outcome, Outcome.SKIPPED)
        self.assertIn("GATEWAY_MT3_AUTO_BLACKLIST", result[Action.DIVERT].detail)
        self.assertEqual(result[Action.DENY].outcome, Outcome.APPLIED)

    def test_text_that_is_not_an_ip_is_recorded_and_never_acted_on(self):
        engine = self.make(mode="enforce", firewall="1")
        result = engine.handle(verdict(ip="8.8.8.8; rm -rf /", phase=8))
        self.assertEqual(by_action(result)[Action.DIVERT].outcome, Outcome.SKIPPED)
        self.assertEqual(by_action(result)[Action.DIVERT].detail, "not a valid IP address")
        self.assertEqual(self.divert.applied, [])
        self.assertEqual(self.deny.applied, [])
        # An ALERT only tells a human, so it may still go out. The bad text is
        # kept in the log exactly as received, so someone can see what arrived.
        self.assertEqual(self.audit_lines()[0]["ip"], "8.8.8.8; rm -rf /")

    def test_the_clean_text_form_of_the_ip_is_used(self):
        engine = self.make()
        engine.handle(verdict(ip=" 45.33.32.156 "))
        self.assertEqual(self.divert.applied[0][0], "45.33.32.156")
        self.assertEqual({r["ip"] for r in self.audit_lines()}, {"45.33.32.156"})


class TestHourlyCap(EngineCase):

    def deny_three(self, engine, ips):
        return [by_action(self.sessions(engine, ip=ip, phase=5))[Action.DENY] for ip in ips]

    def test_cap_stops_new_blocks_until_the_hour_is_up(self):
        engine = self.make(mode="enforce", firewall="1", cap="2")
        first, second, third = self.deny_three(engine, ["45.33.32.1", "45.33.32.2", "45.33.32.3"])
        self.assertEqual([first.outcome, second.outcome], [Outcome.APPLIED, Outcome.APPLIED])
        self.assertEqual(third.outcome, Outcome.SKIPPED)
        self.assertIn("hourly cap of 2", third.detail)
        self.now += 3599
        self.assertEqual(by_action(self.sessions(engine, ip="45.33.32.4", first=1))[Action.DENY].outcome,
                         Outcome.SKIPPED)
        self.now += 2   # now more than an hour since the first two
        self.assertEqual(by_action(self.sessions(engine, ip="45.33.32.5", first=1))[Action.DENY].outcome,
                         Outcome.APPLIED)

    def test_a_cap_of_zero_blocks_nothing(self):
        engine = self.make(mode="enforce", firewall="1", cap="0")
        denied = by_action(self.sessions(engine))[Action.DENY]
        self.assertEqual(denied.outcome, Outcome.SKIPPED)
        self.assertEqual(self.deny.applied, [])

    def test_skips_and_would_applies_do_not_use_up_the_cap(self):
        engine = self.make(mode="enforce", firewall="1", cap="1")
        self.sessions(engine, ip="192.168.1.5")                 # skipped: private
        self.sessions(engine, ip="172.17.0.1")                  # skipped: Docker bridge
        denied = by_action(self.sessions(engine))[Action.DENY]  # the one real block
        self.assertEqual(denied.outcome, Outcome.APPLIED)

    def test_a_failed_block_does_not_use_up_the_cap(self):
        self.deny = FakeExecutor(fail=RuntimeError("boom"))
        engine = self.make(mode="enforce", firewall="1", cap="1")
        self.assertEqual(by_action(self.sessions(engine, ip="45.33.32.1"))[Action.DENY].outcome,
                         Outcome.FAILED)
        self.deny._fail = None
        self.assertEqual(by_action(self.sessions(engine, ip="45.33.32.2"))[Action.DENY].outcome,
                         Outcome.APPLIED)


class TestFailures(EngineCase):

    def test_a_failing_executor_is_recorded_and_the_rest_still_run(self):
        self.divert = FakeExecutor(fail=RuntimeError("boom"))
        engine = self.make(mode="enforce", firewall="1")
        result = by_action(engine.handle(verdict(phase=8)))      # must not raise
        self.assertEqual(result[Action.DIVERT].outcome, Outcome.FAILED)
        self.assertIn("RuntimeError: boom", result[Action.DIVERT].detail)
        self.assertEqual(result[Action.ALERT].outcome, Outcome.APPLIED)

    def test_unwritable_audit_log_refuses_deny_but_not_divert(self):
        blocker = self.tmp / "afile"
        blocker.write_text("not a folder")
        engine = self.make(mode="enforce", firewall="1", audit=AuditLog(blocker / "audit.jsonl"))
        result = by_action(self.sessions(engine))                # must not raise
        self.assertEqual(result[Action.DENY].outcome, Outcome.SKIPPED)
        self.assertIn("audit log is not writable", result[Action.DENY].detail)
        self.assertEqual(self.deny.applied, [])
        self.assertEqual(result[Action.DIVERT].outcome, Outcome.APPLIED)


class TestSessionCounting(EngineCase):

    def test_third_distinct_session_makes_a_repeat_offender(self):
        engine = self.make(mode="observe")
        self.assertNotIn(Action.DENY, by_action(self.sessions(engine, n=2)))
        result = by_action(engine.handle(verdict(sid="third")))
        self.assertEqual(result[Action.DENY].verdict.sessions_seen, 3)

    def test_the_same_session_twice_counts_once(self):
        engine = self.make()
        engine.handle(verdict(sid="same"))
        again = engine.handle(verdict(sid="same"))
        self.assertEqual(again[0].verdict.sessions_seen, 1)

    def test_each_address_is_counted_separately(self):
        engine = self.make()
        self.sessions(engine, ip="45.33.32.1", n=2)
        other = engine.handle(verdict(ip="45.33.32.2", sid="x"))
        self.assertEqual(other[0].verdict.sessions_seen, 1)

    def test_counts_survive_a_restart(self):
        self.sessions(self.make(), n=2)
        restarted = self.make()
        result = by_action(restarted.handle(verdict(sid="third")))
        self.assertEqual(result[Action.DENY].verdict.sessions_seen, 3)


class TestAuditTrail(EngineCase):

    def test_one_audit_line_per_decision_with_matching_ids(self):
        engine = self.make(mode="enforce", firewall="1")
        decisions = self.sessions(engine, phase=8)
        lines = self.audit_lines()
        last_three = lines[-len(decisions):]
        self.assertEqual([r["decision_id"] for r in last_three],
                         [d.decision_id for d in decisions])
        self.assertEqual([r["action"] for r in last_three], ["divert", "alert", "deny"])
        self.assertTrue(all(r["reason"] for r in last_three))

    def test_observe_only_verdicts_are_recorded_too(self):
        engine = self.make()
        engine.handle(verdict(phase=0))
        rec = self.audit_lines()[0]
        self.assertEqual((rec["action"], rec["outcome"]), ("observe", "applied"))


if __name__ == "__main__":
    unittest.main()
