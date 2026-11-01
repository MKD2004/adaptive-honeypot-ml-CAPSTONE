"""
response_mitigation/tests/test_mitigation_firewall_executor.py

DENY, end to end up to the block list file: policy -> engine -> FirewallExecutor
-> blocklist.json. No firewall is touched; the host script is tested separately.

Also here: the engine no longer lets a failing executor check raise out of handle().
"""
import json
import tempfile
import unittest
from pathlib import Path

from response_mitigation.audit import AuditLog
from response_mitigation.blocklist import BlocklistFile
from response_mitigation.config import load_config
from response_mitigation.engine import MitigationEngine, build_engine
from response_mitigation.executors.firewall import FirewallExecutor
from response_mitigation.host import apply_blocklist as hb
from response_mitigation.models import Action, Mode, Outcome, PlannedAction, Verdict
from response_mitigation.safelist import Safelist

PUBLIC = "45.33.32.156"


class FakeManager:
    def __init__(self, whitelisted=()):
        self._wl = set(whitelisted)

    def is_whitelisted(self, ip):
        return ip in self._wl

    def is_blacklisted(self, ip):
        return False

    def blacklist(self, ip, **kwargs):
        pass


def verdict(ip=PUBLIC, phase=5, session="s1", conf=0.9):
    return Verdict(ip=ip, phase=phase, phase_name="Persistence", micro_state="CRON_PERSIST",
                   confidence=conf, session_id=session)


def deny(ttl=86400):
    return PlannedAction(Action.DENY, "repeat_offender", "3 sessions from this address", ttl)


class Case(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.blocklist_path = self.dir / "blocklist.json"

    def engine(self, **env):
        base = {"MITIGATION_MODE": "enforce", "MITIGATION_FIREWALL": "1",
                "MITIGATION_AUDIT_PATH": str(self.dir / "audit.jsonl"),
                "MITIGATION_KILL_FILE": str(self.dir / "STOP"),
                "MITIGATION_BLOCKLIST_PATH": str(self.blocklist_path)}
        cfg = load_config({**base, **env})
        return build_engine(blacklist_manager=FakeManager(), config=cfg, audit=AuditLog(cfg.audit_path))

    def three_sessions(self, engine, ip=PUBLIC, phase=5):
        """A repeat offender: DENY needs 3 sessions. Returns the third session's decisions."""
        for n in range(3):
            decisions = engine.handle(verdict(ip, phase, session=f"s{n}"))
        return decisions

    def deny_of(self, decisions):
        return next(d for d in decisions if d.planned.action is Action.DENY)

    def audit_lines(self):
        return [json.loads(line) for line in (self.dir / "audit.jsonl").read_text().splitlines()]


class TestTheExecutor(Case):

    def setUp(self):
        super().setUp()
        self.file = BlocklistFile(self.blocklist_path, clock=lambda: 1_800_000_000)
        self.executor = FirewallExecutor(self.file, default_ttl_s=7200)

    def test_apply_writes_the_block_and_reports_the_exact_command(self):
        note = self.executor.apply(verdict(), deny(ttl=86400))
        entry = self.file.get(PUBLIC)
        self.assertEqual(entry.expires_at, 1_800_000_000 + 86400)
        self.assertEqual((entry.rule, entry.session_id, entry.reason),
                         ("repeat_offender", "s1", "3 sessions from this address"))
        self.assertIn("nft add element inet honeypot_guard blocked_v4 { 45.33.32.156 timeout 86400s }", note)

    def test_a_plan_without_a_ttl_uses_the_default(self):
        self.executor.apply(verdict(), deny(ttl=None))
        self.assertEqual(self.file.get(PUBLIC).expires_at, 1_800_000_000 + 7200)

    def test_the_note_gives_the_expiry_in_plain_time(self):
        self.assertIn("until 2027-01-16T08:00:00Z", self.executor.apply(verdict(), deny(ttl=86400)))

    def test_an_ip_already_on_the_list_is_skipped(self):
        self.executor.apply(verdict(), deny())
        self.assertIn("already on the block list", self.executor.skip_reason(verdict(), deny()))
        self.assertIsNone(self.executor.skip_reason(verdict("8.8.8.8"), deny()))

    def test_an_address_that_must_never_be_blocked_is_refused_even_if_it_gets_this_far(self):
        for ip in ("10.0.0.1", "127.0.0.1", "172.17.0.1", "224.0.0.1", "not-an-ip", "1.2.3.4; reset"):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                self.executor.apply(verdict(ip), deny())
        self.assertFalse(self.blocklist_path.exists())


class TestDenyThroughTheEngine(Case):

    def test_a_repeat_offender_in_enforce_mode_lands_on_the_block_list(self):
        engine = self.engine()
        first = engine.handle(verdict(session="s0"))
        self.assertEqual([d.planned.action for d in first], [Action.DIVERT])
        decision = self.deny_of(self.three_sessions(engine))
        self.assertIs(decision.outcome, Outcome.APPLIED)
        self.assertIn("nft add element inet honeypot_guard blocked_v4", decision.detail)
        self.assertEqual([e.ip for e in BlocklistFile(self.blocklist_path).entries()], [PUBLIC])

    def test_the_audit_log_says_what_was_done(self):
        self.three_sessions(self.engine())
        denies = [line for line in self.audit_lines() if line["action"] == "deny"]
        self.assertEqual([(d["outcome"], d["rule"], d["ip"]) for d in denies],
                         [("applied", "repeat_offender", PUBLIC)])

    def test_the_same_ip_is_not_blocked_twice(self):
        engine = self.engine()
        self.three_sessions(engine)
        later = engine.handle(verdict(session="s9"))
        decision = self.deny_of(later)
        self.assertIs(decision.outcome, Outcome.SKIPPED)
        self.assertIn("already on the block list", decision.detail)
        self.assertEqual(len(BlocklistFile(self.blocklist_path).entries()), 1)

    def test_observe_mode_only_records_what_it_would_do(self):
        decision = self.deny_of(self.three_sessions(self.engine(MITIGATION_MODE="observe")))
        self.assertIs(decision.outcome, Outcome.WOULD_APPLY)
        self.assertFalse(self.blocklist_path.exists())

    def test_enforce_without_the_firewall_switch_does_not_block(self):
        decision = self.deny_of(self.three_sessions(self.engine(MITIGATION_FIREWALL="0")))
        self.assertIs(decision.outcome, Outcome.WOULD_APPLY)
        self.assertIn("MITIGATION_FIREWALL", decision.detail)
        self.assertFalse(self.blocklist_path.exists())

    def test_addresses_that_must_never_be_blocked_do_not_reach_the_file(self):
        for ip in ("10.0.0.7", "127.0.0.1", "172.17.0.1", "192.168.1.5"):
            with self.subTest(ip=ip):
                decision = self.deny_of(self.three_sessions(self.engine(), ip=ip))
                self.assertIs(decision.outcome, Outcome.SKIPPED)
        self.assertFalse(self.blocklist_path.exists())

    def test_the_admins_own_address_is_never_blocked(self):
        engine = self.engine(MITIGATION_NEVER_BLOCK="45.33.32.0/24")
        self.assertIn("never-block", self.deny_of(self.three_sessions(engine)).detail)
        self.assertFalse(self.blocklist_path.exists())

    def test_the_hourly_cap_stops_a_flood_of_blocks(self):
        engine = self.engine(MITIGATION_MAX_NEW_BLOCKS_PER_HOUR="2")
        results = [self.deny_of(self.three_sessions(engine, ip=f"45.33.32.{n}")).outcome for n in range(1, 5)]
        self.assertEqual(results, [Outcome.APPLIED, Outcome.APPLIED, Outcome.SKIPPED, Outcome.SKIPPED])
        self.assertEqual(len(BlocklistFile(self.blocklist_path).entries()), 2)

    def test_the_kill_switch_stops_blocking(self):
        engine = self.engine()
        (self.dir / "STOP").write_text("")
        self.assertEqual(self.three_sessions(engine), [])
        self.assertFalse(self.blocklist_path.exists())

    def test_the_block_lasts_as_long_as_the_setting_says(self):
        engine = self.engine(MITIGATION_DENY_TTL_HOURS="6")
        self.three_sessions(engine)
        entry = BlocklistFile(self.blocklist_path).get(PUBLIC)
        self.assertEqual(entry.expires_at - entry.added_at, 6 * 3600)

    def test_a_block_list_that_cannot_be_read_gives_a_failed_decision_not_a_crash(self):
        self.blocklist_path.write_bytes(b"{nope")
        engine = self.engine()
        with self.assertLogs("response_mitigation", level="ERROR"):
            decision = self.deny_of(self.three_sessions(engine))
        self.assertIs(decision.outcome, Outcome.FAILED)
        self.assertIn("BlocklistCorrupt", decision.detail)
        self.assertEqual(self.blocklist_path.read_bytes(), b"{nope")       # left for a person to look at
        self.assertEqual([l["outcome"] for l in self.audit_lines() if l["action"] == "deny"], ["failed"])

    def test_a_failed_block_does_not_use_up_the_hourly_cap(self):
        self.blocklist_path.write_bytes(b"{nope")
        engine = self.engine(MITIGATION_MAX_NEW_BLOCKS_PER_HOUR="1")
        with self.assertLogs("response_mitigation", level="ERROR"):
            self.three_sessions(engine)
        self.blocklist_path.unlink()
        decision = self.deny_of(self.three_sessions(engine, ip="8.8.8.8"))
        self.assertIs(decision.outcome, Outcome.APPLIED)


class TestAnExecutorThatFailsItsCheck(unittest.TestCase):
    """executor.skip_reason() used to sit outside the try block, so a failure there
    could escape handle() and reach the pipeline."""

    class Broken:
        def skip_reason(self, verdict, planned):
            raise RuntimeError("disk on fire")

        def apply(self, verdict, planned):
            raise AssertionError("must not be reached")

    def test_it_becomes_a_failed_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = load_config({"MITIGATION_MODE": "enforce", "MITIGATION_FIREWALL": "1",
                               "MITIGATION_KILL_FILE": str(Path(tmp) / "STOP")})
            engine = MitigationEngine(cfg, safelist=Safelist(), audit=AuditLog(Path(tmp) / "a.jsonl"),
                                      executors={Action.DENY: self.Broken()})
            with self.assertLogs("response_mitigation", level="ERROR"):
                for n in range(3):
                    decisions = engine.handle(verdict(session=f"s{n}"))
            decision = next(d for d in decisions if d.planned.action is Action.DENY)
        self.assertIs(decision.outcome, Outcome.FAILED)
        self.assertIn("disk on fire", decision.detail)


class TestEngineAndHostScriptAgreeOnWhatIsProtected(unittest.TestCase):
    """Two separate checks guard the same line: the engine's safelist before the
    file is written, and the host script before the firewall is touched. They must
    not disagree about which kinds of address are never blocked."""

    ADDRESSES = ["45.33.32.156", "172.217.14.206", "8.8.8.8", "2606:4700:4700::1111",
                 "127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "172.17.0.1", "172.31.255.255",
                 "169.254.1.1", "100.64.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1", "239.255.255.250",
                 "240.0.0.1", "203.0.113.5", "198.51.100.7", "::1", "fe80::1", "fc00::1", "ff02::1",
                 "2001:db8::1", "::ffff:10.0.0.1", "::ffff:45.33.32.156", "not-an-ip", "", "8.8.8.8/32"]

    def test_same_answer_for_every_address(self):
        safelist = Safelist()
        for text in self.ADDRESSES:
            engine_refuses = safelist.skip_reason(text, Action.DENY) is not None
            try:
                hb.public_address(text)
                script_refuses = False
            except ValueError:
                script_refuses = True
            with self.subTest(address=text):
                self.assertEqual(engine_refuses, script_refuses)


if __name__ == "__main__":
    unittest.main()
