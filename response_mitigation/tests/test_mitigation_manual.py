"""
response_mitigation/tests/test_mitigation_manual.py

Things a person does through the engine: block an address at the firewall, lift a block, switch the
kill switch, and ask what is going on. Used by the command line and the dashboard.

What must hold: a person can act in every mode, but never past the safety checks; every action is
written to the audit log with the person's name; a broken file gives a FAILED decision, never a crash.
"""
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from response_mitigation.audit import AuditLog
from response_mitigation.config import load_config
from response_mitigation.engine import build_engine
from response_mitigation.models import Action, Outcome, Verdict

PUBLIC = "45.33.32.156"
WHO = "cli:anushka"


class FakeManager:
    def __init__(self, whitelisted=()):
        self._wl = set(whitelisted)

    def is_whitelisted(self, ip):
        return ip in self._wl

    def is_blacklisted(self, ip):
        return False

    def blacklist(self, ip, **kw):
        pass


class Case(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.bl, self.kill = self.dir / "bl.json", self.dir / "STOP"

    def engine(self, manager=None, own=(), **env):
        base = {"MITIGATION_AUDIT_PATH": str(self.dir / "audit.jsonl"), "MITIGATION_KILL_FILE": str(self.kill),
                "MITIGATION_BLOCKLIST_PATH": str(self.bl)}
        cfg = load_config({**base, **env})
        return build_engine(blacklist_manager=manager, config=cfg, audit=AuditLog(cfg.audit_path), own_addresses=own)

    def audit(self):
        path = self.dir / "audit.jsonl"
        return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


class TestBlockingAtTheFirewall(Case):

    def test_a_person_can_block_a_public_address(self):
        d = self.engine().firewall_block(PUBLIC, reason="scanning us", actor=WHO, hours=6)
        self.assertIs(d.outcome, Outcome.APPLIED)
        entry, = self.engine().active_blocks()
        self.assertEqual((entry.ip, entry.rule, entry.reason, entry.expires_at - entry.added_at),
                         (PUBLIC, "manual_block", "scanning us", 6 * 3600))
        self.assertIn("host script applies it", d.detail)

    def test_the_audit_line_says_who_did_it(self):
        self.engine().firewall_block(PUBLIC, reason="r", actor=WHO, hours=1)
        line, = self.audit()
        self.assertEqual((line["actor"], line["action"], line["rule"], line["outcome"], line["ip"], line["ttl_s"]),
                         (WHO, "deny", "manual_block", "applied", PUBLIC, 3600))
        self.assertEqual((line["phase"], line["micro_state"]), (-1, "manual"))      # no model verdict behind it

    def test_it_works_in_every_mode_and_with_the_automatic_firewall_off(self):
        for mode in ("off", "observe", "enforce"):
            for fw in ("0", "1"):
                with self.subTest(mode=mode, firewall=fw):
                    self.bl.unlink(missing_ok=True)
                    d = self.engine(MITIGATION_MODE=mode, MITIGATION_FIREWALL=fw).firewall_block(PUBLIC, reason="r", actor=WHO)
                    self.assertIs(d.outcome, Outcome.APPLIED)

    def test_the_default_block_time_is_the_configured_one(self):
        self.engine(MITIGATION_DENY_TTL_HOURS="6").firewall_block(PUBLIC, reason="r", actor=WHO)
        entry, = self.engine().active_blocks()
        self.assertEqual(entry.expires_at - entry.added_at, 6 * 3600)

    def test_addresses_that_must_never_be_blocked_are_refused_even_for_a_person(self):
        engine = self.engine(FakeManager(whitelisted={"8.8.8.8"}), own=["1.1.1.1"], MITIGATION_NEVER_BLOCK="9.9.9.0/24")
        for ip, word in (("10.0.0.5", "public"), ("127.0.0.1", "public"), ("172.17.0.1", "Docker"),
                         ("192.168.1.1", "public"), ("224.0.0.1", "public"), ("8.8.8.8", "whitelisted"),
                         ("1.1.1.1", "own address"), ("9.9.9.7", "never-block")):
            with self.subTest(ip=ip):
                d = engine.firewall_block(ip, reason="r", actor=WHO)
                self.assertIs(d.outcome, Outcome.SKIPPED)
                self.assertIn(word, d.detail)
        self.assertEqual(engine.active_blocks(), [])
        self.assertEqual({l["outcome"] for l in self.audit()}, {"skipped"})            # each refusal is on record too

    def test_text_that_is_not_an_address_is_refused(self):
        for text in ("not-an-ip", "", "1.2.3.4; flush ruleset", None, 5):
            with self.subTest(text=text):
                self.assertIs(self.engine().firewall_block(text, reason="r", actor=WHO).outcome, Outcome.SKIPPED)
        self.assertFalse(self.bl.exists())

    def test_the_number_of_hours_is_checked(self):
        for hours in (0, -1, 721, 1.5, "5", True):
            with self.subTest(hours=hours):
                d = self.engine().firewall_block(PUBLIC, reason="r", actor=WHO, hours=hours)
                self.assertIs(d.outcome, Outcome.SKIPPED)
                self.assertIn("1 to 720", d.detail)
        self.assertFalse(self.bl.exists())

    def test_blocking_twice_says_so(self):
        engine = self.engine()
        engine.firewall_block(PUBLIC, reason="r", actor=WHO)
        d = engine.firewall_block(PUBLIC, reason="again", actor=WHO)
        self.assertIs(d.outcome, Outcome.SKIPPED)
        self.assertIn("already on the block list", d.detail)
        self.assertEqual(len(engine.active_blocks()), 1)

    def test_it_refuses_while_the_kill_switch_is_on(self):
        engine = self.engine()
        engine.set_kill_switch(True, actor=WHO)
        d = engine.firewall_block(PUBLIC, reason="r", actor=WHO)
        self.assertIs(d.outcome, Outcome.SKIPPED)
        self.assertIn("kill switch", d.detail)
        self.assertEqual(engine.active_blocks(), [])

    def test_it_never_blocks_anyone_it_cannot_write_down(self):
        engine = self.engine()
        with patch.object(AuditLog, "check_writable", side_effect=PermissionError("read-only")):
            d = engine.firewall_block(PUBLIC, reason="r", actor=WHO)
        self.assertIs(d.outcome, Outcome.SKIPPED)
        self.assertIn("audit log is not writable", d.detail)
        self.assertEqual(engine.active_blocks(), [])

    def test_a_broken_block_list_gives_a_failed_decision_not_a_crash(self):
        self.bl.write_bytes(b"{nope")
        engine = self.engine()
        with self.assertLogs("response_mitigation", level="ERROR"):
            d = engine.firewall_block(PUBLIC, reason="r", actor=WHO)
        self.assertIs(d.outcome, Outcome.FAILED)
        self.assertIn("BlocklistCorrupt", d.detail)
        self.assertEqual(self.bl.read_bytes(), b"{nope")

    def test_manual_blocks_do_not_use_up_the_automatic_hourly_cap(self):
        engine = self.engine(MITIGATION_MAX_NEW_BLOCKS_PER_HOUR="1")
        for ip in ("45.33.32.1", "45.33.32.2", "45.33.32.3"):
            self.assertIs(engine.firewall_block(ip, reason="r", actor=WHO).outcome, Outcome.APPLIED)
        self.assertEqual(engine.status()["new_blocks_this_hour"], 0)

    def test_many_threads_blocking_at_once_lose_nothing(self):
        engine = self.engine()
        ips = [f"45.33.32.{i}" for i in range(1, 31)]
        threads = [threading.Thread(target=engine.firewall_block, args=(ip,), kwargs=dict(reason="r", actor=WHO)) for ip in ips]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(e.ip for e in engine.active_blocks()), sorted(ips))
        self.assertEqual(len(self.audit()), 30)


class TestLiftingABlock(Case):

    def test_it_comes_off_the_list(self):
        engine = self.engine()
        engine.firewall_block(PUBLIC, reason="r", actor=WHO)
        d = engine.firewall_unblock(PUBLIC, actor="dashboard", reason="mistake")
        self.assertIs(d.outcome, Outcome.APPLIED)
        self.assertEqual(engine.active_blocks(), [])
        last = self.audit()[-1]
        self.assertEqual((last["actor"], last["rule"], last["reason"]), ("dashboard", "manual_unblock", "mistake"))

    def test_not_blocked_is_not_an_error(self):
        d = self.engine().firewall_unblock(PUBLIC, actor=WHO)
        self.assertIs(d.outcome, Outcome.SKIPPED)
        self.assertEqual(d.detail, "not on the block list")

    def test_it_works_whatever_the_kill_switch_says(self):
        engine = self.engine()
        engine.firewall_block(PUBLIC, reason="r", actor=WHO)
        engine.set_kill_switch(True, actor=WHO)
        self.assertIs(engine.firewall_unblock(PUBLIC, actor=WHO).outcome, Outcome.APPLIED)

    def test_the_other_blocks_stay(self):
        engine = self.engine()
        engine.firewall_block(PUBLIC, reason="r", actor=WHO)
        engine.firewall_block("8.8.8.8", reason="r", actor=WHO)
        engine.firewall_unblock(PUBLIC, actor=WHO)
        self.assertEqual([e.ip for e in engine.active_blocks()], ["8.8.8.8"])

    def test_a_broken_list_gives_a_failed_decision(self):
        self.bl.write_bytes(b"{nope")
        with self.assertLogs("response_mitigation", level="ERROR"):
            self.assertIs(self.engine().firewall_unblock(PUBLIC, actor=WHO).outcome, Outcome.FAILED)


class TestTheKillSwitch(Case):

    def test_on_and_off(self):
        engine = self.engine()
        self.assertFalse(engine.kill_switch_active())
        self.assertIs(engine.set_kill_switch(True, actor=WHO).outcome, Outcome.APPLIED)
        self.assertTrue(self.kill.exists())
        self.assertIn(WHO, self.kill.read_text(encoding="utf-8"))          # the file says who set it
        self.assertTrue(engine.kill_switch_active())
        self.assertIs(engine.set_kill_switch(False, actor=WHO).outcome, Outcome.APPLIED)
        self.assertFalse(self.kill.exists())

    def test_turning_it_off_when_it_is_already_off_is_fine(self):
        self.assertIs(self.engine().set_kill_switch(False, actor=WHO).outcome, Outcome.APPLIED)

    def test_while_it_is_on_nothing_automatic_happens(self):
        engine = self.engine(MITIGATION_MODE="enforce", MITIGATION_FIREWALL="1")
        engine.set_kill_switch(True, actor=WHO)
        self.assertEqual(engine.handle(Verdict(PUBLIC, 5, "Persistence", "X", 0.9, "s1")), [])

    def test_both_changes_are_in_the_audit_log(self):
        engine = self.engine()
        engine.set_kill_switch(True, actor=WHO)
        engine.set_kill_switch(False, actor="dashboard")
        self.assertEqual([(l["rule"], l["actor"]) for l in self.audit()],
                         [("kill_switch_on", WHO), ("kill_switch_off", "dashboard")])

    def test_a_file_that_cannot_be_made_gives_a_failed_decision(self):
        self.kill.mkdir()                                                   # a folder where the file should be
        d = self.engine().set_kill_switch(False, actor=WHO)
        self.assertIs(d.outcome, Outcome.FAILED)


class TestWritingDownWhatAPersonDid(Case):

    def test_a_dashboard_click_is_recorded_with_the_name(self):
        engine = self.engine()
        engine.record_manual(Action.DIVERT, PUBLIC, rule="manual_block", reason="blocked live from dashboard", actor="dashboard")
        engine.record_manual(Action.OBSERVE, PUBLIC, rule="manual_trust", reason="trusted", actor="dashboard")
        self.assertEqual([(l["action"], l["rule"], l["actor"], l["outcome"]) for l in self.audit()],
                         [("divert", "manual_block", "dashboard", "applied"), ("observe", "manual_trust", "dashboard", "applied")])

    def test_automatic_decisions_say_policy(self):
        engine = self.engine(FakeManager())
        engine.handle(Verdict(PUBLIC, 3, "Discovery", "X", 0.9, "s1"))
        self.assertEqual({l["actor"] for l in self.audit()}, {"policy"})


class TestAskingWhatIsGoingOn(Case):

    def test_status(self):
        engine = self.engine(MITIGATION_MODE="enforce", MITIGATION_FIREWALL="1", MITIGATION_NEVER_BLOCK="9.9.9.0/24",
                             MITIGATION_ALERT_WEBHOOK="http://127.0.0.1:9/secret-path")
        engine.firewall_block(PUBLIC, reason="r", actor=WHO)
        s = engine.status()
        self.assertEqual((s["mode"], s["effective_mode"], s["firewall_enabled"], s["kill_switch"], s["active_blocks"]),
                         ("enforce", "enforce", True, False, 1))
        self.assertEqual(s["never_block"], ["9.9.9.0/24"])
        self.assertIs(s["alert_webhook"], True)
        self.assertNotIn("secret-path", json.dumps(s))                       # the URL is never shown
        engine.set_kill_switch(True, actor=WHO)
        self.assertEqual(engine.status()["effective_mode"], "off")
        json.dumps(engine.status())                                          # plain values only

    def test_the_hourly_count_follows_automatic_blocks(self):
        engine = self.engine(MITIGATION_MODE="enforce", MITIGATION_FIREWALL="1")
        for n in range(3):
            engine.handle(Verdict(PUBLIC, 5, "Persistence", "X", 0.9, f"s{n}"))
        self.assertEqual(engine.status()["new_blocks_this_hour"], 1)

    def test_a_broken_block_list_does_not_break_status(self):
        self.bl.write_bytes(b"{nope")
        self.assertIsNone(self.engine().status()["active_blocks"])

    def test_recent_decisions(self):
        engine = self.engine()
        engine.firewall_block(PUBLIC, reason="r", actor=WHO)
        engine.firewall_block("8.8.8.8", reason="r", actor=WHO)
        self.assertEqual([d["ip"] for d in engine.recent_decisions(10)], ["8.8.8.8", PUBLIC])
        self.assertEqual([d["ip"] for d in engine.recent_decisions(10, ip=PUBLIC)], [PUBLIC])


class TestAnEngineWithoutAGateway(Case):
    """The command-line tool has no gateway, so there is no blacklist to divert to."""

    def test_divert_is_simply_not_set_up(self):
        engine = self.engine(None)
        decisions = engine.handle(Verdict(PUBLIC, 3, "Discovery", "X", 0.9, "s1"))
        divert = next(d for d in decisions if d.planned.action is Action.DIVERT)
        self.assertIs(divert.outcome, Outcome.SKIPPED)
        self.assertIn("no divert executor", divert.detail)

    def test_the_firewall_side_still_works(self):
        engine = self.engine(None, MITIGATION_MODE="enforce", MITIGATION_FIREWALL="1")
        for n in range(3):
            decisions = engine.handle(Verdict(PUBLIC, 5, "Persistence", "X", 0.9, f"s{n}"))
        self.assertIs(next(d for d in decisions if d.planned.action is Action.DENY).outcome, Outcome.APPLIED)


if __name__ == "__main__":
    unittest.main()
