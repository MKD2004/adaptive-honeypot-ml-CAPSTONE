"""
response_mitigation/tests/test_mitigation_cli.py

`python -m response_mitigation ...`: what a person types on the server. Every command is run against
temporary files. One test runs the real `python -m` in a separate process.
"""
import datetime as dt
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from response_mitigation import cli

REPO = Path(__file__).resolve().parents[2]
PUBLIC = "45.33.32.156"


class Case(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.env = {"MITIGATION_AUDIT_PATH": str(self.dir / "audit.jsonl"), "MITIGATION_KILL_FILE": str(self.dir / "STOP"),
                    "MITIGATION_BLOCKLIST_PATH": str(self.dir / "bl.json"), "MITIGATION_NEVER_BLOCK": "9.9.9.0/24"}
        patcher = patch("getpass.getuser", return_value="anushka")
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, *argv, env=None):
        out = io.StringIO()
        code = cli.main(list(argv), env={**self.env, **(env or {})}, out=out)
        return code, out.getvalue()


class TestStatusAndBlocks(Case):

    def test_status_in_words(self):
        code, text = self.run_cli("status")
        self.assertEqual(code, 0)
        for part in ("Mode: observe", "Firewall blocking by the pipeline: off", "Active firewall blocks: 0",
                     "Never blocked: 9.9.9.0/24", "Chat alerts: off"):
            self.assertIn(part, text)
        self.assertNotIn("KILL SWITCH", text)

    def test_status_warns_when_nothing_is_protected(self):
        self.env.pop("MITIGATION_NEVER_BLOCK")
        self.assertIn("add your own address", self.run_cli("status")[1])

    def test_status_as_json(self):
        code, text = self.run_cli("status", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)["effective_mode"], "observe")

    def test_blocks_when_there_are_none(self):
        self.assertEqual(self.run_cli("blocks"), (0, "No active firewall blocks.\n"))

    def test_the_list_of_blocks(self):
        self.run_cli("block", PUBLIC, "--hours", "5", "--reason", "scanner")
        code, text = self.run_cli("blocks")
        self.assertEqual(code, 0)
        self.assertIn("1 active firewall block(s):", text)
        for part in (PUBLIC, "manual_block", "scanner", "4 h"):                  # a little under 5 h left
            self.assertIn(part, text)
        entries = json.loads(self.run_cli("blocks", "--json")[1])
        self.assertEqual([e["ip"] for e in entries], [PUBLIC])

    def test_a_block_list_that_cannot_be_read_is_reported(self):
        (self.dir / "bl.json").write_bytes(b"{nope")
        code, text = self.run_cli("blocks")
        self.assertEqual(code, 1)
        self.assertIn("cannot be read", text)
        self.assertIn("unknown (block list unreadable)", self.run_cli("status")[1])


class TestBlockAndUnblock(Case):

    def test_block_then_unblock(self):
        code, text = self.run_cli("block", PUBLIC)
        self.assertEqual(code, 0)
        self.assertIn(f"Blocked {PUBLIC}.", text)
        self.assertIn("host script applies it", text)
        code, text = self.run_cli("unblock", PUBLIC)
        self.assertEqual((code, "Unblocked" in text), (0, True))
        self.assertEqual(self.run_cli("blocks")[1], "No active firewall blocks.\n")

    def test_a_refusal_says_why_and_exits_1(self):
        for ip, word in (("10.0.0.5", "public"), ("172.17.0.1", "Docker"), ("9.9.9.9", "never-block"), ("nonsense", "not a valid")):
            with self.subTest(ip=ip):
                code, text = self.run_cli("block", ip)
                self.assertEqual(code, 1)
                self.assertTrue(text.startswith("Not done:"), text)
                self.assertIn(word, text)

    def test_hours_are_checked(self):
        code, text = self.run_cli("block", PUBLIC, "--hours", "9999")
        self.assertEqual(code, 1)
        self.assertIn("1 to 720", text)

    def test_unblocking_something_not_blocked_exits_1(self):
        code, text = self.run_cli("unblock", PUBLIC)
        self.assertEqual(code, 1)
        self.assertIn("not on the block list", text)

    def test_it_works_with_the_automatic_firewall_off_and_in_every_mode(self):
        self.assertEqual(self.run_cli("block", PUBLIC, env={"MITIGATION_MODE": "off", "MITIGATION_FIREWALL": "0"})[0], 0)


class TestTheKillSwitch(Case):

    def test_off_and_on(self):
        code, text = self.run_cli("off")
        self.assertEqual(code, 0)
        self.assertIn("Kill switch is ON", text)
        self.assertTrue((self.dir / "STOP").exists())
        self.assertIn("KILL SWITCH IS ON", self.run_cli("status")[1])
        self.assertEqual(self.run_cli("block", PUBLIC)[0], 1)                  # refused while it is on
        code, text = self.run_cli("on")
        self.assertEqual(code, 0)
        self.assertIn("Kill switch is OFF", text)
        self.assertFalse((self.dir / "STOP").exists())

    def test_a_problem_is_reported(self):
        (self.dir / "STOP").mkdir()
        code, text = self.run_cli("on")
        self.assertEqual(code, 1)
        self.assertTrue(text.startswith("FAILED"))


class TestTheAuditLog(Case):

    def test_every_change_names_the_person(self):
        self.run_cli("block", PUBLIC)
        self.run_cli("unblock", PUBLIC)
        self.run_cli("off")
        code, text = self.run_cli("audit", "--tail", "10")
        self.assertEqual(code, 0)
        self.assertEqual(text.count("cli:anushka"), 3)
        self.assertLess(text.index("kill_switch_on"), text.index("manual_unblock"))        # newest first
        self.assertLess(text.index("manual_unblock"), text.index("manual_block"))

    def test_one_address_only(self):
        self.run_cli("block", PUBLIC)
        self.run_cli("block", "8.8.8.8")
        code, text = self.run_cli("audit", "--ip", "8.8.8.8")
        self.assertEqual((code, PUBLIC in text, "8.8.8.8" in text), (0, False, True))

    def test_json(self):
        self.run_cli("block", PUBLIC)
        rows = json.loads(self.run_cli("audit", "--json")[1])
        self.assertEqual((rows[0]["actor"], rows[0]["rule"], rows[0]["outcome"]), ("cli:anushka", "manual_block", "applied"))

    def test_an_empty_log(self):
        self.assertIn("no matching decisions", self.run_cli("audit")[1])


class TestSettingsAndMistakes(Case):

    def test_bad_settings_stop_it_with_the_name_of_the_setting(self):
        code, text = self.run_cli("status", env={"MITIGATION_MODE": "enforcing"})
        self.assertEqual(code, 2)
        self.assertIn("MITIGATION_MODE", text)

    def test_bad_commands(self):
        for argv in ([], ["explode"], ["block"], ["audit", "--tail", "x"]):
            with self.subTest(argv=argv), patch("sys.stderr", io.StringIO()):
                self.assertEqual(self.run_cli(*argv)[0], 2)

    def test_help_is_not_an_error(self):
        with patch("sys.stdout", io.StringIO()):
            self.assertEqual(self.run_cli("--help")[0], 0)

    def test_it_never_starts_the_chat_webhook(self):
        before = {t.name for t in threading.enumerate()}
        code, text = self.run_cli("status", env={"MITIGATION_ALERT_WEBHOOK": "https://hooks.example.com/secret-path"})
        self.assertEqual(code, 0)
        self.assertNotIn("secret-path", text)
        self.assertIn("Chat alerts: off", text)                                  # this tool never sends alerts
        self.assertEqual({t.name for t in threading.enumerate()} - before, set())


class TestReplayCommand(Case):

    def write_results(self, rows):
        path = self.dir / "results.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        return str(path)

    def rows(self):
        t0 = dt.datetime(2026, 11, 2, 8, tzinfo=dt.timezone.utc)
        make = lambda i, ip, phase: {"session_id": f"s{i}", "src_ip": ip, "processed_at": (t0 + dt.timedelta(minutes=i)).isoformat(),
                                    "mt3_prediction": {"phase": phase, "phase_name": "P", "micro_state": "X", "confidence": 0.9}}
        return [make(0, PUBLIC, 5), make(1, PUBLIC, 5), make(2, PUBLIC, 5), make(3, "8.8.8.8", 3)]

    def test_a_report_in_words(self):
        code, text = self.run_cli("replay", self.write_results(self.rows()))
        self.assertEqual(code, 0)
        self.assertIn("Replayed 4 sessions from 2 sources", text)
        self.assertIn("blocked at the firewall (1)", text)

    def test_with_labels(self):
        labels = self.dir / "labels.json"
        labels.write_text(json.dumps({PUBLIC: "attack", "8.8.8.8": "benign"}), encoding="utf-8")
        code, text = self.run_cli("replay", self.write_results(self.rows()), "--labels", str(labels))
        self.assertEqual(code, 0)
        self.assertIn("false-positive rate 100.0%", text)                      # the benign 8.8.8.8 was diverted
        self.assertIn("benign sources hit: 8.8.8.8", text)

    def test_json_output_parses(self):
        report = json.loads(self.run_cli("replay", self.write_results(self.rows()), "--json")[1])
        self.assertEqual(report["sessions"], 4)

    def test_the_settings_apply_to_the_replay(self):
        code, text = self.run_cli("replay", self.write_results(self.rows()), "--mode", "enforce", "--firewall",
                                  env={"MITIGATION_DENY_REPEAT_SESSIONS": "5"})
        self.assertNotIn("blocked at the firewall", text)

    def test_input_problems(self):
        self.assertEqual(self.run_cli("replay", str(self.dir / "missing.jsonl"))[0], 2)
        self.assertEqual(self.run_cli("replay", self.write_results([]))[0], 1)
        bad = self.dir / "labels.json"
        bad.write_text('{"1.2.3.4": "maybe"}', encoding="utf-8")
        code, text = self.run_cli("replay", self.write_results(self.rows()), "--labels", str(bad))
        self.assertEqual(code, 2)
        self.assertIn("bad label", text)

    def test_the_replay_does_not_touch_the_real_files(self):
        self.run_cli("replay", self.write_results(self.rows()), "--mode", "enforce", "--firewall")
        self.assertFalse((self.dir / "bl.json").exists())
        self.assertFalse((self.dir / "audit.jsonl").exists())


class TestTheRealCommand(unittest.TestCase):
    """python -m response_mitigation, in its own process, as it will be run on the server."""

    def test_status_and_block_from_a_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, MITIGATION_AUDIT_PATH=f"{tmp}/a.jsonl", MITIGATION_KILL_FILE=f"{tmp}/STOP",
                       MITIGATION_BLOCKLIST_PATH=f"{tmp}/bl.json", PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE="1")

            def run(*args):
                return subprocess.run([sys.executable, "-m", "response_mitigation", *args], cwd=str(REPO), env=env,
                                      capture_output=True, text=True, timeout=60)

            status = run("status")
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertIn("Mode: observe", status.stdout)
            blocked = run("block", PUBLIC, "--hours", "2")
            self.assertEqual(blocked.returncode, 0, blocked.stderr)
            self.assertIn(PUBLIC, run("blocks").stdout)
            refused = run("block", "10.0.0.1")
            self.assertEqual(refused.returncode, 1)
            self.assertEqual(run("explode").returncode, 2)


if __name__ == "__main__":
    unittest.main()
