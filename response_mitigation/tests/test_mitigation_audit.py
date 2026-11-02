"""
response_mitigation/tests/test_mitigation_audit.py

The decision log: one valid JSON line per decision, appended, LF line endings.
Every test writes into a temp folder.
"""
import json
import math
import tempfile
import threading
import unittest
from pathlib import Path

from response_mitigation.audit import AuditLog
from response_mitigation.models import (Action, Decision, Mode, Outcome,
                                        PlannedAction, Verdict)


def decision(ip="45.33.32.156", conf=0.91, action=Action.DENY, outcome=Outcome.APPLIED,
             detail="") -> Decision:
    v = Verdict(ip=ip, phase=5, phase_name="Persistence", micro_state="PERSIST_X",
                confidence=conf, session_id="abc", sessions_seen=4)
    p = PlannedAction(action, "repeat_offender", "because", ttl_s=86400)
    return Decision(v, p, Mode.ENFORCE, outcome, detail)


class TestDecisionRecord(unittest.TestCase):

    def test_record_has_every_field_with_plain_values(self):
        rec = decision(detail="added to blocklist").to_record()
        self.assertEqual(set(rec), {
            "decision_id", "ts", "mode", "ip", "session_id", "action", "rule",
            "reason", "ttl_s", "outcome", "detail", "phase", "phase_name",
            "micro_state", "confidence", "sessions_seen", "actor"})
        self.assertEqual(rec["mode"], "enforce")
        self.assertEqual(rec["action"], "deny")
        self.assertEqual(rec["outcome"], "applied")
        self.assertEqual(rec["ip"], "45.33.32.156")
        self.assertEqual(rec["confidence"], 0.91)
        self.assertEqual(rec["sessions_seen"], 4)
        self.assertEqual(rec["actor"], "policy")        # automatic decisions say so; a person is named instead
        json.dumps(rec, allow_nan=False)   # must be fully JSON-safe

    def test_each_decision_gets_its_own_id(self):
        self.assertNotEqual(decision().decision_id, decision().decision_id)

    def test_nan_and_infinity_become_null(self):
        for bad in (math.nan, math.inf, -math.inf):
            with self.subTest(conf=bad):
                self.assertIsNone(decision(conf=bad).to_record()["confidence"])


class TestReadingTheTail(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "audit.jsonl"
        self.log = AuditLog(self.path)

    def write(self, n, ip_of=lambda i: "45.33.32.156"):
        for i in range(n):
            self.log.write(decision(ip=ip_of(i), detail=f"number {i}"))

    def test_newest_first(self):
        self.write(10)
        self.assertEqual([r["detail"] for r in self.log.tail(3)], ["number 9", "number 8", "number 7"])

    def test_asking_for_more_than_there_is(self):
        self.write(4)
        self.assertEqual([r["detail"] for r in self.log.tail(50)], [f"number {i}" for i in (3, 2, 1, 0)])

    def test_nothing_to_read(self):
        self.assertEqual(self.log.tail(5), [])                       # no file yet
        self.write(3)
        self.assertEqual(self.log.tail(0), [])

    def test_only_one_address(self):
        self.write(12, ip_of=lambda i: "8.8.8.8" if i % 3 == 0 else "1.1.1.1")
        got = self.log.tail(10, ip="8.8.8.8")
        self.assertEqual([r["detail"] for r in got], ["number 9", "number 6", "number 3", "number 0"])

    def test_a_log_bigger_than_one_read_block_comes_back_whole_and_in_order(self):
        self.write(1500)                                              # a few hundred KB: several 64 KB blocks
        self.assertGreater(self.path.stat().st_size, 3 * 65536)
        got = self.log.tail(1200)
        self.assertEqual([r["detail"] for r in got], [f"number {i}" for i in range(1499, 299, -1)])

    def test_every_line_survives_a_block_boundary(self):
        self.write(1500)
        got = self.log.tail(1500)
        self.assertEqual(len(got), 1500)
        self.assertEqual(got[-1]["detail"], "number 0")

    def test_damaged_lines_are_skipped(self):
        self.write(2)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write('not json\n\n{"truncated": \n')
        self.write(1)
        self.assertEqual([r["detail"] for r in self.log.tail(10)], ["number 0", "number 1", "number 0"])

    def test_a_last_line_without_a_newline_is_still_read(self):
        self.write(1)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ip": "1.2.3.4", "detail": "no newline"}))
        self.assertEqual(self.log.tail(1)[0]["detail"], "no newline")


class TestAuditLog(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "deeper" / "audit.jsonl"
        self.log = AuditLog(self.path)

    def lines(self):
        return self.path.read_text(encoding="utf-8").splitlines()

    def test_creates_the_folder_and_writes_one_json_line(self):
        d = decision()
        self.log.write(d)
        lines = self.lines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0]), d.to_record())

    def test_appends_and_never_rewrites(self):
        self.log.write(decision(ip="8.8.8.8"))
        self.log.write(decision(ip="8.8.4.4", outcome=Outcome.SKIPPED, detail="whitelisted"))
        AuditLog(self.path).write(decision(ip="1.1.1.1"))   # a second writer, same file
        recs = [json.loads(line) for line in self.lines()]
        self.assertEqual([r["ip"] for r in recs], ["8.8.8.8", "8.8.4.4", "1.1.1.1"])
        self.assertEqual(recs[1]["outcome"], "skipped")
        self.assertEqual(recs[1]["detail"], "whitelisted")

    def test_lines_end_in_lf_only(self):
        self.log.write(decision())
        self.assertNotIn(b"\r", self.path.read_bytes())

    def test_text_with_odd_characters_stays_on_one_line(self):
        self.log.write(decision(detail='quote " backslash \\ newline \n tab \t unicode é'))
        lines = self.lines()
        self.assertEqual(len(lines), 1)
        self.assertIn("unicode", json.loads(lines[0])["detail"])

    def test_nan_confidence_still_gives_valid_json(self):
        self.log.write(decision(conf=math.nan))
        self.assertIsNone(json.loads(self.lines()[0])["confidence"])

    def test_many_threads_never_mix_lines(self):
        def work(n):
            for i in range(25):
                self.log.write(decision(ip=f"45.33.{n}.{i}"))

        threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        recs = [json.loads(line) for line in self.lines()]   # any torn line would raise
        self.assertEqual(len(recs), 200)
        self.assertEqual(len({r["ip"] for r in recs}), 200)

    def test_an_unwritable_path_raises_so_the_caller_can_refuse_to_act(self):
        blocker = self.path.parent.parent / "afile"
        blocker.write_text("not a folder")
        with self.assertRaises(OSError):
            AuditLog(blocker / "audit.jsonl").write(decision())


if __name__ == "__main__":
    unittest.main()
