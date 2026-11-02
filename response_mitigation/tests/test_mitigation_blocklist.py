"""
response_mitigation/tests/test_mitigation_blocklist.py

The block list file the pipeline writes (blocklist.py), and the check that the
root-side script (host/apply_blocklist.py) reads back exactly what was written.
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from response_mitigation.blocklist import BlockEntry, BlocklistBusy, BlocklistCorrupt, BlocklistFile, _ProcessLock
from response_mitigation.host import apply_blocklist as hb

PUBLIC = "45.33.32.156"


class Clock:
    def __init__(self, now=1_800_000_000):
        self.now = now

    def __call__(self):
        return self.now


class BlocklistCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.path = self.dir / "sub" / "blocklist.json"
        self.clock = Clock()
        self.file = BlocklistFile(self.path, clock=self.clock)

    def block(self, ip=PUBLIC, ttl=3600, **kw):
        kw.setdefault("reason", "why")
        kw.setdefault("rule", "repeat_offender")
        kw.setdefault("session_id", "s1")
        return self.file.add(ip, ttl_s=ttl, **kw)


class TestWriting(BlocklistCase):

    def test_first_block_creates_the_file_and_its_folder(self):
        entry = self.block(ttl=86400)
        self.assertEqual(entry.expires_at, self.clock.now + 86400)
        doc = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(doc["version"], 1)
        self.assertEqual(doc["updated_at"], self.clock.now)
        self.assertEqual(doc["entries"], [{
            "ip": PUBLIC, "added_at": self.clock.now, "expires_at": self.clock.now + 86400,
            "reason": "why", "rule": "repeat_offender", "session_id": "s1"}])

    def test_blocking_an_ip_that_is_already_blocked_keeps_the_first_entry(self):
        first = self.block(ttl=100, reason="first")
        self.clock.now += 50
        again = self.block(ttl=9999, reason="second")
        self.assertEqual(again, first)
        self.assertEqual(self.file.entries(), [first])

    def test_expired_entries_are_dropped_from_the_file_on_the_next_write(self):
        self.block("8.8.8.8", ttl=10)
        self.clock.now += 11
        self.block("1.1.1.1", ttl=10)
        self.assertEqual([e["ip"] for e in json.loads(self.path.read_text())["entries"]], ["1.1.1.1"])

    def test_an_expired_block_can_be_made_again(self):
        self.block(ttl=10)
        self.clock.now += 10
        self.assertIsNone(self.file.get(PUBLIC))
        again = self.block(ttl=10)
        self.assertEqual(again.added_at, self.clock.now)

    def test_entries_come_back_oldest_first_and_get_finds_one(self):
        self.block("8.8.8.8")
        self.clock.now += 5
        self.block("1.1.1.1")
        self.assertEqual([e.ip for e in self.file.entries()], ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(self.file.get("1.1.1.1").added_at, self.clock.now)
        self.assertIsNone(self.file.get("9.9.9.9"))

    def test_remove_lifts_a_block(self):
        self.block("8.8.8.8")
        self.block("1.1.1.1")
        self.assertTrue(self.file.remove("8.8.8.8"))
        self.assertFalse(self.file.remove("8.8.8.8"))
        self.assertEqual([e.ip for e in self.file.entries()], ["1.1.1.1"])

    def test_nothing_is_written_when_there_is_nothing_to_remove(self):
        self.assertFalse(self.file.remove(PUBLIC))
        self.assertFalse(self.path.exists())

    def test_a_missing_file_reads_as_empty(self):
        self.assertEqual(self.file.entries(), [])

    def test_ttl_must_be_a_whole_number_of_seconds(self):
        for bad in (0, -1, 1.5, "60", None, True):
            with self.subTest(ttl=bad), self.assertRaises(ValueError):
                self.block(ttl=bad)
        self.assertFalse(self.path.exists())

    def test_the_reason_is_one_short_line(self):
        entry = self.block(reason="line one\nline two\t\ttabbed " + "x" * 500)
        self.assertNotIn("\n", entry.reason)
        self.assertLessEqual(len(entry.reason), 200)
        self.assertTrue(entry.reason.startswith("line one line two tabbed"))

    @unittest.skipIf(os.name == "nt", "file modes are a POSIX idea")
    def test_the_file_is_readable_by_the_root_script_whoever_owns_it(self):
        self.block()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)


class TestNeverLeavesAHalfWrittenFile(BlocklistCase):

    def test_a_failed_save_keeps_the_old_file_and_removes_the_temp_file(self):
        self.block("8.8.8.8")
        before = self.path.read_bytes()
        with patch("response_mitigation.blocklist.os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.block("1.1.1.1")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.path.parent.iterdir()), ["blocklist.json", "blocklist.json.lock"])

    def test_no_temp_files_are_left_after_a_normal_save(self):
        self.block()
        self.block("8.8.8.8")
        self.assertEqual(sorted(p.name for p in self.path.parent.iterdir()), ["blocklist.json", "blocklist.json.lock"])

    def test_many_threads_adding_at_once_lose_nothing(self):
        ips = [f"45.33.{i // 200}.{i % 200 + 1}" for i in range(40)]
        threads = [threading.Thread(target=self.block, args=(ip,)) for ip in ips]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(e.ip for e in self.file.entries()), sorted(ips))


REPO = Path(__file__).resolve().parents[2]

_WRITER = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from response_mitigation.blocklist import BlocklistFile
f = BlocklistFile(Path(sys.argv[2]))
for i in range(int(sys.argv[4])):
    f.add("45.33.%s.%d" % (sys.argv[3], i + 1), ttl_s=3600, reason="p", rule="t")
"""


class TestSeveralProcessesAtOnce(BlocklistCase):
    """The pipeline, the command line and the dashboard can all write this file."""

    def test_no_update_is_lost_when_four_processes_write_together(self):
        procs = [subprocess.Popen([sys.executable, "-c", _WRITER, str(REPO), str(self.path), str(k), "15"])
                 for k in range(4)]
        for proc in procs:
            self.assertEqual(proc.wait(timeout=180), 0)
        # The children use the real clock, this test's clock is fixed in 2027, so count the raw file.
        doc = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(sorted(e["ip"] for e in doc["entries"]),
                         sorted(f"45.33.{k}.{i}" for k in range(4) for i in range(1, 16)))

    def test_a_process_that_cannot_get_the_lock_gives_up_and_changes_nothing(self):
        self.block("8.8.8.8")
        before = self.path.read_bytes()
        impatient = BlocklistFile(self.path, clock=self.clock, lock_timeout_s=0.2)
        with _ProcessLock(self.dir / "sub" / "blocklist.json.lock"):
            with self.assertRaises(BlocklistBusy):
                impatient.add(PUBLIC, ttl_s=60, reason="r", rule="r")
            with self.assertRaises(BlocklistBusy):
                impatient.remove("8.8.8.8")
        self.assertEqual(self.path.read_bytes(), before)

    def test_reading_never_needs_the_lock(self):
        self.block("8.8.8.8")
        with _ProcessLock(self.dir / "sub" / "blocklist.json.lock"):
            self.assertEqual([e.ip for e in self.file.entries()], ["8.8.8.8"])

    def test_the_lock_is_released_after_each_change(self):
        self.block("8.8.8.8")
        self.block("1.1.1.1")                                          # would hang if the first kept the lock
        self.assertTrue(self.file.remove("8.8.8.8"))
        self.assertEqual(len(self.file.entries()), 1)


class TestAFileThatCannotBeReadIsNeverReplaced(BlocklistCase):

    def setUp(self):
        super().setUp()
        self.path.parent.mkdir(parents=True)

    def assert_left_alone(self, content: bytes):
        self.path.write_bytes(content)
        for call in (self.file.entries, lambda: self.block("8.8.8.8"), lambda: self.file.remove("8.8.8.8")):
            with self.assertRaises(BlocklistCorrupt):
                call()
        self.assertEqual(self.path.read_bytes(), content)

    def test_not_json(self):
        self.assert_left_alone(b"{nope")

    def test_empty(self):
        self.assert_left_alone(b"")

    def test_other_layout_version(self):
        self.assert_left_alone(b'{"version": 2, "entries": []}')

    def test_an_entry_with_a_missing_or_extra_field(self):
        self.assert_left_alone(b'{"version": 1, "entries": [{"ip": "8.8.8.8"}]}')
        self.assert_left_alone(json.dumps({"version": 1, "entries": [
            {**BlockEntry(PUBLIC, 1, 2, "r", "r", "s").__dict__, "extra": 1}]}).encode())

    def test_entries_that_are_not_objects(self):
        self.assert_left_alone(b'{"version": 1, "entries": ["8.8.8.8"]}')

    def test_the_message_does_not_repeat_the_file_content(self):
        self.path.write_bytes(b"SECRET-TOKEN-123 {")
        with self.assertRaises(BlocklistCorrupt) as ctx:
            self.file.entries()
        self.assertNotIn("SECRET", str(ctx.exception))


class TestTheRootScriptReadsWhatWeWrite(BlocklistCase):
    """The two halves are written separately, so prove they fit together."""

    def test_round_trip(self):
        self.block(PUBLIC, ttl=600)
        self.block("2606:4700:4700::1111", ttl=60)
        parsed = hb.parse_entries(self.path.read_bytes(), now=self.clock.now)
        self.assertEqual(parsed.desired, {PUBLIC: self.clock.now + 600,
                                          "2606:4700:4700::1111": self.clock.now + 60})
        self.assertEqual(parsed.rejected, [])

    def test_the_script_would_run_the_command_the_executor_reported(self):
        self.block(PUBLIC, ttl=600)
        parsed = hb.parse_entries(self.path.read_bytes(), now=self.clock.now)
        add, _ = hb.plan_changes(parsed.desired, {}, self.clock.now)
        self.assertEqual([hb.add_element_command(ip, secs) for ip, secs in add],
                         ["add element inet honeypot_guard blocked_v4 { 45.33.32.156 timeout 600s }"])

    def test_the_longest_block_we_can_write_is_one_the_script_accepts(self):
        self.block(PUBLIC, ttl=hb.MAX_TTL_S)
        parsed = hb.parse_entries(self.path.read_bytes(), now=self.clock.now)
        self.assertIn(PUBLIC, parsed.desired)


if __name__ == "__main__":
    unittest.main()
