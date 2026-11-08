"""
deploy/sandbox/tests/test_sandbox_cowrie_ips.py

check_cowrie_ips.py: does Cowrie see attackers' real addresses, or Docker's own?
"""
import importlib.util
import io
import contextlib
import json
import os
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("check_cowrie_ips", HERE.parent / "check_cowrie_ips.py")
cci = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cci)

PUBLIC, PUBLIC_2, PUBLIC_V6 = "45.33.32.156", "172.217.14.206", "2606:4700:4700::1111"


def connect(ip):
    return {"eventid": "cowrie.session.connect", "src_ip": ip, "session": "x", "timestamp": "2026-11-01T00:00:00Z"}


class LogCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def log(self, ips, name="cowrie.json", extra_lines=()):
        path = self.dir / name
        with path.open("w", encoding="utf-8") as fh:
            for ip in ips:
                fh.write(json.dumps(connect(ip)) + "\n")
            for line in extra_lines:
                fh.write(line + "\n")
        return path

    def check(self, **kw):
        return cci.check(self.dir, **kw)


class TestWhatKindOfAddressIsThis(unittest.TestCase):

    def test_kinds(self):
        for text, kind in (("45.33.32.156", "public"), ("172.217.14.206", "public"), ("2606:4700:4700::1111", "public"),
                           ("172.17.0.1", "docker"), ("172.16.0.1", "docker"), ("172.31.255.255", "docker"),
                           ("::ffff:172.17.0.1", "docker"), ("172.15.255.255", "public"), ("172.32.0.1", "public"),   # just outside 172.16/12
                           ("127.0.0.1", "loopback"), ("::1", "loopback"),
                           ("10.0.0.7", "private"), ("192.168.1.5", "private"), ("fe80::1", "private"),
                           ("224.0.0.1", "private"), ("not-an-ip", "invalid"), ("", "invalid"), (None, "invalid")):
            with self.subTest(text=text):
                self.assertEqual(cci.classify(text), kind)


class TestTheVerdict(LogCase):

    def test_real_addresses_pass(self):
        self.log([PUBLIC, PUBLIC_2, PUBLIC_V6])
        code, lines = self.check()
        self.assertEqual(code, 0, lines)
        self.assertIn("3 public", lines[0])

    def test_docker_address_fails_even_among_real_ones(self):
        self.log([PUBLIC, "172.17.0.1", PUBLIC_2])
        code, lines = self.check()
        self.assertEqual(code, 1)
        self.assertTrue(any("172.17.0.1" in l for l in lines))
        self.assertTrue(any("proxy" in l for l in lines))

    def test_docker_address_fails_even_in_lab_mode(self):
        self.log(["172.17.0.1"])
        self.assertEqual(self.check(allow_private=True)[0], 1)

    def test_private_and_loopback_fail_on_the_internet_but_not_in_lab_mode(self):
        for ip in ("10.0.0.7", "192.168.1.5", "127.0.0.1"):
            with self.subTest(ip=ip):
                self.log([ip])
                self.assertEqual(self.check()[0], 1)
                self.assertEqual(self.check(allow_private=True)[0], 0)

    def test_no_connections_yet(self):
        self.assertEqual(self.check()[0], 2)                     # no log files at all
        self.log([], extra_lines=['{"eventid": "cowrie.login.failed"}'])
        self.assertEqual(self.check()[0], 2)                     # a log with no connect events

    def test_junk_lines_are_ignored(self):
        self.log([PUBLIC], extra_lines=["not json", "[]", "", '{"eventid": "cowrie.session.connect"}'])
        self.assertEqual(self.check()[0], 0)

    def test_only_the_last_n_connections_count(self):
        self.log(["172.17.0.1"] * 10 + [PUBLIC] * 5)
        self.assertEqual(self.check(last=5)[0], 0)
        self.assertEqual(self.check(last=15)[0], 1)

    def test_only_the_two_newest_log_files_are_read(self):
        old = self.log(["172.17.0.1"], name="cowrie.json.2026-10-29")
        mid = self.log([PUBLIC], name="cowrie.json.2026-10-31")
        new = self.log([PUBLIC_2], name="cowrie.json")
        for n, path in enumerate((old, mid, new)):
            os.utime(path, (1_000_000 + n, 1_000_000 + n))
        code, lines = self.check()
        self.assertEqual(code, 0, lines)
        self.assertIn("2 public", lines[0])

    def test_a_log_that_cannot_be_read(self):
        (self.dir / "cowrie.json").mkdir()                       # a folder where the log should be
        code, lines = self.check()
        self.assertEqual(code, 4)
        self.assertIn("cannot read", lines[0])


class TestCheckingTheClientYouUsed(LogCase):

    def test_seen(self):
        self.log([PUBLIC, PUBLIC_2])
        code, lines = self.check(client_ip=PUBLIC_2)
        self.assertEqual(code, 0)
        self.assertIn("real address", lines[-1])

    def test_not_seen(self):
        self.log([PUBLIC])
        code, lines = self.check(client_ip=PUBLIC_2)
        self.assertEqual(code, 3)
        self.assertIn("not among them", lines[-1])

    def test_the_two_ways_of_writing_an_ipv4_address_are_the_same(self):
        self.log(["::ffff:45.33.32.156"])
        self.assertEqual(self.check(client_ip="45.33.32.156")[0], 0)
        self.log([PUBLIC])
        self.assertEqual(self.check(client_ip="::ffff:45.33.32.156")[0], 0)

    def test_ipv6_clients(self):
        self.log([PUBLIC_V6])
        self.assertEqual(self.check(client_ip="2606:4700:4700:0:0:0:0:1111")[0], 0)

    def test_a_mistyped_client_is_reported_not_crashed_on(self):
        self.log([PUBLIC])
        code, lines = self.check(client_ip="45.33.32")
        self.assertEqual(code, 4)
        self.assertIn("not an IP address", lines[-1])

    def test_a_docker_address_beats_a_matching_client(self):
        self.log(["172.17.0.1"])
        self.assertEqual(self.check(client_ip="172.17.0.1")[0], 1)


class TestCommandLine(LogCase):

    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cci.main([str(self.dir), *argv])
        return code, out.getvalue()

    def test_prints_and_returns_the_code(self):
        self.log([PUBLIC])
        code, text = self.run_main("--client-ip", PUBLIC)
        self.assertEqual(code, 0)
        self.assertIn("public", text)

    def test_lab_flag(self):
        self.log(["10.0.0.7"])
        self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.run_main("--allow-private")[0], 0)


if __name__ == "__main__":
    unittest.main()
