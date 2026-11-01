"""
response_mitigation/tests/test_host_linux_integration.py

The real thing: the block list writer, then the root-side script, then the Linux
kernel's firewall, with real TCP connections. It skips itself unless it runs on
Linux as root with `nft` and `ip` installed.

How it works. Two throwaway network namespaces are joined by a virtual cable:

    attacker 45.33.32.156 / .157  <--- veth --->  victim 45.33.32.1, listening on :2222

Nothing leaves the machine and the host's own firewall is not touched. The
script runs inside the victim namespace, so its table is the victim's table. The
chain is the same one production uses: `hook prerouting priority raw`.

The addresses are public-looking on purpose: the script refuses to block private
ranges, so a test with 10.x addresses could not prove anything.

Run:  sudo python3 -m unittest response_mitigation.tests.test_host_linux_integration -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from response_mitigation.blocklist import BlocklistFile
from response_mitigation.host import apply_blocklist as hb

ON_LINUX_AS_ROOT = (sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0
                    and shutil.which("nft") and shutil.which("ip"))

VICTIM_NS, ATTACKER_NS = "hgt_victim", "hgt_attacker"
VICTIM, ATTACKER, ATTACKER_2 = "45.33.32.1", "45.33.32.156", "45.33.32.157"
PORT = 2222
SCRIPT = str(Path(hb.__file__).resolve())

LISTENER = f"""
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("{VICTIM}", {PORT})); s.listen(64)
print("ready", flush=True)
while True:
    c, _ = s.accept(); c.close()
"""

KNOCK = f"""
import socket, sys
s = socket.socket(); s.settimeout(1.5); s.bind((sys.argv[1], 0))
try:
    s.connect(("{VICTIM}", {PORT})); print("open")
except socket.timeout:
    print("dropped")
except ConnectionRefusedError:
    print("refused")
"""


def sh(*argv, ns=None, check=True, stdin=None):
    cmd = ["ip", "netns", "exec", ns, *argv] if ns else list(argv)
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, check=check, timeout=60)


@unittest.skipUnless(ON_LINUX_AS_ROOT, "needs Linux, root, nft and ip")
class TestRealFirewall(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp(prefix="hgt-"))
        cls.listener = None
        try:
            for ns in (VICTIM_NS, ATTACKER_NS):
                sh("ip", "netns", "del", ns, check=False)
                sh("ip", "netns", "add", ns)
            sh("ip", "link", "add", "hgtv0", "type", "veth", "peer", "name", "hgta0")
            sh("ip", "link", "set", "hgtv0", "netns", VICTIM_NS)
            sh("ip", "link", "set", "hgta0", "netns", ATTACKER_NS)
            for ns, dev, addrs in ((VICTIM_NS, "hgtv0", [VICTIM]), (ATTACKER_NS, "hgta0", [ATTACKER, ATTACKER_2])):
                for addr in addrs:
                    sh("ip", "addr", "add", f"{addr}/24", "dev", dev, ns=ns)
                sh("ip", "link", "set", dev, "up", ns=ns)
                sh("ip", "link", "set", "lo", "up", ns=ns)
            cls.listener = subprocess.Popen(
                ["ip", "netns", "exec", VICTIM_NS, sys.executable, "-c", LISTENER],
                stdout=subprocess.PIPE, text=True)
            if cls.listener.stdout.readline().strip() != "ready":
                raise RuntimeError("the listener did not start")
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        if cls.listener is not None:
            cls.listener.kill()
            cls.listener.wait()
        for ns in (VICTIM_NS, ATTACKER_NS):
            sh("ip", "netns", "del", ns, check=False)
        shutil.rmtree(cls.dir, ignore_errors=True)

    def setUp(self):
        self.blocklist_path = self.dir / "blocklist.json"
        self.kill = self.dir / "MITIGATION_DISABLED"
        for path in (self.blocklist_path, self.kill):
            path.unlink(missing_ok=True)
        sh("nft", "delete", "table", "inet", "honeypot_guard", ns=VICTIM_NS, check=False)
        self.blocklist = BlocklistFile(self.blocklist_path)

    # -- helpers ------------------------------------------------------------
    def apply(self, *extra):
        done = sh(sys.executable, SCRIPT, "--blocklist", str(self.blocklist_path),
                  "--kill-file", str(self.kill), *extra, ns=VICTIM_NS, check=False)
        self.last = done.stdout + done.stderr
        return done.returncode

    def knock(self, source=ATTACKER):
        return sh(sys.executable, "-c", KNOCK, source, ns=ATTACKER_NS).stdout.strip()

    def block(self, ip=ATTACKER, ttl=300):
        self.blocklist.add(ip, ttl_s=ttl, reason="integration test", rule="test")

    def set_contents(self, name="blocked_v4"):
        return sh("nft", "list", "set", "inet", "honeypot_guard", name, ns=VICTIM_NS).stdout

    # -- the tests ----------------------------------------------------------
    def test_without_a_block_the_connection_works(self):
        """The control. If this failed, 'dropped' below would prove nothing."""
        self.assertEqual(self.knock(ATTACKER), "open")
        self.assertEqual(self.apply(), 0, self.last)                # table made, nothing to block
        self.assertEqual(self.knock(ATTACKER), "open")

    def test_a_blocked_ip_is_dropped_and_other_ips_still_get_through(self):
        self.block(ATTACKER)
        self.assertEqual(self.apply(), 0, self.last)
        self.assertEqual(self.knock(ATTACKER), "dropped")           # silently: not "refused"
        self.assertEqual(self.knock(ATTACKER_2), "open")

    def test_the_block_ends_by_itself_when_it_expires(self):
        self.block(ATTACKER, ttl=3)
        self.assertEqual(self.apply(), 0, self.last)
        self.assertEqual(self.knock(ATTACKER), "dropped")
        time.sleep(3)                                               # no second run of the script
        self.assertEqual(self.knock(ATTACKER), "open")

    def test_taking_the_entry_out_of_the_file_lifts_the_block(self):
        self.block(ATTACKER)
        self.apply()
        self.assertEqual(self.knock(), "dropped")
        self.assertTrue(self.blocklist.remove(ATTACKER))
        self.assertEqual(self.apply(), 0, self.last)
        self.assertEqual(self.knock(), "open")

    def test_the_kill_switch_lifts_every_block_and_stays_in_force_until_removed(self):
        self.block(ATTACKER)
        self.apply()
        self.assertEqual(self.knock(), "dropped")
        self.kill.write_text("")
        self.assertEqual(self.apply(), 0, self.last)
        self.assertIn("kill switch", self.last)
        self.assertEqual(self.knock(), "open")
        self.assertEqual(self.apply(), 0, self.last)                # still off on the next run
        self.assertEqual(self.knock(), "open")
        # Removing the kill file resumes: blocks that have not expired come back.
        self.kill.unlink()
        self.assertEqual(self.apply(), 0, self.last)
        self.assertEqual(self.knock(), "dropped")

    def test_running_twice_changes_nothing(self):
        self.block(ATTACKER)
        self.apply()
        self.assertEqual(self.apply(), 0, self.last)
        self.assertIn("add 0, remove 0, keep 1", self.last)
        self.assertEqual(self.knock(), "dropped")

    def test_dry_run_changes_nothing(self):
        self.block(ATTACKER)
        self.assertEqual(self.apply("--dry-run"), 0, self.last)
        self.assertIn("would run: nft add element", self.last)
        self.assertEqual(self.knock(), "open")
        listed = sh("nft", "list", "table", "inet", "honeypot_guard", ns=VICTIM_NS, check=False)
        self.assertNotEqual(listed.returncode, 0)                   # not even the table was created

    def test_unsafe_entries_in_the_file_never_reach_the_firewall(self):
        now = int(time.time())
        entries = [{"ip": ip, "added_at": now, "expires_at": now + 600, "reason": "x", "rule": "x", "session_id": "x"}
                   for ip in ("10.0.0.5", "127.0.0.1", "172.17.0.1", "224.0.0.1",
                              "8.8.8.8; flush ruleset", "1.2.3.4 }\nflush ruleset", ATTACKER)]
        self.blocklist_path.write_text(json.dumps({"version": 1, "entries": entries}))
        self.assertEqual(self.apply(), 0, self.last)
        listing = self.set_contents()
        self.assertIn(ATTACKER, listing)
        for bad in ("10.0.0.5", "127.0.0.1", "172.17.0.1", "224.0.0.1", "flush"):
            self.assertNotIn(bad, listing)
        self.assertIn("ip saddr @blocked_v4 drop", sh("nft", "list", "ruleset", ns=VICTIM_NS).stdout)
        self.assertEqual(self.knock(), "dropped")

    def test_the_never_block_option_wins_over_the_file(self):
        self.block(ATTACKER)
        self.assertEqual(self.apply("--never-block", "45.33.32.0/24"), 0, self.last)
        self.assertIn("on the never-block list", self.last)
        self.assertEqual(self.knock(), "open")

    def test_ipv6_blocks_are_accepted_by_the_kernel(self):
        self.blocklist.add("2606:4700:4700::1111", ttl_s=600, reason="v6", rule="test")
        self.assertEqual(self.apply(), 0, self.last)
        self.assertIn("2606:4700:4700::1111", self.set_contents("blocked_v6"))

    def test_a_broken_block_list_leaves_existing_blocks_in_force(self):
        self.block(ATTACKER)
        self.apply()
        self.blocklist_path.write_bytes(b"{nope")
        self.assertEqual(self.apply(), 2, self.last)
        self.assertEqual(self.knock(), "dropped")

    def test_a_table_that_was_wiped_is_rebuilt_and_blocks_again(self):
        """e.g. nftables.service reloading /etc/nftables.conf with `flush ruleset`."""
        self.block(ATTACKER)
        self.apply()
        sh("nft", "flush", "ruleset", ns=VICTIM_NS)
        self.assertEqual(self.knock(), "open")
        self.assertEqual(self.apply(), 0, self.last)
        self.assertEqual(self.knock(), "dropped")

    def test_a_table_whose_drop_rules_vanished_is_repaired(self):
        self.block(ATTACKER)
        self.apply()
        sh("nft", "flush", "chain", "inet", "honeypot_guard", "pre", ns=VICTIM_NS)
        self.assertEqual(self.knock(), "open")                      # the set still holds the IP, the rule is gone
        self.assertEqual(self.apply(), 0, self.last)
        self.assertIn("drifted", self.last)
        self.assertEqual(self.knock(), "dropped")

    def test_the_real_nft_output_matches_what_the_parsers_expect(self):
        self.block(ATTACKER)
        self.apply()
        table = sh("nft", "-j", "list", "table", "inet", "honeypot_guard", ns=VICTIM_NS).stdout
        self.assertTrue(hb.table_is_healthy(table))
        listing = sh("nft", "-j", "list", "set", "inet", "honeypot_guard", "blocked_v4", ns=VICTIM_NS).stdout
        found = hb.parse_set_listing(listing)
        self.assertEqual(list(found), [ATTACKER])
        self.assertTrue(0 < found[ATTACKER] <= 300)


if __name__ == "__main__":
    unittest.main()
