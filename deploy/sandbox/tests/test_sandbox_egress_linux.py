"""
deploy/sandbox/tests/test_sandbox_egress_linux.py

The REAL outbound block (deploy/sandbox/egress.nft), loaded into a real Linux kernel, with
real TCP connections. Skips itself unless run on Linux as root with `nft` and `ip`.

Three throwaway network namespaces stand in for the server's world:

    inside  172.28.0.2  --[ br-honeypot ]--  router  --[ wan ]--  world 198.51.100.2
    (the honeypot net)                      172.28.0.1
                                            198.51.100.1

`router` is the Docker host. Its interface to `inside` is named br-honeypot, exactly as in
docker-compose.yml, because the rule matches on that name. Forwarding is on and there is no
NAT, so this checks the rule itself, not Docker. (Docker's own port forwarding is checked on
the real server: README parts A10 and A11.)

What must hold:
  * with the rule loaded, the honeypot cannot start a connection to the world
  * ... nor to a service on the host itself
  * attackers can still connect IN to the honeypot and get answers back
  * loading the rule twice does not duplicate it, and removing it restores everything

Run:  sudo python3 -m unittest deploy.sandbox.tests.test_sandbox_egress_linux -v
      (or: sudo python3 deploy/sandbox/tests/test_sandbox_egress_linux.py)
"""
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

EGRESS = Path(__file__).resolve().parent.parent / "egress.nft"

ON_LINUX_AS_ROOT = (sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0
                    and shutil.which("nft") and shutil.which("ip"))

ROUTER, INSIDE, WORLD = "hge_router", "hge_inside", "hge_world"
INSIDE_IP, GATEWAY_IP, WAN_IP, WORLD_IP = "172.28.0.2", "172.28.0.1", "198.51.100.1", "198.51.100.2"

SERVER = """
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(16)
print("ready", flush=True)
while True:
    c, _ = s.accept(); c.sendall(b"hello"); c.close()
"""

CLIENT = """
import socket, sys
s = socket.socket(); s.settimeout(1.5)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    print(s.recv(16).decode() or "open")
except socket.timeout:
    print("timeout")
except ConnectionRefusedError:
    print("refused")
"""


def ip(*argv, ns=None, check=True):
    cmd = (["ip", "netns", "exec", ns] if ns else []) + list(argv)
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=60)


@unittest.skipUnless(ON_LINUX_AS_ROOT, "needs Linux, root, nft and ip")
class TestEgressRule(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.servers = []
        try:
            for ns in (ROUTER, INSIDE, WORLD):
                ip("ip", "netns", "del", ns, check=False)
                ip("ip", "netns", "add", ns)
            # Created inside the router so the name br-honeypot cannot clash with anything on the real host.
            ip("ip", "link", "add", "br-honeypot", "type", "veth", "peer", "name", "hgei0", "netns", INSIDE, ns=ROUTER)
            ip("ip", "link", "add", "hgew0", "type", "veth", "peer", "name", "hgew1", "netns", WORLD, ns=ROUTER)
            for ns, dev, addr in ((ROUTER, "br-honeypot", f"{GATEWAY_IP}/24"), (ROUTER, "hgew0", f"{WAN_IP}/24"),
                                  (INSIDE, "hgei0", f"{INSIDE_IP}/24"), (WORLD, "hgew1", f"{WORLD_IP}/24")):
                ip("ip", "addr", "add", addr, "dev", dev, ns=ns)
                ip("ip", "link", "set", dev, "up", ns=ns)
            for ns in (ROUTER, INSIDE, WORLD):
                ip("ip", "link", "set", "lo", "up", ns=ns)
            ip("sysctl", "-qw", "net.ipv4.ip_forward=1", ns=ROUTER)
            ip("ip", "route", "add", "default", "via", GATEWAY_IP, ns=INSIDE)
            ip("ip", "route", "add", "172.28.0.0/24", "via", WAN_IP, ns=WORLD)
            for ns, addr, port in ((WORLD, WORLD_IP, 9000), (ROUTER, GATEWAY_IP, 7777), (INSIDE, INSIDE_IP, 2222)):
                proc = subprocess.Popen(["ip", "netns", "exec", ns, sys.executable, "-c", SERVER, addr, str(port)],
                                        stdout=subprocess.PIPE, text=True)
                cls.servers.append(proc)
                if proc.stdout.readline().strip() != "ready":
                    raise RuntimeError(f"server in {ns} did not start")
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for proc in cls.servers:
            proc.kill()
            proc.wait()
        for ns in (ROUTER, INSIDE, WORLD):
            ip("ip", "netns", "del", ns, check=False)

    def setUp(self):
        ip("nft", "delete", "table", "inet", "honeypot_egress", ns=ROUTER, check=False)

    # -- helpers ------------------------------------------------------------
    def load(self):
        return ip("nft", "-f", str(EGRESS), ns=ROUTER)

    def connect(self, client_ns, host, port):
        return ip(sys.executable, "-c", CLIENT, host, str(port), ns=client_ns).stdout.strip()

    def honeypot_to_world(self):
        return self.connect(INSIDE, WORLD_IP, 9000)

    def honeypot_to_host(self):
        return self.connect(INSIDE, GATEWAY_IP, 7777)

    def world_to_honeypot(self):
        return self.connect(WORLD, INSIDE_IP, 2222)

    def counter(self, chain):
        out = ip("nft", "list", "chain", "inet", "honeypot_egress", chain, ns=ROUTER).stdout
        return int(out.split("counter packets ")[1].split()[0])

    # -- tests --------------------------------------------------------------
    def test_without_the_rule_everything_works(self):
        """The control. If this failed, 'timeout' below would prove nothing."""
        self.assertEqual(self.honeypot_to_world(), "hello")
        self.assertEqual(self.honeypot_to_host(), "hello")
        self.assertEqual(self.world_to_honeypot(), "hello")

    def test_the_honeypot_cannot_start_a_connection_to_the_world(self):
        self.load()
        self.assertEqual(self.honeypot_to_world(), "timeout")        # dropped silently, not refused

    def test_the_honeypot_cannot_reach_services_on_the_host(self):
        self.load()
        self.assertEqual(self.honeypot_to_host(), "timeout")

    def test_attackers_can_still_connect_in_and_get_answers(self):
        self.load()
        self.assertEqual(self.world_to_honeypot(), "hello")          # the reply is "established", not "new"
        self.assertEqual(self.world_to_honeypot(), "hello")

    def test_the_counters_show_what_was_dropped(self):
        self.load()
        before = (self.counter("forward_guard"), self.counter("input_guard"))
        self.honeypot_to_world()
        self.honeypot_to_host()
        after = (self.counter("forward_guard"), self.counter("input_guard"))
        self.assertGreater(after[0], before[0])
        self.assertGreater(after[1], before[1])

    def test_inbound_traffic_does_not_move_the_counters(self):
        self.load()
        before = (self.counter("forward_guard"), self.counter("input_guard"))
        self.world_to_honeypot()
        self.assertEqual((self.counter("forward_guard"), self.counter("input_guard")), before)

    def test_loading_twice_does_not_duplicate_the_rules(self):
        self.load()
        self.load()
        listing = ip("nft", "list", "table", "inet", "honeypot_egress", ns=ROUTER).stdout
        self.assertEqual(listing.count('iifname "br-honeypot"'), 2)
        self.assertEqual(self.honeypot_to_world(), "timeout")

    def test_removing_the_table_restores_outbound(self):
        self.load()
        self.assertEqual(self.honeypot_to_world(), "timeout")
        ip("nft", "delete", "table", "inet", "honeypot_egress", ns=ROUTER)
        self.assertEqual(self.honeypot_to_world(), "hello")

    def test_the_host_itself_can_still_reach_the_world(self):
        """The rule is about the honeypot's network only: the server keeps its own outbound traffic
        (updates, threat-intel look-ups, the model download)."""
        self.load()
        self.assertEqual(self.connect(ROUTER, WORLD_IP, 9000), "hello")


if __name__ == "__main__":
    unittest.main()
