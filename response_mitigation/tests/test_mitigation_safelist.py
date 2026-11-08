"""
response_mitigation/tests/test_mitigation_safelist.py

The never-block list. The 172.x cases are the regression for the text-prefix
bug fixed in traffic_gateway/peer_attribution.py: public 172.x addresses must
stay blockable, and every address inside 172.16.0.0/12 must stay protected.
"""
import ipaddress
import unittest

from response_mitigation.models import Action
from response_mitigation.safelist import Safelist, canonical, parse_ip

PUBLIC = ["45.33.32.156", "8.8.8.8", "185.220.101.5", "2001:4860:4860::8888"]

# Public space that the old "172.1" / "172.2" text check wrongly treated as Docker.
PUBLIC_172 = ["172.1.2.3", "172.10.0.1", "172.15.255.255", "172.32.0.1",
              "172.100.1.1", "172.200.1.1", "172.217.14.206"]

# Inside 172.16.0.0/12: private, and where Docker's bridges live.
BRIDGE_172 = ["172.16.0.1", "172.17.0.1", "172.20.1.1", "172.31.255.255"]

NOT_PUBLIC = ["127.0.0.1", "::1", "10.1.2.3", "192.168.1.5", "169.254.1.1",
              "100.64.0.1", "0.0.0.0", "255.255.255.255", "240.0.0.1",
              "224.0.0.1", "239.255.255.250", "ff02::1",   # multicast
              "203.0.113.5",     # documentation range: never a real attacker
              "fe80::1", "fc00::1", "::ffff:10.0.0.1"] + BRIDGE_172

NOT_AN_IP = ["", "   ", "abc", "8.8.8.8; rm -rf /", "8.8.8.8\nnft flush ruleset",
             "1.2.3.4/32", "1.2.3", "999.1.1.1", "fe80::1%eth0", None, 12345]


class TestParse(unittest.TestCase):

    def test_canonical_form(self):
        self.assertEqual(canonical(" 8.8.8.8 "), "8.8.8.8")
        self.assertEqual(canonical("2001:4860:4860:0:0:0:0:8888"), "2001:4860:4860::8888")

    def test_ipv4_mapped_ipv6_is_unwrapped(self):
        self.assertEqual(canonical("::ffff:172.17.0.1"), "172.17.0.1")

    def test_anything_else_is_rejected(self):
        for value in NOT_AN_IP:
            with self.subTest(value=value):
                self.assertIsNone(parse_ip(value))
                self.assertIsNone(canonical(value))


class TestDeny(unittest.TestCase):

    def setUp(self):
        self.safe = Safelist()

    def test_public_addresses_may_be_denied(self):
        for ip in PUBLIC + PUBLIC_172:
            with self.subTest(ip=ip):
                self.assertIsNone(self.safe.skip_reason(ip, Action.DENY))

    def test_non_public_addresses_are_protected(self):
        for ip in NOT_PUBLIC:
            with self.subTest(ip=ip):
                self.assertIsNotNone(self.safe.skip_reason(ip, Action.DENY))

    def test_docker_bridge_gets_its_own_reason(self):
        for ip in BRIDGE_172 + ["::ffff:172.17.0.1"]:
            with self.subTest(ip=ip):
                self.assertIn("Docker bridge", self.safe.skip_reason(ip, Action.DENY))

    def test_the_whole_172_16_12_range_is_covered(self):
        net = ipaddress.ip_network("172.16.0.0/12")
        for ip in (net[0], net[1], net[-2], net[-1]):
            with self.subTest(ip=str(ip)):
                self.assertIsNotNone(self.safe.skip_reason(str(ip), Action.DENY))

    def test_bad_input_is_never_denied(self):
        for value in NOT_AN_IP:
            with self.subTest(value=value):
                self.assertEqual(self.safe.skip_reason(value, Action.DENY),
                                 "not a valid IP address")

    def test_admin_network_and_single_address_are_protected(self):
        safe = Safelist(never_block=[ipaddress.ip_network("45.33.32.0/24"),
                                     ipaddress.ip_network("8.8.8.8")])
        self.assertIn("never-block", safe.skip_reason("45.33.32.156", Action.DENY))
        self.assertIn("never-block", safe.skip_reason("8.8.8.8", Action.DENY))
        self.assertIsNone(safe.skip_reason("45.33.33.1", Action.DENY))
        self.assertIsNone(safe.skip_reason("8.8.4.4", Action.DENY))

    def test_own_address_is_protected_in_either_notation(self):
        safe = Safelist(own_addresses=["34.1.2.3"])
        self.assertIn("own address", safe.skip_reason("34.1.2.3", Action.DENY))
        self.assertIn("own address", safe.skip_reason("::ffff:34.1.2.3", Action.DENY))
        self.assertIsNone(safe.skip_reason("34.1.2.4", Action.DENY))

    def test_a_bad_own_address_stops_start_up(self):
        with self.assertRaises(ValueError):
            Safelist(own_addresses=["not-an-ip"])


class TestDivert(unittest.TestCase):

    def test_demo_addresses_may_be_diverted(self):
        # The two-laptop demo diverts loopback and LAN peers. Keep it working.
        safe = Safelist()
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.1.5"] + PUBLIC + PUBLIC_172:
            with self.subTest(ip=ip):
                self.assertIsNone(safe.skip_reason(ip, Action.DIVERT))

    def test_docker_bridge_is_not_diverted(self):
        safe = Safelist()
        for ip in BRIDGE_172 + ["::ffff:172.17.0.1"]:
            with self.subTest(ip=ip):
                self.assertIn("Docker bridge", safe.skip_reason(ip, Action.DIVERT))

    def test_bad_input_is_not_diverted(self):
        safe = Safelist()
        for value in NOT_AN_IP:
            with self.subTest(value=value):
                self.assertEqual(safe.skip_reason(value, Action.DIVERT),
                                 "not a valid IP address")

    def test_never_block_list_does_not_stop_a_divert(self):
        safe = Safelist(never_block=[ipaddress.ip_network("45.33.32.0/24")])
        self.assertIsNone(safe.skip_reason("45.33.32.156", Action.DIVERT))


class TestWhitelist(unittest.TestCase):

    def test_whitelisted_is_protected_from_divert_and_deny(self):
        seen = []

        def whitelisted(ip):
            seen.append(ip)
            return ip == "45.33.32.156"

        safe = Safelist(is_whitelisted=whitelisted)
        for action in (Action.DIVERT, Action.DENY):
            with self.subTest(action=action):
                self.assertEqual(safe.skip_reason(" 45.33.32.156 ", action), "whitelisted")
                self.assertIsNone(safe.skip_reason("8.8.8.8", action))
        # It is always asked with the clean text form, never the raw input.
        self.assertEqual(set(seen), {"45.33.32.156", "8.8.8.8"})


class TestInformationalActions(unittest.TestCase):

    def test_observe_and_alert_are_never_skipped(self):
        safe = Safelist(is_whitelisted=lambda _ip: True)
        for action in (Action.OBSERVE, Action.ALERT):
            for ip in ["127.0.0.1", "172.17.0.1", "45.33.32.156", "garbage", None]:
                with self.subTest(action=action, ip=ip):
                    self.assertIsNone(safe.skip_reason(ip, action))


if __name__ == "__main__":
    unittest.main()
