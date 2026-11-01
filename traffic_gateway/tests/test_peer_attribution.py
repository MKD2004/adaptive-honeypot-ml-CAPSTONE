"""
traffic_gateway/tests/test_peer_attribution.py

Unit tests for peer_attribution: which addresses count as "the proxy itself",
and how a honeypot session is matched back to the peer the gateway proxied.
No network I/O; the gateway event log is a temp file passed in explicitly, so
nothing under traffic_gateway/data is read or written.
"""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from traffic_gateway.peer_attribution import (
    PeerAttributor,
    is_docker_bridge_addr,
    looks_like_proxy,
)


class TestLooksLikeProxy(unittest.TestCase):

    def test_loopback_is_proxy(self):
        for ip in ("127.0.0.1", "127.0.0.2", "::1", "localhost"):
            with self.subTest(ip=ip):
                self.assertTrue(looks_like_proxy(ip))

    def test_docker_bridge_range_is_proxy(self):
        # 172.16.0.0/12 -> 172.16.0.0 .. 172.31.255.255; 172.17.0.1 is the
        # default bridge gateway a published container port is NATed from.
        for ip in ("172.16.0.1", "172.17.0.1", "172.18.0.2", "172.31.255.254"):
            with self.subTest(ip=ip):
                self.assertTrue(looks_like_proxy(ip))

    def test_public_172_space_is_not_proxy(self):
        # The old check was ip.startswith("172.1") / ("172.2"), which flagged
        # all of these as the proxy although none is in 172.16.0.0/12.
        for ip in ("172.1.2.3", "172.15.255.255", "172.32.0.1", "172.100.1.1",
                   "172.200.0.1", "172.217.14.206", "172.253.1.1"):
            with self.subTest(ip=ip):
                self.assertFalse(looks_like_proxy(ip))

    def test_ordinary_peers_are_not_proxy(self):
        for ip in ("8.8.8.8", "203.0.113.5", "198.51.100.7", "2001:db8::1"):
            with self.subTest(ip=ip):
                self.assertFalse(looks_like_proxy(ip))

    def test_ipv4_mapped_ipv6(self):
        self.assertTrue(looks_like_proxy("::ffff:172.17.0.1"))
        self.assertTrue(looks_like_proxy("::ffff:127.0.0.1"))
        self.assertFalse(looks_like_proxy("::ffff:8.8.8.8"))
        self.assertFalse(looks_like_proxy("::ffff:172.217.14.206"))

    def test_malformed_input_is_not_proxy(self):
        for ip in ("", None, "not-an-ip", "172.17", "172.17.0.1.5", "172."):
            with self.subTest(ip=ip):
                self.assertFalse(looks_like_proxy(ip))

    def test_surrounding_whitespace_is_ignored(self):
        self.assertTrue(looks_like_proxy(" 172.17.0.1 "))


class TestIsDockerBridgeAddr(unittest.TestCase):
    """The auto-blacklist skips only these: a bridge address as the *peer*
    means attribution failed. Loopback must still be blockable (it is the
    real peer in a one-machine rehearsal), and so must public 172.x space."""

    def test_bridge_range(self):
        for ip in ("172.16.0.1", "172.17.0.1", "172.31.255.254", "::ffff:172.17.0.1"):
            with self.subTest(ip=ip):
                self.assertTrue(is_docker_bridge_addr(ip))

    def test_loopback_is_not_bridge(self):
        for ip in ("127.0.0.1", "::1", "localhost"):
            with self.subTest(ip=ip):
                self.assertFalse(is_docker_bridge_addr(ip))

    def test_public_172_space_is_not_bridge(self):
        for ip in ("172.15.0.1", "172.32.0.1", "172.100.1.1", "172.217.14.206"):
            with self.subTest(ip=ip):
                self.assertFalse(is_docker_bridge_addr(ip))

    def test_malformed_is_not_bridge(self):
        for ip in ("", None, "garbage", "172.17"):
            with self.subTest(ip=ip):
                self.assertFalse(is_docker_bridge_addr(ip))


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


class TestPeerAttributorResolve(unittest.TestCase):

    T0 = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.log = Path(self._dir.name) / "sessions.jsonl"

    def _write_events(self, *events):
        with self.log.open("w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")

    def _proxy_event(self, ip, when):
        return {"event": "PROXY_CONNECTED", "type": "honeypot",
                "ip": ip, "ts": _iso(when)}

    def test_session_is_matched_to_the_peer_the_gateway_proxied(self):
        self._write_events(self._proxy_event("198.51.100.7", self.T0))
        attr = PeerAttributor(event_log=self.log, window=45.0)
        got = attr.resolve(_iso(self.T0 + timedelta(seconds=3)),
                           fallback="172.17.0.1")
        self.assertEqual(got, "198.51.100.7")

    def test_closest_event_wins(self):
        self._write_events(
            self._proxy_event("198.51.100.7", self.T0),
            self._proxy_event("203.0.113.9", self.T0 + timedelta(seconds=20)),
        )
        attr = PeerAttributor(event_log=self.log, window=45.0)
        got = attr.resolve(_iso(self.T0 + timedelta(seconds=18)),
                           fallback="172.17.0.1")
        self.assertEqual(got, "203.0.113.9")

    def test_outside_window_falls_back_to_observed_address(self):
        self._write_events(self._proxy_event("198.51.100.7", self.T0))
        attr = PeerAttributor(event_log=self.log, window=45.0)
        got = attr.resolve(_iso(self.T0 + timedelta(seconds=300)),
                           fallback="172.17.0.1")
        self.assertEqual(got, "172.17.0.1")

    def test_non_honeypot_events_are_ignored(self):
        ev = self._proxy_event("198.51.100.7", self.T0)
        ev["type"] = "backend"
        self._write_events(ev)
        attr = PeerAttributor(event_log=self.log, window=45.0)
        self.assertEqual(attr.resolve(_iso(self.T0), fallback="x"), "x")

    def test_missing_log_falls_back(self):
        # The no-gateway (direct-to-internet) topology has no gateway log at
        # all; every session must keep the address the honeypot saw.
        attr = PeerAttributor(event_log=Path(self._dir.name) / "absent.jsonl")
        self.assertEqual(attr.resolve(_iso(self.T0), fallback="198.51.100.7"),
                         "198.51.100.7")

    def test_unparseable_start_time_falls_back(self):
        self._write_events(self._proxy_event("198.51.100.7", self.T0))
        attr = PeerAttributor(event_log=self.log)
        self.assertEqual(attr.resolve("garbage", fallback="fb"), "fb")
        self.assertEqual(attr.resolve(None, fallback="fb"), "fb")


if __name__ == "__main__":
    unittest.main()
