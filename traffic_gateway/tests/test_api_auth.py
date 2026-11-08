"""
traffic_gateway/tests/test_api_auth.py

HONEYPOT_AUDIT.md PART 3, fix #1 -- the one it rated more urgent than any of the
other thirteen items. `POST`/`DELETE` on `/api/blacklist` and `/api/whitelist`
had no authentication and CORS allowed every origin, so anyone who could reach
port 5000 could whitelist themselves and walk past the gateway, the honeypot and
MT3 in a single request.

The most important test here is not the token check -- it is
TestStartupGuard.test_reachable_host_without_a_token_is_refused. A weak token is
a theoretical problem; deploying to a VPS having never set one is the realistic
one, and that is the mistake the guard has to stop.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_tmp = tempfile.mkdtemp()
import traffic_gateway.config as _cfg_mod
_cfg_mod.CONFIG.DATA_DIR = Path(_tmp) / "data"
_cfg_mod.CONFIG.LOG_DIR = Path(_tmp) / "logs"
_cfg_mod.CONFIG.DATA_DIR.mkdir(parents=True, exist_ok=True)
_cfg_mod.CONFIG.LOG_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(REPO_ROOT / "honeypot_dataset"))

from traffic_gateway import api_auth                                    # noqa: E402
from traffic_gateway.api_auth import (                                  # noqa: E402
    InsecureExposure, allowed_origins, assert_safe_to_serve, auth_status,
    configured_token, is_loopback_host, reads_need_auth, token_matches,
)

GOOD_TOKEN = "a" * 40


class _Env(unittest.TestCase):
    """Restores every GATEWAY_API_* variable, whatever the test did to them."""

    VARS = ("GATEWAY_API_TOKEN", "GATEWAY_API_ORIGINS",
            "GATEWAY_API_REQUIRE_AUTH_FOR_READS")

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in self.VARS}
        for k in self.VARS:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class TestTokenConfig(_Env):

    def test_unset_is_none(self):
        self.assertIsNone(configured_token())

    def test_blank_is_none(self):
        os.environ["GATEWAY_API_TOKEN"] = "   "
        self.assertIsNone(configured_token())

    def test_a_good_token_is_returned(self):
        os.environ["GATEWAY_API_TOKEN"] = GOOD_TOKEN
        self.assertEqual(configured_token(), GOOD_TOKEN)

    def test_a_short_token_is_refused_not_warned_about(self):
        """A warning in a log nobody reads is not protection."""
        for weak in ("x", "secret", "a" * 15):
            with self.subTest(token=weak):
                os.environ["GATEWAY_API_TOKEN"] = weak
                with self.assertRaises(InsecureExposure):
                    configured_token()

    def test_sixteen_characters_is_the_boundary(self):
        os.environ["GATEWAY_API_TOKEN"] = "a" * 16
        self.assertEqual(configured_token(), "a" * 16)

    def test_generated_tokens_are_long_and_unique(self):
        a, b = api_auth._generate(), api_auth._generate()
        self.assertNotEqual(a, b)
        self.assertGreaterEqual(len(a), 32)


class TestTokenComparison(unittest.TestCase):

    def test_matching(self):
        self.assertTrue(token_matches(GOOD_TOKEN, GOOD_TOKEN))

    def test_not_matching(self):
        self.assertFalse(token_matches("b" * 40, GOOD_TOKEN))

    def test_missing_either_side_never_matches(self):
        for presented, expected in ((None, GOOD_TOKEN), (GOOD_TOKEN, None),
                                    ("", GOOD_TOKEN), (GOOD_TOKEN, ""),
                                    (None, None)):
            with self.subTest(presented=presented, expected=expected):
                self.assertFalse(token_matches(presented, expected))

    def test_a_prefix_does_not_match(self):
        self.assertFalse(token_matches(GOOD_TOKEN[:20], GOOD_TOKEN))


class TestTokenExtraction(unittest.TestCase):

    def headers(self, **kw):
        return {k.replace("_", "-"): v for k, v in kw.items()}

    def test_bearer_header(self):
        self.assertEqual(
            api_auth.token_from_request(self.headers(Authorization=f"Bearer {GOOD_TOKEN}")),
            GOOD_TOKEN)

    def test_bearer_is_case_insensitive_on_the_scheme(self):
        self.assertEqual(
            api_auth.token_from_request(self.headers(Authorization=f"bearer {GOOD_TOKEN}")),
            GOOD_TOKEN)

    def test_x_api_token_header(self):
        self.assertEqual(
            api_auth.token_from_request(self.headers(X_API_Token=GOOD_TOKEN)),
            GOOD_TOKEN)

    def test_nothing_presented(self):
        self.assertIsNone(api_auth.token_from_request({}))

    def test_empty_bearer_is_nothing(self):
        self.assertIsNone(api_auth.token_from_request(
            self.headers(Authorization="Bearer    ")))


class TestStartupGuard(_Env):
    """The part that actually protects anyone."""

    def test_reachable_host_without_a_token_is_refused(self):
        for host in ("0.0.0.0", "", "192.168.0.201", "10.1.4.147", "::"):
            with self.subTest(host=host):
                with self.assertRaises(InsecureExposure) as ctx:
                    assert_safe_to_serve(host)
                msg = str(ctx.exception)
                self.assertIn("GATEWAY_API_TOKEN", msg)
                self.assertIn("127.0.0.1", msg, "must say how to bind safely")

    def test_loopback_without_a_token_is_allowed(self):
        for host in ("127.0.0.1", "localhost", "::1"):
            with self.subTest(host=host):
                assert_safe_to_serve(host)        # must not raise

    def test_reachable_host_with_a_token_is_allowed(self):
        os.environ["GATEWAY_API_TOKEN"] = GOOD_TOKEN
        assert_safe_to_serve("0.0.0.0")           # must not raise

    def test_a_short_token_does_not_satisfy_the_guard(self):
        os.environ["GATEWAY_API_TOKEN"] = "short"
        with self.assertRaises(InsecureExposure):
            assert_safe_to_serve("0.0.0.0")

    def test_unparseable_host_fails_closed(self):
        with self.assertRaises(InsecureExposure):
            assert_safe_to_serve("not-a-host")


class TestLoopbackDetection(unittest.TestCase):

    def test_loopback(self):
        for host in ("127.0.0.1", "127.0.0.5", "::1", "localhost"):
            with self.subTest(host=host):
                self.assertTrue(is_loopback_host(host))

    def test_not_loopback(self):
        for host in ("0.0.0.0", "::", "", "192.168.1.5", "10.1.4.147",
                     "45.33.32.156", "not-a-host"):
            with self.subTest(host=host):
                self.assertFalse(is_loopback_host(host))


class TestOrigins(_Env):

    def test_default_covers_the_local_dev_servers(self):
        origins = allowed_origins()
        self.assertIn("http://localhost:5173", origins)   # vite
        self.assertIn("http://127.0.0.1:5000", origins)   # legacy dashboard
        self.assertNotIn("*", origins)

    def test_explicit_list_is_used(self):
        os.environ["GATEWAY_API_ORIGINS"] = "https://soc.example.com, http://10.1.4.147:5173"
        self.assertEqual(allowed_origins(),
                         ["https://soc.example.com", "http://10.1.4.147:5173"])

    def test_star_is_honoured_but_is_not_the_default(self):
        os.environ["GATEWAY_API_ORIGINS"] = "*"
        self.assertEqual(allowed_origins(), ["*"])
        os.environ.pop("GATEWAY_API_ORIGINS")
        self.assertNotIn("*", allowed_origins())


class TestReadsFlag(_Env):

    def test_default_is_open(self):
        self.assertFalse(reads_need_auth())

    def test_can_be_switched_on(self):
        for value in ("1", "true", "YES", "on"):
            with self.subTest(value=value):
                os.environ["GATEWAY_API_REQUIRE_AUTH_FOR_READS"] = value
                self.assertTrue(reads_need_auth())


class TestAuthStatus(_Env):
    """Reported on /api/health, so it must never leak the secret."""

    def test_never_contains_the_token(self):
        os.environ["GATEWAY_API_TOKEN"] = GOOD_TOKEN
        blob = repr(auth_status("0.0.0.0"))
        self.assertNotIn(GOOD_TOKEN, blob)
        self.assertNotIn(GOOD_TOKEN[:8], blob)

    def test_reports_what_is_enforced(self):
        os.environ["GATEWAY_API_TOKEN"] = GOOD_TOKEN
        st = auth_status("0.0.0.0")
        self.assertTrue(st["token_configured"])
        self.assertTrue(st["writes_require_token"])
        self.assertFalse(st["reads_require_token"])
        self.assertFalse(st["bind_is_loopback"])

    def test_reports_the_open_state_honestly(self):
        st = auth_status("127.0.0.1")
        self.assertFalse(st["token_configured"])
        self.assertFalse(st["writes_require_token"])
        self.assertTrue(st["bind_is_loopback"])

    def test_a_bad_token_surfaces_as_a_problem_not_a_crash(self):
        os.environ["GATEWAY_API_TOKEN"] = "short"
        st = auth_status("0.0.0.0")
        self.assertFalse(st["token_configured"])
        self.assertIn("problem", st)


class TestEndpointsAreGuarded(_Env):
    """Exercises the real Flask app, so a decorator that was never applied fails."""

    WRITES = (("post", "/api/blacklist", {"ip": "45.33.32.156"}),
              ("delete", "/api/blacklist/45.33.32.156", None),
              ("post", "/api/whitelist", {"ip": "45.33.32.156"}),
              ("delete", "/api/whitelist/45.33.32.156", None))

    def client(self):
        from traffic_gateway import api
        api.app.config["TESTING"] = True
        return api.app.test_client()

    def test_writes_are_401_without_a_token(self):
        os.environ["GATEWAY_API_TOKEN"] = GOOD_TOKEN
        c = self.client()
        for method, path, body in self.WRITES:
            with self.subTest(path=f"{method.upper()} {path}"):
                r = getattr(c, method)(path, json=body)
                self.assertEqual(r.status_code, 401)
                self.assertEqual(r.headers.get("WWW-Authenticate"), "Bearer")

    def test_writes_are_401_with_the_wrong_token(self):
        os.environ["GATEWAY_API_TOKEN"] = GOOD_TOKEN
        c = self.client()
        for method, path, body in self.WRITES:
            with self.subTest(path=path):
                r = getattr(c, method)(path, json=body,
                                       headers={"Authorization": "Bearer " + "b" * 40})
                self.assertEqual(r.status_code, 401)

    def test_writes_pass_the_gate_with_the_right_token(self):
        os.environ["GATEWAY_API_TOKEN"] = GOOD_TOKEN
        c = self.client()
        for method, path, body in self.WRITES:
            with self.subTest(path=path):
                r = getattr(c, method)(path, json=body,
                                       headers={"Authorization": f"Bearer {GOOD_TOKEN}"})
                self.assertNotEqual(r.status_code, 401,
                                    "the right token must get past the gate")

    def test_reads_stay_open_by_default(self):
        os.environ["GATEWAY_API_TOKEN"] = GOOD_TOKEN
        r = self.client().get("/api/health")
        self.assertEqual(r.status_code, 200)

    def test_writes_are_open_when_no_token_is_configured(self):
        """Unchanged local behaviour -- assert_safe_to_serve is what stops this
        leniency reaching a public port."""
        r = self.client().post("/api/blacklist", json={"ip": "45.33.32.156"})
        self.assertNotEqual(r.status_code, 401)

    def test_health_reports_auth_without_leaking_it(self):
        os.environ["GATEWAY_API_TOKEN"] = GOOD_TOKEN
        r = self.client().get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["auth"]["writes_require_token"])
        self.assertNotIn(GOOD_TOKEN, r.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
