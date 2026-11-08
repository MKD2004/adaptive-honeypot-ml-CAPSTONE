"""
response_mitigation/tests/test_mitigation_alert.py

ALERT: the log line, the chat webhook, and the webhook's settings. The webhook is tested three ways:
with a stand-in sender, with a real HTTP server on this machine, and through the engine.
Nothing here contacts the internet.
"""
import http.server
import json
import logging
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path

from response_mitigation.audit import AuditLog
from response_mitigation.config import load_config
from response_mitigation.engine import MitigationEngine, build_engine
from response_mitigation.executors.alert import (CompositeAlertExecutor, LogAlertExecutor, WebhookAlertExecutor,
                                                 _post_json, alert_text)
from response_mitigation.models import Action, Outcome, PlannedAction, Verdict
from response_mitigation.safelist import Safelist

SECRET_URL = "https://hooks.example.com/services/T000/B000/SECRETSECRETSECRET"


def verdict(phase=7, ip="45.33.32.156", conf=0.93, sid="s1", state="LATERAL_SSH"):
    return Verdict(ip=ip, phase=phase, phase_name="Lateral Movement", micro_state=state,
                   confidence=conf, session_id=sid)


PLAN = PlannedAction(Action.ALERT, "late_stage_alert", "this attacker is late in the kill chain; a person should look")


class FakeSender:
    def __init__(self, status=200, error=None, gate=None):
        self.calls, self.status, self.error, self.gate = [], status, error, gate

    def __call__(self, url, payload, timeout):
        if self.gate is not None:
            self.gate.wait(5)
        self.calls.append((url, payload, timeout))
        if self.error:
            raise self.error
        return self.status


class TestTheMessage(unittest.TestCase):

    def test_what_a_person_reads(self):
        text = alert_text(verdict(), PLAN)
        for part in ("45.33.32.156", "LATERAL_SSH", "phase 7 Lateral Movement", "93%", "late_stage_alert", "Session s1"):
            self.assertIn(part, text)

    def test_nothing_the_attacker_typed_can_get_in(self):
        v = verdict()
        text = alert_text(v, PLAN)
        self.assertEqual(set(vars(v)) - {"ip", "phase", "phase_name", "micro_state", "confidence", "session_id", "sessions_seen"}, set())
        self.assertNotIn("\n", text)

    def test_it_is_one_short_line(self):
        long_plan = PlannedAction(Action.ALERT, "r", "word " * 1000)
        text = alert_text(verdict(), long_plan)
        self.assertLessEqual(len(text), 1800)
        self.assertNotIn("\n", text)
        self.assertNotIn("  ", alert_text(verdict(), PlannedAction(Action.ALERT, "r", "a   b\n\nc")))


class TestTheWebhook(unittest.TestCase):

    def make(self, sender=None, **kw):
        sender = sender or FakeSender()
        hook = WebhookAlertExecutor(SECRET_URL, post=sender, **kw)
        self.addCleanup(hook.close)
        return hook, sender

    def test_a_message_is_sent_to_the_url_with_both_chat_field_names(self):
        hook, sender = self.make()
        note = hook.apply(verdict(), PLAN)
        self.assertTrue(hook.flush())
        self.assertEqual(note, "queued for the webhook at hooks.example.com")
        (url, payload, timeout), = sender.calls
        self.assertEqual(url, SECRET_URL)
        self.assertEqual(set(payload), {"text", "content"})            # Slack reads "text", Discord reads "content"
        self.assertEqual(payload["text"], payload["content"])
        self.assertEqual(timeout, 5.0)

    def test_the_note_for_the_audit_log_never_contains_the_secret_url(self):
        hook, _ = self.make()
        self.assertNotIn("SECRET", hook.apply(verdict(), PLAN))

    def test_at_most_n_messages_an_hour(self):
        now = [1000.0]
        hook, sender = self.make(max_per_hour=2, clock=lambda: now[0])
        notes = [hook.apply(verdict(sid=f"s{i}"), PLAN) for i in range(4)]
        hook.flush()
        self.assertEqual(len(sender.calls), 2)
        self.assertTrue(notes[2].startswith("webhook limit of 2 per hour reached"))
        now[0] += 3600
        self.assertTrue(hook.apply(verdict(), PLAN).startswith("queued"))
        hook.flush()
        self.assertEqual(len(sender.calls), 3)

    def test_a_limit_of_zero_sends_nothing(self):
        hook, sender = self.make(max_per_hour=0)
        self.assertIn("limit", hook.apply(verdict(), PLAN))
        hook.flush()
        self.assertEqual(sender.calls, [])

    def test_a_dead_webhook_never_raises_and_later_alerts_still_go_out(self):
        sender = FakeSender(error=ConnectionError("down"))
        hook, _ = self.make(sender)
        with self.assertLogs("response_mitigation.alert", level="WARNING") as logs:
            hook.apply(verdict(sid="a"), PLAN)
            hook.apply(verdict(sid="b"), PLAN)
            hook.flush()
        self.assertEqual(len(sender.calls), 2)
        self.assertIn("ConnectionError", " ".join(logs.output))

    def test_the_log_names_the_host_and_never_the_secret(self):
        for sender in (FakeSender(error=RuntimeError("boom")), FakeSender(status=500),
                       FakeSender(error=urllib.error.HTTPError(SECRET_URL, 403, "no", {}, None))):
            hook, _ = self.make(sender)
            with self.assertLogs("response_mitigation.alert", level="WARNING") as logs:
                hook.apply(verdict(), PLAN)
                hook.flush()
            text = " ".join(logs.output)
            self.assertIn("hooks.example.com", text)
            self.assertNotIn("SECRET", text)

    def test_a_full_queue_drops_the_message_instead_of_waiting(self):
        gate = threading.Event()
        hook, _ = self.make(FakeSender(gate=gate), queue_size=1, max_per_hour=100)
        notes = [hook.apply(verdict(sid=f"s{i}"), PLAN) for i in range(5)]       # the worker is stuck on the first
        gate.set()
        self.assertTrue(any("queue is full" in n for n in notes))
        hook.flush()

    def test_apply_returns_at_once_even_if_the_webhook_is_slow(self):
        gate = threading.Event()
        hook, sender = self.make(FakeSender(gate=gate))
        hook.apply(verdict(), PLAN)
        self.assertEqual(sender.calls, [])             # not sent yet, and we are already back
        gate.set()
        hook.flush()
        self.assertEqual(len(sender.calls), 1)


class _Capture(http.server.BaseHTTPRequestHandler):
    seen = []
    redirect = False

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        type(self).seen.append((self.path, self.headers.get("Content-Type"), self.headers.get("User-Agent"), json.loads(body)))
        if type(self).redirect and self.path == "/hook":
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.end_headers()
            return
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


class TestARealHttpServer(unittest.TestCase):

    def setUp(self):
        _Capture.seen, _Capture.redirect = [], False
        self.server = http.server.HTTPServer(("127.0.0.1", 0), _Capture)
        self.addCleanup(self.server.server_close)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/hook"

    def test_the_real_post(self):
        self.assertEqual(_post_json(self.url, {"text": "hi", "content": "hi"}, 5), 204)
        (path, ctype, agent, body), = _Capture.seen
        self.assertEqual((path, ctype, agent, body), ("/hook", "application/json", "honeypot-mitigation/1", {"text": "hi", "content": "hi"}))

    def test_a_redirect_is_not_followed(self):
        _Capture.redirect = True
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            _post_json(self.url, {"text": "x"}, 5)
        self.assertEqual(ctx.exception.code, 302)
        self.assertEqual([p for p, *_ in _Capture.seen], ["/hook"])          # never went on to /elsewhere

    def test_end_to_end_through_the_executor(self):
        hook = WebhookAlertExecutor(self.url)
        self.addCleanup(hook.close)
        hook.apply(verdict(), PLAN)
        self.assertTrue(hook.flush())
        (_, _, _, body), = _Capture.seen
        self.assertIn("45.33.32.156", body["text"])

    def test_a_server_that_is_not_there(self):
        self.server.shutdown()
        self.server.server_close()
        hook = WebhookAlertExecutor(self.url, timeout_s=1)
        self.addCleanup(hook.close)
        with self.assertLogs("response_mitigation.alert", level="WARNING"):
            hook.apply(verdict(), PLAN)
            self.assertTrue(hook.flush(10))


class TestCombiningSinks(unittest.TestCase):

    class Sink:
        def __init__(self, note=None, error=None):
            self.note, self.error, self.calls = note, error, 0

        def apply(self, v, p):
            self.calls += 1
            if self.error:
                raise self.error
            return self.note

    def test_all_sinks_run_and_the_notes_are_joined(self):
        a, b = self.Sink("one"), self.Sink("two")
        self.assertEqual(CompositeAlertExecutor([a, b]).apply(verdict(), PLAN), "one; two")

    def test_one_failing_sink_does_not_stop_the_others(self):
        bad, good = self.Sink(error=RuntimeError("x")), self.Sink("fine")
        with self.assertLogs("response_mitigation.alert", level="ERROR"):
            self.assertEqual(CompositeAlertExecutor([bad, good]).apply(verdict(), PLAN), "fine")
        self.assertEqual((bad.calls, good.calls), (1, 1))

    def test_if_every_sink_fails_the_engine_is_told(self):
        with self.assertLogs("response_mitigation.alert", level="ERROR"), self.assertRaises(RuntimeError):
            CompositeAlertExecutor([self.Sink(error=RuntimeError("a")), self.Sink(error=RuntimeError("b"))]).apply(verdict(), PLAN)


class TestTheSettings(unittest.TestCase):

    def cfg(self, **env):
        return load_config(env)

    def test_off_by_default(self):
        cfg = self.cfg()
        self.assertIsNone(cfg.alert_webhook)
        self.assertEqual(cfg.alert_max_per_hour, 30)

    def test_valid_urls(self):
        for url in (SECRET_URL, "https://discord.com/api/webhooks/1/abc", "http://localhost:9000/hook",
                    "http://127.0.0.1:1/x", "http://[::1]:5/x"):
            with self.subTest(url=url):
                self.assertEqual(self.cfg(MITIGATION_ALERT_WEBHOOK=url).alert_webhook, url)

    def test_bad_urls_are_refused_and_the_error_does_not_show_the_url(self):
        for url in ("http://hooks.example.com/x", "ftp://hooks.example.com/x", "hooks.example.com/x", "https://",
                    "https://hooks.example.com/with space", "https://x.example.com/" + "a" * 3000, "javascript:alert(1)"):
            with self.subTest(url=url[:40]):
                with self.assertRaises(ValueError) as ctx:
                    self.cfg(MITIGATION_ALERT_WEBHOOK=url)
                self.assertIn("MITIGATION_ALERT_WEBHOOK", str(ctx.exception))
                self.assertNotIn("hooks.example.com/x", str(ctx.exception))

    def test_the_hourly_limit(self):
        self.assertEqual(self.cfg(MITIGATION_ALERT_MAX_PER_HOUR="5").alert_max_per_hour, 5)
        self.assertEqual(self.cfg(MITIGATION_ALERT_MAX_PER_HOUR="0").alert_max_per_hour, 0)
        for bad in ("-1", "1001", "many"):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                self.cfg(MITIGATION_ALERT_MAX_PER_HOUR=bad)


class TestThroughTheEngine(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def env(self, **extra):
        return {"MITIGATION_AUDIT_PATH": str(self.dir / "audit.jsonl"), "MITIGATION_KILL_FILE": str(self.dir / "STOP"),
                "MITIGATION_BLOCKLIST_PATH": str(self.dir / "bl.json"), **extra}

    def test_a_late_stage_session_sends_a_message_in_enforce_mode(self):
        cfg = load_config(self.env(MITIGATION_MODE="enforce"))
        sender = FakeSender()
        hook = WebhookAlertExecutor("https://hooks.example.com/x", post=sender)
        self.addCleanup(hook.close)
        engine = MitigationEngine(cfg, safelist=Safelist(), audit=AuditLog(cfg.audit_path),
                                  executors={Action.ALERT: CompositeAlertExecutor([LogAlertExecutor(), hook])})
        with self.assertLogs("response_mitigation.alert", level="WARNING"):
            decisions = engine.handle(verdict(phase=7))
        hook.flush()
        alert = next(d for d in decisions if d.planned.action is Action.ALERT)
        self.assertIs(alert.outcome, Outcome.APPLIED)
        self.assertIn("written to the log", alert.detail)
        self.assertIn("queued for the webhook", alert.detail)
        self.assertEqual(len(sender.calls), 1)

    def test_in_observe_mode_nothing_is_sent_only_logged_as_would_apply(self):
        cfg = load_config(self.env(MITIGATION_MODE="observe"))
        sender = FakeSender()
        hook = WebhookAlertExecutor("https://hooks.example.com/x", post=sender)
        self.addCleanup(hook.close)
        engine = MitigationEngine(cfg, safelist=Safelist(), audit=AuditLog(cfg.audit_path), executors={Action.ALERT: hook})
        alert = next(d for d in engine.handle(verdict(phase=7)) if d.planned.action is Action.ALERT)
        hook.flush()
        self.assertIs(alert.outcome, Outcome.WOULD_APPLY)
        self.assertEqual(sender.calls, [])

    def test_the_builder_adds_the_webhook_only_when_one_is_configured(self):
        plain = build_engine(blacklist_manager=None, config=load_config(self.env()), audit=AuditLog(self.dir / "a1"))
        self.assertIsInstance(plain._executors[Action.ALERT], LogAlertExecutor)
        wired = build_engine(blacklist_manager=None, audit=AuditLog(self.dir / "a2"),
                             config=load_config(self.env(MITIGATION_ALERT_WEBHOOK="http://127.0.0.1:9/x")))
        self.addCleanup(lambda: [s.close() for s in wired._executors[Action.ALERT]._sinks if hasattr(s, "close")])
        self.assertIsInstance(wired._executors[Action.ALERT], CompositeAlertExecutor)
        self.assertTrue(wired.status()["alert_webhook"])
        self.assertNotIn("127.0.0.1", json.dumps(wired.status()))              # the URL is a secret: only "yes/no" is shown


if __name__ == "__main__":
    unittest.main()
