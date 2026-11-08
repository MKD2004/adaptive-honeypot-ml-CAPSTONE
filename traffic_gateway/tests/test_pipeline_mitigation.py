"""
traffic_gateway/tests/test_pipeline_mitigation.py

PostSessionPipeline.process_session -> response_mitigation, end to end, with a
stand-in MT3 and a stand-in blacklist. Checks what lands in the result record
and which IPs reach the blacklist. This is the first automated test of the
auto-blacklist decision. No real model, network, blacklist file or log is used.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from response_mitigation.audit import AuditLog
from response_mitigation.config import load_config
from response_mitigation.engine import build_engine
from traffic_gateway import post_session_pipeline as psp

PUBLIC_IP = "45.33.32.156"


class FakeManager:
    def __init__(self, whitelisted=(), blacklisted=()):
        self._wl, self._bl = set(whitelisted), set(blacklisted)
        self.calls = []

    def is_whitelisted(self, ip):
        return ip in self._wl

    def is_blacklisted(self, ip):
        return ip in self._bl

    def blacklist(self, ip, *, reason, source, risk_score):
        self.calls.append((ip, reason, source, risk_score))
        self._bl.add(ip)


class StubMT3:
    def __init__(self, phase, confidence):
        self.phase, self.confidence = phase, confidence

    def predict(self, x_raw):
        return {"micro_state": "SSH_BRUTE_FORCE", "phase": self.phase,
                "phase_name": "Initial Access", "confidence": self.confidence,
                "top3": []}


def stub_configurator(pred, record):
    return {"previous_config": None, "new_config": None, "changed": False, "reason": "stub"}


class PipelineCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.manager = FakeManager()

        # attribution is not what is under test; keep it from reading real logs
        for name, kwargs in (("resolve_peer_ip", {"side_effect": lambda t, fallback="": fallback}),
                             ("extract_features", {"return_value": np.zeros(128)})):
            patcher = patch.object(psp, name, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    def engine(self, manager=None, **kwargs):
        cfg = load_config({"MITIGATION_AUDIT_PATH": str(self.tmp / "audit.jsonl"),
                           "MITIGATION_KILL_FILE": str(self.tmp / "STOP")})
        return build_engine(blacklist_manager=manager or self.manager, config=cfg,
                            audit=AuditLog(cfg.audit_path), **kwargs)

    def pipeline(self, phase=3, confidence=0.9, engine=None):
        p = psp.PostSessionPipeline(
            cowrie_log_dir=self.tmp / "cowrie", results_path=self.tmp / "results.jsonl",
            configurator=stub_configurator, mitigation=engine or self.engine())
        p.mt3 = StubMT3(phase, confidence)
        p.started = True    # skip the slow start-up (threat intel, DistilBERT, checkpoint)
        return p

    def run_session(self, p, ip=PUBLIC_IP, sid="s1"):
        # source="cowrie_real" matters: mt3_is_trusted_for() gates the mitigation
        # layer on it, and cowrie_parser.build_record always sets it. Without it
        # the gate fails closed and mitigation is skipped -- which is the correct
        # behaviour, covered by TestUntrustedSourceIsNotMitigated below.
        record = {"session_id": sid, "src_ip": ip, "t_start": 1_700_000_000.0,
                  "source": "cowrie_real",
                  "command_text": "uname -a ; id", "login_attempts": 3,
                  "session_duration_s": 4.0, "micro_state_sequence": ""}
        return p.process_session(record, gateway_score=0.2, write=False)


class TestAutoBlacklist(PipelineCase):

    def test_attack_from_a_public_ip_is_blacklisted(self):
        result = self.run_session(self.pipeline(phase=3, confidence=0.9))
        self.assertIs(result["auto_blacklisted"], True)
        self.assertEqual(self.manager.calls, [(
            PUBLIC_IP, "MT3: SSH_BRUTE_FORCE (phase 3 Initial Access, conf 0.90)",
            "mt3_pipeline", 0.9)])
        self.assertEqual(result["mitigation"], [
            {"action": "divert", "rule": "divert_attack", "outcome": "applied"}])

    def test_recon_is_only_recorded(self):
        result = self.run_session(self.pipeline(phase=0, confidence=0.99))
        self.assertIs(result["auto_blacklisted"], False)
        self.assertEqual(self.manager.calls, [])
        self.assertEqual([m["action"] for m in result["mitigation"]], ["observe"])

    def test_low_confidence_is_only_recorded(self):
        result = self.run_session(self.pipeline(phase=5, confidence=0.3))
        self.assertIs(result["auto_blacklisted"], False)
        self.assertEqual(self.manager.calls, [])

    def test_docker_bridge_address_is_not_blacklisted(self):
        result = self.run_session(self.pipeline(), ip="172.17.0.1")
        self.assertIs(result["auto_blacklisted"], False)
        self.assertEqual(self.manager.calls, [])
        self.assertEqual(result["mitigation"][0]["outcome"], "skipped")

    def test_public_172_address_is_blacklisted(self):
        # The case the old "172.1" / "172.2" text check got wrong.
        result = self.run_session(self.pipeline(), ip="172.217.14.206")
        self.assertIs(result["auto_blacklisted"], True)
        self.assertEqual(self.manager.calls[0][0], "172.217.14.206")

    def test_loopback_peer_is_blacklisted_for_the_single_laptop_demo(self):
        result = self.run_session(self.pipeline(), ip="127.0.0.1")
        self.assertIs(result["auto_blacklisted"], True)

    def test_whitelisted_and_already_blacklisted_are_left_alone(self):
        for manager in (FakeManager(whitelisted={PUBLIC_IP}), FakeManager(blacklisted={PUBLIC_IP})):
            with self.subTest(manager=manager._wl or manager._bl):
                result = self.run_session(self.pipeline(engine=self.engine(manager)))
                self.assertIs(result["auto_blacklisted"], False)
                self.assertEqual(manager.calls, [])

    def test_auto_blacklist_switched_off(self):
        engine = self.engine(divert_enabled=False)
        result = self.run_session(self.pipeline(engine=engine))
        self.assertIs(result["auto_blacklisted"], False)
        self.assertEqual(self.manager.calls, [])

    def test_the_decision_is_in_the_audit_log(self):
        self.run_session(self.pipeline())
        lines = (self.tmp / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertIn('"action":"divert"', lines[0])
        self.assertIn(PUBLIC_IP, lines[0])


class TestPipelineSurvivesMitigationFailures(PipelineCase):

    def test_an_engine_that_raises_does_not_lose_the_session(self):
        engine = self.engine()
        engine.handle = lambda verdict: (_ for _ in ()).throw(RuntimeError("engine bug"))
        with self.assertLogs("traffic_gateway.post_session", level="ERROR"):
            result = self.run_session(self.pipeline(engine=engine))
        self.assertIs(result["auto_blacklisted"], False)
        self.assertEqual(result["mitigation"], [])
        self.assertEqual(result["mt3_prediction"]["micro_state"], "SSH_BRUTE_FORCE")

    def test_the_old_result_fields_are_still_there(self):
        result = self.run_session(self.pipeline())
        for key in ("session_id", "src_ip", "mt3_prediction", "honeypot_action",
                    "auto_blacklisted", "gateway_score", "latency_ms"):
            self.assertIn(key, result)


class TestEngineIsBuiltFromTheEnvironment(PipelineCase):

    def env(self, **extra):
        base = {"MITIGATION_AUDIT_PATH": str(self.tmp / "audit.jsonl"),
                "MITIGATION_KILL_FILE": str(self.tmp / "STOP")}
        return patch.dict(os.environ, {**base, **extra})

    def bare_pipeline(self):
        return psp.PostSessionPipeline(cowrie_log_dir=self.tmp / "cowrie",
                                       results_path=self.tmp / "results.jsonl")

    def test_it_uses_the_gateways_own_thresholds_and_is_built_once(self):
        with self.env(), patch.object(psp, "blacklist_manager", self.manager):
            p = self.bare_pipeline()
            engine = p._get_mitigation()
            self.assertIs(p._get_mitigation(), engine)
        self.assertEqual(engine.config.policy.divert_min_phase, psp.CONFIG.MT3_AUTO_BLACKLIST_MIN_PHASE)
        self.assertEqual(engine.config.policy.min_confidence, psp.CONFIG.MT3_AUTO_BLACKLIST_CONF)

    def test_a_bad_mitigation_setting_stops_start_up(self):
        with self.env(MITIGATION_MODE="enforcing"):
            with self.assertRaises(ValueError) as ctx:
                self.bare_pipeline().startup()    # fails before any slow loading
        self.assertIn("MITIGATION_MODE", str(ctx.exception))


class TestProvenance(PipelineCase):
    """Every result says which honeypot saw the session and where the data comes from."""

    def with_source(self, value):
        patcher = patch.dict(os.environ, {"PIPELINE_SOURCE": value} if value is not None else {})
        patcher.start()
        self.addCleanup(patcher.stop)
        if value is None:
            os.environ.pop("PIPELINE_SOURCE", None)

    def test_the_result_carries_the_sensor_and_a_source(self):
        self.with_source(None)
        record = {"session_id": "s1", "src_ip": PUBLIC_IP, "t_start": 1_700_000_000.0,
                  "source": "cowrie_real", "command_text": "id",
                  "login_attempts": 1, "session_duration_s": 2.0, "micro_state_sequence": "",
                  "sensor": "sandbox-cowrie-1"}
        result = self.pipeline().process_session(record, gateway_score=0.2, write=False)
        self.assertEqual((result["sensor"], result["source"]), ("sandbox-cowrie-1", "unspecified"))

    def test_a_record_without_a_sensor_gets_an_empty_one(self):
        self.with_source(None)
        self.assertEqual(self.run_session(self.pipeline())["sensor"], "")

    def test_the_source_comes_from_the_environment(self):
        for tag in ("internet", "injected", "lab-2", "demo_1", "a.b"):
            with self.subTest(tag=tag):
                self.with_source(tag)
                self.assertEqual(self.run_session(self.pipeline())["source"], tag)

    def test_a_source_with_odd_characters_stops_the_pipeline_instead_of_being_stored(self):
        for bad in ("in ternet", "x" * 41, "a/b", 'a"b', "naïve", "a;b"):
            with self.subTest(tag=bad):
                self.with_source(bad)
                with self.assertRaises(ValueError) as ctx:
                    self.pipeline()
                self.assertIn("PIPELINE_SOURCE", str(ctx.exception))

    def test_the_sensor_name_is_read_from_the_real_cowrie_log(self):
        self.with_source("internet")
        logs = self.tmp / "cowrie"
        logs.mkdir()
        events = [{"eventid": "cowrie.session.connect", "src_ip": PUBLIC_IP, "src_port": 40000, "dst_port": 2222,
                   "session": "abc123", "protocol": "ssh", "sensor": "sandbox-cowrie-1", "timestamp": "2026-11-02T08:00:00.000000Z"},
                  {"eventid": "cowrie.session.closed", "duration_ms": 900, "session": "abc123",
                   "sensor": "sandbox-cowrie-1", "timestamp": "2026-11-02T08:00:01.000000Z"}]
        (logs / "cowrie.json").write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
        p = self.pipeline()
        p.cowrie_log_dir = logs
        p.from_start = True
        results = p.scan_once()
        self.assertEqual([(r["session_id"], r["sensor"], r["source"]) for r in results], [("abc123", "sandbox-cowrie-1", "internet")])
        line = json.loads((self.tmp / "results.jsonl").read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual((line["sensor"], line["source"]), ("sandbox-cowrie-1", "internet"))

    def test_a_log_without_sensor_names_falls_back_to_the_source_name(self):
        """Changed at the Phase-1/mitigation merge, deliberately.

        This asserted "" before. With multiple honeypots an empty sensor loses the
        attribution entirely, so the fallback is now the LogSource's own name -- a
        session from a honeypot whose log omits `sensor` is still traceable to that
        honeypot. Cowrie itself always writes the field (cowrie.cfg sensor_name),
        so this path only fires on a misconfigured or minimal log.
        """
        logs = self.tmp / "cowrie"
        logs.mkdir()
        events = [{"eventid": "cowrie.session.connect", "src_ip": PUBLIC_IP, "session": "x1", "timestamp": "2026-11-02T08:00:00.000000Z"},
                  {"eventid": "cowrie.session.closed", "session": "x1", "timestamp": "2026-11-02T08:00:01.000000Z"}]
        (logs / "cowrie.json").write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
        p = self.pipeline()
        p.cowrie_log_dir = logs
        p._sources = [psp.cowrie_source(logs)]
        self.assertEqual([r["sensor"] for r in p.scan_once()], ["cowrie"])


if __name__ == "__main__":
    unittest.main()


class TestUntrustedSourceIsNotMitigated(TestAutoBlacklist):
    """The merge precondition: the mitigation engine inherits the MT3 trust gate.

    The engine's job is "given a verdict, decide and act safely". Deciding whether
    the verdict is worth believing at all is upstream of it. Without this gate,
    merging the mitigation layer would have undone HONEYPOT_AUDIT.md PART 7: a
    Heralding bare connect scores DISC_NETSTAT_SCAN at confidence 1.000 (phase 3),
    clearing every threshold the engine checks, so it would blacklist a user for
    opening a TCP connection.
    """

    def test_untrusted_source_is_skipped_not_blacklisted(self):
        p = self.pipeline(phase=3, confidence=0.99)
        record = {"session_id": "h1", "src_ip": PUBLIC_IP, "t_start": 1_700_000_000.0,
                  "source": "heralding", "command_text": "admin:hunter2",
                  "login_attempts": 3, "micro_state_sequence": "", "protocol": "http",
                  "dst_port": 80}
        result = p.process_session(record, write=False)
        self.assertIs(result["mt3_trusted"], False)
        self.assertIs(result["auto_blacklisted"], False)
        self.assertEqual([m["action"] for m in result["mitigation"]], ["skipped"])
        self.assertEqual(self.manager.calls, [],
                         "the mitigation layer must not touch the blacklist for "
                         "a source MT3 is not trusted on")

    def test_trusted_source_still_reaches_the_engine(self):
        result = self.run_session(self.pipeline(phase=3, confidence=0.9))
        self.assertIs(result["mt3_trusted"], True)
        self.assertNotEqual([m["action"] for m in result["mitigation"]], ["skipped"])
