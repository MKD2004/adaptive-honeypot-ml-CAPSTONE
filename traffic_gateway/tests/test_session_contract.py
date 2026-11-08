"""
traffic_gateway/tests/test_session_contract.py

The guard that stops the next honeypot integration becoming pipeline surgery
(MULTI_HONEYPOT.md Phase 1).

Three things are locked down here:

  1. PARITY. cowrie_parser.build_record() called with no keywords must still
     emit dst_port=22 / protocol="ssh". Those are not read from the events, and
     changing them would shift feature 39 (dst_port_norm) ~100x against a value
     MT3 only ever saw as a constant. See the docstring on build_record.

  2. THE CONTRACT. Every parser's output must satisfy session_contract, and the
     contract must actually be capable of failing -- hence the negative controls.

  3. MULTI-PROTOCOL RESOLUTION. feature_bridge.honeypot_target_for() must return
     something other than SSH_HONEYPOT when a parser says so. Before Phase 1 this
     could not pass: the hardcoded 22/"ssh" made the whole _PORT_TO_HONEYPOT
     table dead code.

No network I/O and no model loading -- honeypot_target_for() is pure lookup.
"""
import sys
import os
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Redirect persistence before importing anything that touches disk, same as
# test_router.py does.
_tmp = tempfile.mkdtemp()
import traffic_gateway.config as _cfg_mod
_cfg_mod.CONFIG.DATA_DIR = Path(_tmp) / "data"
_cfg_mod.CONFIG.LOG_DIR = Path(_tmp) / "logs"
_cfg_mod.CONFIG.DATA_DIR.mkdir(parents=True, exist_ok=True)
_cfg_mod.CONFIG.LOG_DIR.mkdir(parents=True, exist_ok=True)

# The parsers live under honeypot_dataset/src, which is not a package root.
sys.path.insert(0, str(REPO_ROOT / "honeypot_dataset"))

from src.parsers.cowrie_parser import build_record            # noqa: E402
from src.parsers.session_contract import (                    # noqa: E402
    OPTIONAL_FIELDS, REQUIRED_FIELDS, assert_valid, validate,
)
from traffic_gateway.feature_bridge import honeypot_target_for  # noqa: E402


def _events(session="abc123def456", src_ip="203.0.113.9"):
    """A minimal but realistic closed Cowrie session: connect, login, cmd, close."""
    return [
        {"eventid": "cowrie.session.connect", "session": session, "src_ip": src_ip,
         "src_port": 51234, "dst_ip": "10.0.0.1", "dst_port": 2222,
         "timestamp": "2026-11-04T10:00:00.000000Z", "protocol": "ssh"},
        {"eventid": "cowrie.login.success", "session": session, "src_ip": src_ip,
         "username": "root", "password": "x",
         "timestamp": "2026-11-04T10:00:01.000000Z"},
        {"eventid": "cowrie.command.input", "session": session, "src_ip": src_ip,
         "input": "uname -a", "timestamp": "2026-11-04T10:00:02.000000Z"},
        {"eventid": "cowrie.session.closed", "session": session, "src_ip": src_ip,
         "timestamp": "2026-11-04T10:00:03.000000Z"},
    ]


class TestParity(unittest.TestCase):
    """build_record()'s defaults are load-bearing. Do not let them drift."""

    def test_defaults_are_ssh_port_22(self):
        rec = build_record(_events())
        self.assertEqual(rec["dst_port"], 22,
                         "default dst_port must stay 22 -- notebook 01 parity and "
                         "MT3's trained dst_port_norm depend on it")
        self.assertEqual(rec["protocol"], "ssh")

    def test_defaults_ignore_the_port_in_the_events(self):
        # The events say 2222. build_record has always flattened that to 22, and
        # every Cowrie session in the training set went through that flattening.
        rec = build_record(_events())
        self.assertEqual(rec["dst_port"], 22)

    def test_record_is_stable_across_calls(self):
        self.assertEqual(build_record(_events()), build_record(_events()))


class TestContract(unittest.TestCase):

    def test_cowrie_output_conforms(self):
        assert_valid(build_record(_events()), where="cowrie_parser.build_record()")

    def test_contract_covers_what_build_record_emits(self):
        rec = build_record(_events())
        self.assertEqual(set(rec), set(REQUIRED_FIELDS),
                         "build_record's keys and REQUIRED_FIELDS have diverged")

    def test_optional_fields_are_genuinely_optional(self):
        rec = build_record(_events())
        for key in OPTIONAL_FIELDS:
            self.assertNotIn(key, rec)
        self.assertEqual(validate(rec), [])

    def test_optional_fields_are_type_checked_when_present(self):
        rec = build_record(_events())
        rec["ja3_hash"] = 12345                      # should be str
        self.assertTrue(any("ja3_hash" in p for p in validate(rec)))

    # -- negative controls: a check that cannot fail is not a check -----------

    def test_missing_required_key_is_caught(self):
        rec = build_record(_events())
        del rec["protocol"]
        self.assertIn("missing required key: protocol", validate(rec))

    def test_wrong_type_is_caught(self):
        rec = build_record(_events())
        rec["dst_port"] = "22"
        self.assertTrue(any("dst_port" in p for p in validate(rec)))

    def test_none_value_is_caught(self):
        rec = build_record(_events())
        rec["command_text"] = None
        self.assertIn("command_text is None", validate(rec))

    def test_empty_protocol_is_caught(self):
        rec = build_record(_events())
        rec["protocol"] = "   "
        self.assertTrue(any("protocol is empty" in p for p in validate(rec)))

    def test_out_of_range_port_is_caught(self):
        rec = build_record(_events())
        rec["dst_port"] = 99999
        self.assertTrue(any("out of range" in p for p in validate(rec)))

    def test_nan_is_caught(self):
        rec = build_record(_events())
        rec["session_duration_s"] = float("nan")
        self.assertTrue(any("NaN" in p for p in validate(rec)))

    def test_bool_is_not_accepted_as_int(self):
        rec = build_record(_events())
        rec["n_events"] = True
        self.assertTrue(any("n_events" in p for p in validate(rec)))

    def test_assert_valid_raises_with_every_problem_listed(self):
        rec = build_record(_events())
        del rec["protocol"]
        rec["dst_port"] = "nope"
        with self.assertRaises(ValueError) as ctx:
            assert_valid(rec)
        msg = str(ctx.exception)
        self.assertIn("protocol", msg)
        self.assertIn("dst_port", msg)


class TestMultiProtocolResolution(unittest.TestCase):
    """The payoff. None of these could pass before Phase 1."""

    def test_ssh_still_resolves_to_ssh(self):
        self.assertEqual(honeypot_target_for(build_record(_events())), "SSH_HONEYPOT")

    def test_http_resolves_to_web(self):
        rec = build_record(_events(), protocol="http", dst_port=8080)
        self.assertEqual(honeypot_target_for(rec), "WEB_HONEYPOT")

    def test_https_resolves_to_web(self):
        rec = build_record(_events(), protocol="https", dst_port=443)
        self.assertEqual(honeypot_target_for(rec), "WEB_HONEYPOT")

    def test_mysql_resolves_to_db(self):
        rec = build_record(_events(), protocol="mysql", dst_port=3306)
        self.assertEqual(honeypot_target_for(rec), "DB_HONEYPOT")

    def test_postgres_resolves_to_db(self):
        rec = build_record(_events(), protocol="postgres", dst_port=5432)
        self.assertEqual(honeypot_target_for(rec), "DB_HONEYPOT")

    def test_port_decides_when_protocol_is_unrecognised(self):
        # _PROTO_TO_HONEYPOT misses, so _PORT_TO_HONEYPOT must carry it.
        rec = build_record(_events(), protocol="tcp", dst_port=3306)
        self.assertEqual(honeypot_target_for(rec), "DB_HONEYPOT")

    def test_overridden_records_still_conform(self):
        for proto, port in (("http", 8080), ("https", 443), ("mysql", 3306)):
            with self.subTest(protocol=proto):
                assert_valid(build_record(_events(), protocol=proto, dst_port=port))


class TestProvenanceTag(unittest.TestCase):
    """PIPELINE_SOURCE, ported from 4a6ed19. Keeps real captures, injected demo
    traffic and lab runs from ever being pooled into one statistic."""

    def setUp(self):
        from traffic_gateway import post_session_pipeline as psp
        self.psp = psp
        self._saved = os.environ.get("PIPELINE_SOURCE")

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("PIPELINE_SOURCE", None)
        else:
            os.environ["PIPELINE_SOURCE"] = self._saved

    def test_unset_is_unspecified(self):
        os.environ.pop("PIPELINE_SOURCE", None)
        self.assertEqual(self.psp._source_tag(), "unspecified")

    def test_blank_is_unspecified(self):
        os.environ["PIPELINE_SOURCE"] = "   "
        self.assertEqual(self.psp._source_tag(), "unspecified")

    def test_accepts_the_tags_we_actually_use(self):
        for tag in ("internet", "injected", "lab", "demo", "vps-1", "cowrie.ssh_01"):
            with self.subTest(tag=tag):
                os.environ["PIPELINE_SOURCE"] = tag
                self.assertEqual(self.psp._source_tag(), tag)

    def test_rejects_junk_rather_than_storing_it(self):
        for bad in ("has space", "semi;colon", "quote\"", "x" * 41, "nl\nline"):
            with self.subTest(bad=bad):
                os.environ["PIPELINE_SOURCE"] = bad
                with self.assertRaises(ValueError):
                    self.psp._source_tag()

    def test_sensor_is_an_optional_contract_field(self):
        # The pipeline sets `sensor` on the record; the contract must know about
        # it, or a strict validate() would reject a perfectly good record.
        self.assertIn("sensor", OPTIONAL_FIELDS)
        rec = build_record(_events())
        rec["sensor"] = "cowrie-honeypot"
        self.assertEqual(validate(rec, allow_extra=False), [])

    def test_sensor_must_be_a_string(self):
        rec = build_record(_events())
        rec["sensor"] = 99
        self.assertTrue(any("sensor" in p for p in validate(rec)))


class TestMultiSource(unittest.TestCase):
    """The pipeline tails N honeypot logs, not one hardcoded Cowrie directory."""

    def setUp(self):
        import functools
        import json
        import shutil
        from traffic_gateway.post_session_pipeline import (
            LogSource, PostSessionPipeline, cowrie_source,
        )
        self.LogSource = LogSource
        self.PostSessionPipeline = PostSessionPipeline
        self.cowrie_source = cowrie_source
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

        # a second honeypot's log, Cowrie-ish shape but its own close event
        self.hdir = self.tmp / "heralding"
        self.hdir.mkdir()
        self.sess = "aa11bb22cc33"
        self.evs = [
            {"eventid": "auth.attempt", "session": self.sess, "src_ip": "198.51.100.7",
             "src_port": 5555, "timestamp": "2026-11-04T12:00:00.000000Z",
             "sensor": "heralding-01"},
            {"eventid": "session.end", "session": self.sess, "src_ip": "198.51.100.7",
             "timestamp": "2026-11-04T12:00:02.000000Z"},
        ]
        (self.hdir / "heralding.json").write_text(
            "\n".join(json.dumps(e) for e in self.evs) + "\n", encoding="utf-8")
        self.web = LogSource(
            name="heralding", log_dir=self.hdir, glob="heralding.json*",
            session_key="session",
            is_closed=lambda ev: ev.get("eventid") == "session.end",
            build=functools.partial(build_record, protocol="http", dst_port=8080),
        )

    def _pipe(self, **kw):
        return self.PostSessionPipeline(results_path=self.tmp / "r.jsonl", **kw)

    def test_default_is_exactly_one_cowrie_source(self):
        pipe = self._pipe()
        self.assertEqual([s.name for s in pipe._sources], ["cowrie"])

    def test_default_honours_cowrie_log_dir_argument(self):
        pipe = self.PostSessionPipeline(cowrie_log_dir=self.hdir,
                                        results_path=self.tmp / "r.jsonl")
        self.assertEqual(pipe._sources[0].log_dir, self.hdir)

    def test_extra_source_is_tailed(self):
        pipe = self._pipe(sources=[self.cowrie_source(), self.web])
        self.assertEqual([s.name for s in pipe._sources], ["cowrie", "heralding"])
        self.assertEqual(len(pipe._log_files(self.web)), 1)

    def test_log_files_across_all_sources(self):
        pipe = self._pipe(sources=[self.web])
        self.assertEqual(len(pipe._log_files()), len(pipe._log_files(self.web)))

    def test_tail_keys_do_not_collide_on_same_filename(self):
        # two honeypots can both write "x.json" in different folders
        other = self.tmp / "other"
        other.mkdir()
        (other / "heralding.json").write_text("", encoding="utf-8")
        a = self.web
        b = self.LogSource(name="second", log_dir=other, glob="heralding.json*",
                           session_key="session", is_closed=a.is_closed, build=a.build)
        pipe = self._pipe(sources=[a, b])
        keys = {pipe._tail_key(s, p) for s in (a, b) for p in pipe._log_files(s)}
        self.assertEqual(len(keys), 2, "per-source tail keys must stay distinct")

    def test_source_build_sets_protocol_and_port(self):
        rec = self.web.build(self.evs)
        self.assertEqual((rec["protocol"], rec["dst_port"]), ("http", 8080))
        self.assertEqual(honeypot_target_for(rec), "WEB_HONEYPOT")
        assert_valid(rec, where="heralding source")

    def test_stats_and_startup_report_sources(self):
        pipe = self._pipe(sources=[self.cowrie_source(), self.web])
        self.assertEqual(pipe.stats()["sources"], ["cowrie", "heralding"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
