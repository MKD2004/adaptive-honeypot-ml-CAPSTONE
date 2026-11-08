"""
traffic_gateway/tests/test_heralding_parser.py

Heralding -> session contract. MULTI_HONEYPOT.md Phase 2.

Written against the schema in Heralding's own source
(`heralding/misc/session.py`, `Session.get_session_info`), NOT against a live
Heralding instance -- Docker was unavailable when this was written, so the
fixtures below reproduce the documented field names, the naive-UTC timestamp
format and the interim/final `session_ended` pair. They are faithful to the
source but UNVERIFIED against real output; a first real capture should be
diffed against `_session()` before trusting the labels.

The timezone test is the one that matters most. Heralding writes
`datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')` with no offset, and
`datetime.fromisoformat` accepts that string while treating it as LOCAL time.
Reusing cowrie_parser.to_ts() would therefore shift every session by the
machine's UTC offset, and peer_attribution matches the gateway log BY CONNECT
TIME, so attribution would fail silently.
"""
import json
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

from src.parsers import heralding_parser as hp                      # noqa: E402
from src.parsers.session_contract import assert_valid, validate     # noqa: E402
from traffic_gateway.feature_bridge import honeypot_target_for      # noqa: E402


def _session(protocol="http", port=80, attempts=(), duration=12,
             ended=True, sid="7f3a0000-1111-2222-3333-444455556666",
             ts="2026-11-04 10:00:00.123456", sensor="heralding-01"):
    """One `log_session.json` record, shaped as Session.get_session_info() writes it."""
    return {
        "timestamp": ts,
        "duration": duration,
        "session_id": sid,
        "source_ip": "198.51.100.7",
        "source_port": 51515,
        "destination_ip": "10.1.4.147",
        "destination_port": port,
        "protocol": protocol,
        "num_auth_attempts": len(attempts),
        "auth_attempts": [
            {"timestamp": f"2026-11-04 10:00:{i + 1:02d}.000000",
             "username": u, "password": p}
            for i, (u, p) in enumerate(attempts)
        ],
        "session_ended": ended,
        "auxiliary_data": {},
        "sensor": sensor,
    }


class TestTimezone(unittest.TestCase):
    """The bug this parser exists to avoid."""

    def test_naive_utc_is_read_as_utc(self):
        import datetime as dt
        rec = hp.build_record([_session(ts="2026-11-04 10:00:00.000000")])
        got = dt.datetime.fromtimestamp(rec["t_start"], dt.timezone.utc)
        self.assertEqual(got.strftime("%Y-%m-%d %H:%M:%S"), "2026-11-04 10:00:00")

    def test_does_not_agree_with_the_naive_cowrie_parse_unless_utc_local(self):
        # cowrie_parser.to_ts would read the same string as local time. On a
        # machine at UTC+0 the two agree; anywhere else they must not.
        import datetime as dt
        from src.parsers.cowrie_parser import to_ts
        s = "2026-11-04 10:00:00.000000"
        offset = dt.datetime.now().astimezone().utcoffset() or dt.timedelta(0)
        if offset.total_seconds() == 0:
            self.skipTest("machine is at UTC+0; the two parses coincide")
        self.assertNotEqual(hp._utc_ts(s), to_ts(s))

    def test_unparseable_timestamp_is_zero_not_a_crash(self):
        self.assertEqual(hp._utc_ts("not a date"), 0.0)
        self.assertEqual(hp._utc_ts(""), 0.0)
        self.assertEqual(hp._utc_ts(None), 0.0)

    def test_second_precision_timestamp_also_parses(self):
        self.assertGreater(hp._utc_ts("2026-11-04 10:00:00"), 0.0)

    def test_duration_sets_t_end(self):
        rec = hp.build_record([_session(duration=37)])
        self.assertAlmostEqual(rec["t_end"] - rec["t_start"], 37.0, places=3)
        self.assertAlmostEqual(rec["session_duration_s"], 37.0, places=3)


class TestContract(unittest.TestCase):

    def test_every_scenario_conforms(self):
        scenarios = {
            "bare connect": [],
            "user enum": [("admin", ""), ("root", ""), ("test", "")],
            "stuffing": [("alice", "Summer2026"), ("bob", "Summer2026"),
                         ("carol", "Summer2026"), ("dave", "Summer2026")],
            "defaults": [("admin", "admin")],
            "brute force": [("admin", "hunter2"), ("admin", "letmein")],
        }
        for name, attempts in scenarios.items():
            with self.subTest(scenario=name):
                assert_valid(hp.build_record([_session(attempts=attempts)]),
                             where=f"heralding/{name}")

    def test_empty_input_returns_none(self):
        self.assertIsNone(hp.build_record([]))
        self.assertIsNone(hp.build_record(None))

    def test_missing_session_id_returns_none(self):
        bad = _session()
        del bad["session_id"]
        self.assertIsNone(hp.build_record([bad]))

    def test_non_dict_entries_are_ignored(self):
        self.assertIsNone(hp.build_record(["nonsense", 42]))

    def test_last_record_wins(self):
        # the interim record has fewer attempts than the final one
        interim = _session(attempts=[("admin", "x")], ended=False)
        final = _session(attempts=[("admin", "x"), ("admin", "y"), ("admin", "z")])
        rec = hp.build_record([interim, final])
        self.assertEqual(rec["login_attempts"], 3)

    def test_no_shell_means_no_commands(self):
        rec = hp.build_record([_session(attempts=[("a", "b")])])
        self.assertEqual(rec["n_commands"], 0)
        self.assertEqual(rec["n_downloads"], 0)

    def test_source_is_heralding(self):
        self.assertEqual(hp.build_record([_session()])["source"], "heralding")

    def test_sensor_from_log_then_fallback(self):
        self.assertEqual(hp.build_record([_session(sensor="box-7")])["sensor"], "box-7")
        s = _session()
        del s["sensor"]
        self.assertEqual(hp.build_record([s])["sensor"], "heralding")

    def test_garbage_port_is_repaired_not_passed_through(self):
        rec = hp.build_record([_session(protocol="http", port=0)])
        self.assertEqual(validate(rec), [], "a 0 port would violate the contract")
        self.assertEqual(rec["dst_port"], 80)


class TestLabelling(unittest.TestCase):
    """Heuristic labels, for MT3-vs-rule agreement (MULTI_HONEYPOT.md 7.6).
    Agreement with these is NOT accuracy."""

    def test_no_auth_is_recon(self):
        self.assertEqual(hp.label_session(_session(attempts=[])), "RECON_IP_SCAN")

    def test_usernames_without_passwords_is_user_enum(self):
        self.assertEqual(
            hp.label_session(_session(attempts=[("admin", ""), ("root", ""), ("x", "")])),
            "RECON_USER_ENUM")

    def test_one_password_many_users_is_stuffing(self):
        self.assertEqual(
            hp.label_session(_session(attempts=[("a", "P@ss"), ("b", "P@ss"),
                                                ("c", "P@ss"), ("d", "P@ss")])),
            "ACCESS_CRED_STUFF")

    def test_factory_default_pair_wins_over_brute_force(self):
        self.assertEqual(
            hp.label_session(_session(attempts=[("admin", "admin")])),
            "ACCESS_DEFAULT_CRED")

    def test_http_brute_force(self):
        self.assertEqual(
            hp.label_session(_session(protocol="http",
                                      attempts=[("admin", "hunter2"), ("admin", "qwerty")])),
            "ACCESS_BRUTE_HTTP")

    def test_ssh_brute_force_uses_the_ssh_class(self):
        self.assertEqual(
            hp.label_session(_session(protocol="ssh", port=22,
                                      attempts=[("root", "9x!Qa"), ("root", "zzTop1")])),
            "ACCESS_BRUTE_SSH")

    def test_unknown_protocol_falls_back(self):
        self.assertEqual(
            hp.label_session(_session(protocol="gopher",
                                      attempts=[("a", "sdfgh"), ("a", "jklmn")])),
            "ACCESS_BRUTE_HTTP")

    def test_every_label_is_a_real_micro_state(self):
        from configs.schema import MICRO_STATES  # type: ignore
        names = {m["label"] for m in MICRO_STATES}
        produced = {hp.label_session(_session(protocol=p, attempts=a))
                    for p in ("http", "https", "ssh", "ftp", "telnet", "vnc", "smtp",
                              "imap", "pop3", "socks5", "mysql", "gopher")
                    for a in ([], [("admin", "")], [("admin", "admin")],
                              [("a", "P"), ("b", "P"), ("c", "P"), ("d", "P")],
                              [("admin", "hunter2")])}
        self.assertTrue(produced <= names,
                        f"not in the 45-class taxonomy: {produced - names}")


class TestTaxonomyGap(unittest.TestCase):
    """MULTI_HONEYPOT.md 7.1 -- no database-auth micro-state exists."""

    def test_database_protocol_warns_loudly(self):
        with self.assertLogs("heralding_parser", level="WARNING") as cm:
            hp.label_session(_session(protocol="mysql", port=3306,
                                      attempts=[("app", "s3cr3t")]))
        self.assertTrue(any("taxonomy" in m for m in cm.output))

    def test_database_still_produces_a_valid_record(self):
        rec = hp.build_record([_session(protocol="mysql", port=3306,
                                        attempts=[("app", "s3cr3t")])])
        assert_valid(rec, where="heralding/mysql")


class TestPayloadChoice(unittest.TestCase):
    """What lands in command_text. Group D is zero-filled for non-SSH either way
    (Phase 1b); this only affects Group C's payload statistics."""

    def test_credentials_become_the_payload_by_default(self):
        rec = hp.build_record([_session(attempts=[("admin", "hunter2"), ("root", "toor")])])
        self.assertEqual(rec["command_text"], "admin:hunter2 ; root:toor")

    def test_opt_out_matches_cowries_empty_case(self):
        rec = hp.build_record([_session(attempts=[("admin", "hunter2")])],
                              credentials_as_payload=False)
        self.assertEqual(rec["command_text"], "[no commands]")

    def test_no_attempts_is_always_the_empty_marker(self):
        self.assertEqual(hp.build_record([_session(attempts=[])])["command_text"],
                         "[no commands]")


class TestRouting(unittest.TestCase):
    """The point of Phase 1: these records reach the right honeypot target."""

    def test_http_routes_to_web(self):
        rec = hp.build_record([_session(protocol="http", port=80)])
        self.assertEqual(honeypot_target_for(rec), "WEB_HONEYPOT")

    def test_https_routes_to_web(self):
        rec = hp.build_record([_session(protocol="https", port=443)])
        self.assertEqual(honeypot_target_for(rec), "WEB_HONEYPOT")

    def test_ssh_routes_to_ssh(self):
        rec = hp.build_record([_session(protocol="ssh", port=22)])
        self.assertEqual(honeypot_target_for(rec), "SSH_HONEYPOT")

    def test_override_beats_the_log(self):
        rec = hp.build_record([_session(protocol="http", port=80)],
                              protocol="mysql", dst_port=3306)
        self.assertEqual((rec["protocol"], rec["dst_port"]), ("mysql", 3306))
        self.assertEqual(honeypot_target_for(rec), "DB_HONEYPOT")


class TestLogSourceWiring(unittest.TestCase):

    def setUp(self):
        import shutil
        from traffic_gateway.post_session_pipeline import (
            PostSessionPipeline, cowrie_source, heralding_source,
        )
        self.PostSessionPipeline = PostSessionPipeline
        self.cowrie_source = cowrie_source
        self.heralding_source = heralding_source
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.hdir = self.tmp / "hlogs"
        self.hdir.mkdir()
        (self.hdir / "log_session.json").write_text(
            json.dumps(_session(attempts=[("admin", "x")], ended=False)) + "\n"
            + json.dumps(_session(attempts=[("admin", "x"), ("admin", "y")])) + "\n",
            encoding="utf-8")

    def test_factory_builds_a_usable_source(self):
        src = self.heralding_source(self.hdir)
        self.assertEqual(src.name, "heralding")
        self.assertEqual(src.session_key, "session_id")
        self.assertEqual(src.glob, hp.HERALDING_SESSION_GLOB)

    def test_pipeline_finds_the_log(self):
        src = self.heralding_source(self.hdir)
        pipe = self.PostSessionPipeline(results_path=self.tmp / "r.jsonl",
                                        sources=[self.cowrie_source(), src])
        self.assertEqual([s.name for s in pipe._sources], ["cowrie", "heralding"])
        self.assertEqual(len(pipe._log_files(src)), 1)

    def test_interim_records_are_not_treated_as_closed(self):
        src = self.heralding_source(self.hdir)
        lines = (self.hdir / "log_session.json").read_text(encoding="utf-8").splitlines()
        events = [json.loads(l) for l in lines if l.strip()]
        self.assertEqual(sum(1 for e in events if src.is_closed(e)), 1)

    def test_build_through_the_source_conforms_and_routes(self):
        src = self.heralding_source(self.hdir)
        lines = (self.hdir / "log_session.json").read_text(encoding="utf-8").splitlines()
        rec = src.build([json.loads(l) for l in lines if l.strip()])
        assert_valid(rec, where="heralding_source.build")
        self.assertEqual(rec["login_attempts"], 2)
        self.assertEqual(honeypot_target_for(rec), "WEB_HONEYPOT")

    def test_payload_opt_out_flows_through_the_factory(self):
        src = self.heralding_source(self.hdir, credentials_as_payload=False)
        lines = (self.hdir / "log_session.json").read_text(encoding="utf-8").splitlines()
        rec = src.build([json.loads(l) for l in lines if l.strip()])
        self.assertEqual(rec["command_text"], "[no commands]")


if __name__ == "__main__":
    unittest.main(verbosity=2)
