"""
honeypot_dataset/tests/test_cowrie_simulator.py

Guards `src/generators/cowrie_simulator.py` -- the generator that emits COWRIE
LOG EVENTS and runs them through the real parser, rather than writing
feature-adjacent scalars directly (DATA_INTEGRITY.md section 4, Part 1).

WHAT THESE TESTS ARE FOR. Part 1 exists to make two classes of defect
structurally impossible rather than merely unlikely:

  1. A derived feature contradicting its own definition. 39% of the frozen
     TabSyn rows have `log_session_duration != log1p(session_duration_s)` and
     23% have `iat_mean > iat_max`, because both sides of each identity were
     GENERATED. Here they are COMPUTED from an event stream, so the identity
     holds by construction -- and `test_derived_quantities_are_computed_not_drawn`
     is what proves the stream is actually the source.

  2. A quantity with no real counterpart. The frozen synthetic rows carry
     `login_attempts` up to 552 and a lognormal `bytes_out`, against a real
     capture whose maximum is 1 and whose `bytes_out` is always 0. Those are
     guarded by name below, because they are the specific skews that put real
     sessions 226x outside the training distribution.

CALIBRATION TARGETS are the 13-day real capture (114,490 sessions, 754,063
events). The bands here are deliberately loose -- they catch a generator that
has broken or drifted structurally, not one that moved by a few percent. The
tight comparison is the stratified table in the module docstring, which is
re-measured against `cowrie_logs/` rather than asserted here, because that
capture is gitignored and not present on every machine.
"""
import math
import sys
import unittest
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "honeypot_dataset"))

from configs.schema import IDX_TO_PHASE, LABEL_TO_IDX, MICRO_STATES  # noqa: E402
from src.generators import cowrie_simulator as cs                    # noqa: E402
from src.parsers.cowrie_parser import build_record                   # noqa: E402
from src.parsers.session_contract import validate as contract_validate  # noqa: E402

ALL_LABELS = [s["label"] for s in MICRO_STATES]

# A session's events, parsed, for every one of the 45 classes.
_CORPUS = None


def corpus():
    """`(intended_label, events, record)` triples -- built once, reused."""
    global _CORPUS
    if _CORPUS is None:
        rows = []
        for label, _seq, events in cs.generate_sessions(0, seed=1234, per_class=40):
            rec = build_record(list(events))
            if rec is not None:
                rows.append((label, events, rec))
        _CORPUS = rows
    return _CORPUS


class TestEventStreamIsRealCowrie(unittest.TestCase):
    """The events must be what the real honeypot writes, not an approximation."""

    def test_the_real_parser_accepts_every_generated_session(self):
        """`build_record` must return a record for all 45 classes.

        This is the whole premise of Part 1: synthetic and real sessions travel
        the same path. If the parser rejects a generated session, they do not.
        """
        seen = set()
        for label, _events, rec in corpus():
            self.assertIsNotNone(rec)
            seen.add(label)
        self.assertEqual(seen, set(ALL_LABELS),
                         "some micro-state produced no parseable session")

    def test_records_satisfy_the_session_contract(self):
        """Parsed records must match `session_contract`, like live traffic."""
        for _label, _events, rec in corpus()[:500]:
            problems = contract_validate(rec)
            self.assertEqual(problems, [], f"contract violation: {problems}")

    def test_every_session_starts_connecting_and_ends_closed(self):
        """All 114,490 real sessions open with `connect`; all close with `closed`."""
        for _label, events, _rec in corpus():
            self.assertEqual(events[0]["eventid"], "cowrie.session.connect")
            self.assertEqual(events[-1]["eventid"], "cowrie.session.closed")

    def test_timestamps_are_ascending_and_iso_with_z(self):
        """Cowrie writes `2026-11-01T17:19:45.416701Z`; the parser splits on it."""
        for _label, events, _rec in corpus()[:500]:
            stamps = [e["timestamp"] for e in events]
            self.assertEqual(stamps, sorted(stamps))
            for s in stamps:
                self.assertTrue(s.endswith("Z"), s)
                self.assertIn("T", s)

    def test_every_event_carries_the_fields_the_parser_reads(self):
        for _label, events, _rec in corpus()[:500]:
            for e in events:
                for key in ("session", "eventid", "timestamp", "src_ip",
                            "src_port", "dst_port", "protocol", "sensor"):
                    self.assertIn(key, e, f"{e.get('eventid')} missing {key}")

    def test_commands_only_appear_after_a_successful_login(self):
        """Cowrie cannot log a command for an unauthenticated connection.

        Every one of the 52,843 real command-issuing sessions carries a
        `login.success`, so a generated session that issues commands without one
        is a shape the honeypot can never produce.
        """
        for _label, events, _rec in corpus():
            ids = [e["eventid"] for e in events]
            if "cowrie.command.input" in ids:
                self.assertIn("cowrie.login.success", ids)
                self.assertLess(ids.index("cowrie.login.success"),
                                ids.index("cowrie.command.input"))

    def test_params_and_log_closed_are_paired(self):
        """Real: `session.params` and `log.closed` both number 53,466 exactly."""
        for _label, events, _rec in corpus():
            ids = [e["eventid"] for e in events]
            self.assertEqual(ids.count("cowrie.session.params"),
                             ids.count("cowrie.log.closed"))

    def test_only_log_closed_carries_a_size_field(self):
        """`bytes_in` IS the ttylog size -- `build_record` sums every `size`.

        In the real capture `cowrie.log.closed` is the ONLY event type with a
        `size` field (53,466 of 754,063 events). Any other event carrying one
        would silently inflate `bytes_in` for synthetic rows only.
        """
        for _label, events, _rec in corpus():
            for e in events:
                if "size" in e:
                    self.assertEqual(e["eventid"], "cowrie.log.closed")

    def test_dst_port_is_2222_in_events_and_22_in_the_record(self):
        """Faithful to the log, flattened by the parser -- exactly like real data.

        Real events all carry 2222; `build_record` has always flattened that to
        22, so MT3 has only ever seen 22/65535 in feature 39. Emitting 22 in the
        events would be unfaithful; letting 2222 reach the record would shift
        that feature ~100x. See `cowrie_parser.build_record`'s docstring.
        """
        for _label, events, rec in corpus()[:200]:
            self.assertEqual(events[0]["dst_port"], 2222)
            self.assertEqual(rec["dst_port"], 22)


class TestDerivedQuantitiesAreComputed(unittest.TestCase):
    """Finding two cannot recur for this source. These tests say why."""

    def test_derived_quantities_are_computed_not_drawn(self):
        """n_events, n_commands, duration and bytes_in must match the events.

        This is the structural fix. If any of these can be set independently of
        the event stream, the generator is back to asserting values that the
        stream contradicts -- which is how `iat_mean > iat_max` happened.
        """
        for _label, events, rec in corpus():
            ids = [e["eventid"] for e in events]
            self.assertEqual(rec["n_events"], len(events))
            self.assertEqual(rec["n_commands"], ids.count("cowrie.command.input"))
            self.assertEqual(rec["login_attempts"],
                             ids.count("cowrie.login.success")
                             + ids.count("cowrie.login.failed"))
            self.assertEqual(rec["bytes_in"],
                             sum(e.get("size", 0) for e in events if "size" in e))
            self.assertAlmostEqual(
                rec["session_duration_s"], rec["t_end"] - rec["t_start"], places=6)

    def test_event_timestamps_agree_with_t_start_and_t_end(self):
        for _label, _events, rec in corpus():
            ts = rec["event_timestamps"]
            self.assertEqual(len(ts), rec["n_events"])
            self.assertAlmostEqual(ts[0], rec["t_start"], places=6)
            self.assertAlmostEqual(ts[-1], rec["t_end"], places=6)
            self.assertEqual(ts, sorted(ts))

    def test_log1p_identity_holds_on_every_row(self):
        """The identity TabSyn broke on 39% of rows, here true by construction."""
        for _label, _events, rec in corpus():
            d = rec["session_duration_s"]
            self.assertAlmostEqual(math.log1p(d), math.log1p(max(d, 0.0)), places=9)
            self.assertGreaterEqual(d, 0.0)

    def test_inter_arrival_summary_cannot_contradict_itself(self):
        """`iat_min <= iat_mean <= iat_max`, and spread implies cv > 0.

        23% of the frozen TabSyn rows violate the first and 36% the second.
        Computed from a real gap series, neither can happen.
        """
        import statistics as st
        for _label, _events, rec in corpus():
            ts = rec["event_timestamps"]
            if len(ts) < 3:
                continue
            gaps = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
            lo, mean, hi = min(gaps), sum(gaps) / len(gaps), max(gaps)
            self.assertLessEqual(lo, mean + 1e-9)
            self.assertLessEqual(mean, hi + 1e-9)
            if hi - lo > 1e-6:
                self.assertGreater(st.pstdev(gaps) / max(mean, 1e-12), 0.0,
                                   "varying gaps reported zero coefficient of variation")

    def test_milestones_are_members_of_the_event_series(self):
        """`t_first_auth`/`t_first_cmd` must BE events, not independent offsets."""
        for _label, _events, rec in corpus():
            ts = set(round(t, 6) for t in rec["event_timestamps"])
            self.assertIn(round(rec["t_first_auth"], 6), ts)
            self.assertIn(round(rec["t_first_cmd"], 6), ts)


class TestCalibratedToTheRealCapture(unittest.TestCase):
    """The specific skews that put real sessions 226x outside training."""

    def test_login_attempts_never_exceeds_one(self):
        """Real SSH brute force is ONE attempt per TCP connection.

        Measured maximum across 114,490 real sessions: 1. The frozen synthetic
        split reaches 552, because the old generator drew
        `lognormal(mean=3.5)` for brute-force labels. A bot reconnects; it does
        not retry inside a session.
        """
        worst = max(rec["login_attempts"] for _l, _e, rec in corpus())
        self.assertLessEqual(worst, 1, "a session retried authentication")

    def test_bytes_out_is_always_zero(self):
        """Cowrie emits no outbound byte count, so the parser hard-codes 0.

        The frozen generator drew it from a lognormal -- a feature alive in
        training and dead at inference.
        """
        for _label, _events, rec in corpus():
            self.assertEqual(rec["bytes_out"], 0)

    def test_associated_cve_is_always_empty(self):
        """E_threat_intel stays DROPped -- DATA_INTEGRITY.md 3c.

        `associated_cve` is empty in 100% of real sessions. Populating it only
        in synthetic data would train MT3 to lean on a 14-feature block that is
        all-zero at inference, which is worse than a dead feature.
        """
        for _label, _events, rec in corpus():
            self.assertEqual(rec["associated_cve"], "")

    def test_n_events_stays_within_the_real_range(self):
        """Real: p50 5, max 41. The old generator's lognormal reached 1,139."""
        counts = [rec["n_events"] for _l, _e, rec in corpus()]
        self.assertGreaterEqual(min(counts), 2)
        self.assertLessEqual(max(counts), 80,
                             "generated a session far longer than any real one")

    def test_one_command_sessions_report_the_real_ttylog_size(self):
        """88.4% of real single-command TTY blocks are exactly 86 bytes.

        This is the sharpest available check that `bytes_in` comes from the
        measured distribution rather than a convenient parametric one.
        """
        sizes = Counter(rec["bytes_in"] for _l, _e, rec in corpus()
                        if rec["n_commands"] == 1)
        self.assertTrue(sizes, "no single-command sessions were generated")
        self.assertEqual(sizes.most_common(1)[0][0], 86)

    def test_no_command_sessions_have_zero_bytes_in(self):
        """No shell means no transcript. Real: bytes_in p50 and p90 both 0."""
        for _label, _events, rec in corpus():
            if rec["n_commands"] == 0:
                self.assertEqual(rec["bytes_in"], 0)

    def test_commands_arrive_at_machine_speed(self):
        """98.1% of real `command.input` gaps are sub-100 ms -- scripted bots.

        This one guards against a plausible-looking regression: pacing commands
        seconds apart "because a human types" inverts the real structure and
        kills the burst features it is meant to feed.
        """
        fast = total = 0
        for _label, events, _rec in corpus():
            from src.parsers.cowrie_parser import to_ts
            for i in range(len(events) - 1):
                if events[i + 1]["eventid"] != "cowrie.command.input":
                    continue
                gap = to_ts(events[i + 1]["timestamp"]) - to_ts(events[i]["timestamp"])
                total += 1
                fast += gap < 0.1
        self.assertGreater(total, 0)
        self.assertGreater(fast / total, 0.60,
                           "command gaps are far slower than the real capture")

    def test_long_pauses_are_concentrated_in_deep_and_unauthenticated_sessions(self):
        """Real rate ranges 0.24% to 37.3% across neighbouring session types.

        Pooling it hides the idle timeout entirely -- the trap
        DATA_INTEGRITY.md section 7 records. A generator that spreads long
        pauses evenly passes a pooled check and still has the structure wrong.
        """
        from src.parsers.cowrie_parser import to_ts
        shallow = deep = shallow_paused = deep_paused = 0
        for _label, events, rec in corpus():
            ts = [to_ts(e["timestamp"]) for e in events]
            if len(ts) < 2:
                continue
            paused = any(ts[i + 1] - ts[i] > 30.0 for i in range(len(ts) - 1))
            if rec["login_attempts"] > 0 and 1 <= rec["n_commands"] <= 4:
                shallow += 1
                shallow_paused += paused
            elif rec["login_attempts"] > 0 and rec["n_commands"] >= 5:
                deep += 1
                deep_paused += paused
        self.assertGreater(shallow, 50)
        self.assertGreater(deep, 50)
        self.assertLess(shallow_paused / shallow, 0.05,
                        "shallow sessions pause far more than the real 0.24%")
        self.assertGreater(deep_paused / deep, 0.15,
                           "deep sessions pause far less than the real 37.3%")

    def test_recon_sessions_mostly_do_not_authenticate(self):
        """No-login sessions and RECON sessions are the same 7.8% of real data.

        8,889 real sessions carry no login event; the parser labels 8,898
        RECON_IP_SCAN. A recon session is one that never got as far as a
        password.
        """
        phase0 = [rec for label, _e, rec in corpus()
                  if IDX_TO_PHASE[LABEL_TO_IDX[label]] == 0]
        self.assertGreater(len(phase0), 100)
        no_login = sum(1 for rec in phase0 if rec["login_attempts"] == 0)
        self.assertGreater(no_login / len(phase0), 0.7,
                           "most reconnaissance sessions should never authenticate")
        # And they must not reach a shell at all: a recon session that issues
        # commands has escalated past reconnaissance, which is what the
        # start-anchored walk used to produce for 57.5% of phase-0 rows.
        with_cmds = sum(1 for rec in phase0 if rec["n_commands"] > 0)
        self.assertEqual(with_cmds, 0,
                         "a reconnaissance-labelled session issued shell commands")


class TestLabelHonesty(unittest.TestCase):
    """The label gap must be recorded, never hidden. See the module docstring."""

    def test_both_labels_are_recorded_on_every_row(self):
        df = cs.generate_balanced_sessions(0, seed=7, per_class=5)
        for col in ("micro_state", "parser_micro_state", "parser_sequence",
                    "label_agrees", "label_source"):
            self.assertIn(col, df.columns)
        self.assertTrue((df["label_source"] == "generator").all())

    def test_micro_state_keeps_the_intended_label(self):
        """`micro_state` is the training target and must stay the intended class.

        `feature_bridge`, `post_session_pipeline` and the dashboard all read
        that field name, so it keeps its meaning; the parser's answer goes in
        `parser_micro_state` alongside.
        """
        df = cs.generate_balanced_sessions(0, seed=7, per_class=5)
        self.assertEqual(set(df["micro_state"]), set(ALL_LABELS))

    def test_agreement_is_reported_rather_than_assumed(self):
        """`agreement_report` must cover every class, including the 0% ones.

        27 of the 45 classes are unreachable by `cowrie_parser` BY CONSTRUCTION
        -- it can only emit 18 labels. A silent 0% is the failure mode this
        guards: the number has to be visible to be stated in the paper.
        """
        df = cs.generate_balanced_sessions(0, seed=7, per_class=5)
        rep = cs.agreement_report(df)
        self.assertEqual(len(rep), len(ALL_LABELS))
        self.assertIn("agree", rep.columns)
        self.assertIn("parser_says", rep.columns)
        # The gap is real and large; if this ever passes 95% the labeller has
        # been widened and the module docstring needs rewriting.
        self.assertLess(df["label_agrees"].mean(), 0.95)

    def test_commands_come_from_every_state_in_the_walk(self):
        """`command_text` must describe the same session as the state sequence.

        `sim_commands.add_command_text` keys only off the single `micro_state`
        label, so a frozen row whose sequence held five states carried commands
        from one of them. Here each state contributes its own.
        """
        rng_labels = ["PERSIST_CRONTAB", "EXFIL_STAGING_TAR", "PRIVESC_SUDO_ABUSE"]
        found_multi = False
        for label, seq, events in cs.generate_sessions(0, seed=99, labels=rng_labels,
                                                       per_class=10):
            rec = build_record(list(events))
            if rec is None or rec["n_commands"] < 2:
                continue
            post_auth = [s for s in seq if not s.startswith(("RECON_", "ACCESS_"))]
            if len(post_auth) >= 2:
                found_multi = True
                break
        self.assertTrue(found_multi,
                        "no multi-state session issued commands from its walk")


class TestRepeatVisitors(unittest.TestCase):
    def test_seen_before_is_set_from_src_ip_in_corpus_order(self):
        """`build_record` does not emit `seen_before`, so it must be added back.

        `tls_host` reads it for `attacker_repeat_visitor`. The fix lives in
        `mark_repeat_visitors` rather than the generator because it works
        identically on real records -- the real path must call it too, or the
        feature is alive in training and dead at inference.
        """
        recs = [{"src_ip": "192.0.2.1"}, {"src_ip": "192.0.2.2"},
                {"src_ip": "192.0.2.1"}]
        cs.mark_repeat_visitors(recs)
        self.assertEqual([r["seen_before"] for r in recs], [False, False, True])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestProvenanceCannotBeLost(unittest.TestCase):
    """A generated log must never read back as real honeypot traffic.

    `build_record` hard-codes `source: "cowrie_real"`. This project has already
    spent months describing 15,000 teammate-generated Cowrie sessions as real
    (CLAUDE.md's provenance note, DECISIONS.md), so a generator that writes logs
    indistinguishable from the real capture has to ship the way to tell them
    apart.
    """

    def test_written_log_round_trips_through_the_real_parser(self):
        import tempfile
        from src.parsers.cowrie_parser import parse_closed_sessions

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cowrie.json"
            counts = cs.write_jsonlines(path, 0, seed=5, per_class=2)
            self.assertEqual(sum(counts.values()), 90)
            # The live-pipeline path must recognise every session as closed.
            self.assertEqual(len(parse_closed_sessions(path)), 90)

    def test_parse_generated_log_stamps_the_synthetic_source(self):
        import tempfile
        from src.parsers.cowrie_parser import parse_closed_sessions

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cowrie.json"
            cs.write_jsonlines(path, 0, seed=5, per_class=2)
            # The naive read mislabels it -- this is the hazard, asserted so the
            # reason `parse_generated_log` exists stays visible.
            naive = parse_closed_sessions(path)
            self.assertTrue(all(r["source"] == "cowrie_real" for r in naive))
            # The correct read does not.
            recs = cs.parse_generated_log(path)
            self.assertTrue(all(r["source"] == cs.SYNTHETIC_SOURCE for r in recs))
            self.assertTrue(all("seen_before" in r for r in recs))

    def test_events_carry_a_synthetic_sensor_id(self):
        """The second, independent marker: never the real capture's sensor."""
        for _label, events, _rec in corpus()[:200]:
            for e in events:
                self.assertEqual(e["sensor"], "synthetic-cowrie-01")
                self.assertNotEqual(e["sensor"], "7b0b4b6a20d0")

    def test_a_log_mixing_real_sessions_is_refused(self):
        """Stamping a mixed file as synthetic would launder real data, or vice
        versa. Better to raise than to guess."""
        import json as _json
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cowrie.json"
            cs.write_jsonlines(path, 0, seed=5, per_class=1)
            with path.open("a", encoding="utf-8") as fh:
                for eid in ("cowrie.session.connect", "cowrie.session.closed"):
                    fh.write(_json.dumps({
                        "session": "realone", "eventid": eid,
                        "timestamp": "2026-11-01T17:19:45.416701Z",
                        "src_ip": "203.0.113.9", "src_port": 40000,
                        "dst_ip": "172.18.0.2", "dst_port": 2222,
                        "protocol": "ssh", "sensor": "7b0b4b6a20d0",
                    }) + "\n")
            with self.assertRaises(ValueError):
                cs.parse_generated_log(path)
