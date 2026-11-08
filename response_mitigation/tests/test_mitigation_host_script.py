"""
response_mitigation/tests/test_mitigation_host_script.py

The script that runs as root on the Linux host (host/apply_blocklist.py).
It has to be strict, because the file it reads is written by a less-trusted
process. These tests run on any OS: nft is replaced by a recording stand-in.

REAL_TABLE_JSON and REAL_SET_JSON below are the exact output of `nft -j` from
nftables 1.0.9 on Ubuntu 24.04 (WSL2), captured 2026-11-01.
"""
import ipaddress
import json
import os
import tempfile
import unittest
from pathlib import Path

from response_mitigation.host import apply_blocklist as hb

NOW = 1_800_000_000
PUBLIC = "45.33.32.156"
PUBLIC_V6 = "2606:4700:4700::1111"

REAL_TABLE_JSON = (
    '{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}}, '
    '{"table": {"family": "inet", "name": "honeypot_guard", "handle": 1}}, '
    '{"set": {"family": "inet", "name": "blocked_v4", "table": "honeypot_guard", "type": "ipv4_addr", "handle": 2, "flags": ["timeout"]}}, '
    '{"set": {"family": "inet", "name": "blocked_v6", "table": "honeypot_guard", "type": "ipv6_addr", "handle": 3, "flags": ["timeout"]}}, '
    '{"chain": {"family": "inet", "table": "honeypot_guard", "name": "pre", "handle": 1, "type": "filter", "hook": "prerouting", "prio": -300, "policy": "accept"}}, '
    '{"rule": {"family": "inet", "table": "honeypot_guard", "chain": "pre", "handle": 4, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@blocked_v4"}}, {"drop": null}]}}, '
    '{"rule": {"family": "inet", "table": "honeypot_guard", "chain": "pre", "handle": 5, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}}, "right": "@blocked_v6"}}, {"drop": null}]}}]}'
)
REAL_SET_JSON = (
    '{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}}, '
    '{"set": {"family": "inet", "name": "blocked_v4", "table": "honeypot_guard", "type": "ipv4_addr", "handle": 2, "flags": ["timeout"], '
    '"elem": [{"elem": {"val": "8.8.4.4", "timeout": 90, "expires": 89}}, {"elem": {"val": "45.33.32.156", "timeout": 3600, "expires": 3599}}]}}]}'
)
REAL_EMPTY_SET_JSON = (
    '{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}}, '
    '{"set": {"family": "inet", "name": "blocked_v6", "table": "honeypot_guard", "type": "ipv6_addr", "handle": 2, "flags": ["timeout"]}}]}'
)


def blocklist_bytes(*entries, **extra):
    doc = {"version": 1, "updated_at": NOW, "entries": list(entries)}
    doc.update(extra)
    return json.dumps(doc).encode()


def entry(ip=PUBLIC, expires=NOW + 3600, **extra):
    return {"ip": ip, "added_at": NOW, "expires_at": expires, "reason": "t", "rule": "r",
            "session_id": "s", **extra}


class TestWhichAddressesMayBeBlocked(unittest.TestCase):

    def test_public_addresses_are_accepted(self):
        for text in (PUBLIC, "172.217.14.206", "8.8.8.8", PUBLIC_V6, " 45.33.32.156 "):
            with self.subTest(text=text):
                self.assertEqual(hb.public_address(text), ipaddress.ip_address(text.strip()))

    def test_everything_that_is_not_public_unicast_is_refused(self):
        for text in ("127.0.0.1", "10.1.2.3", "192.168.0.9", "172.16.0.1", "172.17.0.1", "172.31.255.255",
                     "169.254.1.1", "100.64.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1",
                     "239.255.255.250", "240.0.0.1", "203.0.113.5", "198.51.100.7",
                     "::1", "::", "fe80::1", "fc00::1", "ff02::1", "2001:db8::1",
                     "::ffff:10.0.0.1", "::ffff:127.0.0.1"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                hb.public_address(text)

    def test_ipv4_mapped_ipv6_is_unwrapped_to_the_ipv4_address(self):
        self.assertEqual(hb.public_address("::ffff:45.33.32.156"), ipaddress.ip_address(PUBLIC))

    def test_text_that_is_not_one_ip_is_refused(self):
        for value in ("", "not-an-ip", "1.2.3.4; reset", "1.2.3.4 }", "1.2.3.4/32", "1.2.3.4,5.6.7.8",
                      "8.8.8.8\nflush ruleset", "fe80::1%eth0", "2606:4700:4700::1111%eth0",
                      None, 4, b"8.8.8.8", ["8.8.8.8"]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                hb.public_address(value)


class TestCommandText(unittest.TestCase):

    def test_exact_text(self):
        self.assertEqual(hb.add_element_command(PUBLIC, 86400),
                         "add element inet honeypot_guard blocked_v4 { 45.33.32.156 timeout 86400s }")
        self.assertEqual(hb.add_element_command(PUBLIC_V6, 600),
                         "add element inet honeypot_guard blocked_v6 { 2606:4700:4700::1111 timeout 600s }")
        self.assertEqual(hb.delete_element_command(PUBLIC),
                         "delete element inet honeypot_guard blocked_v4 { 45.33.32.156 }")
        self.assertEqual(hb.delete_element_command(PUBLIC_V6),
                         "delete element inet honeypot_guard blocked_v6 { 2606:4700:4700::1111 }")

    def test_the_text_comes_from_the_parsed_address_not_the_input(self):
        self.assertIn("{ 45.33.32.156 timeout", hb.add_element_command("  45.33.32.156  ", 60))
        self.assertIn("{ 45.33.32.156 timeout", hb.add_element_command("::ffff:45.33.32.156", 60))

    def test_nothing_unsafe_can_get_into_a_command(self):
        for bad in ("1.2.3.4 } ; flush ruleset ; { 5.6.7.8", "8.8.8.8\nflush ruleset", "10.0.0.1"):
            with self.subTest(ip=bad), self.assertRaises(ValueError):
                hb.add_element_command(bad, 60)

    def test_timeouts_must_be_whole_seconds_in_range(self):
        for bad in (0, -5, 1.5, "60", None, True, hb.MAX_TTL_S + 1):
            with self.subTest(timeout=bad), self.assertRaises(ValueError):
                hb.add_element_command(PUBLIC, bad)
        hb.add_element_command(PUBLIC, 1)
        hb.add_element_command(PUBLIC, hb.MAX_TTL_S)

    def test_the_ruleset_names_match_the_command_text(self):
        for name in (hb.TABLE, hb.SET_V4, hb.SET_V6):
            self.assertIn(name, hb.RULESET)
        self.assertIn("hook prerouting priority raw", hb.RULESET)
        self.assertEqual(hb.HOOK_PRIORITY, -300)    # what "raw" means; the health check relies on it


class TestParsingTheBlockList(unittest.TestCase):

    def parse(self, *entries, **kwargs):
        return hb.parse_entries(blocklist_bytes(*entries), now=NOW, **kwargs)

    def test_valid_entries_are_kept(self):
        got = self.parse(entry(PUBLIC, NOW + 100), entry(PUBLIC_V6, NOW + 200))
        self.assertEqual(got.desired, {PUBLIC: NOW + 100, PUBLIC_V6: NOW + 200})
        self.assertEqual(got.rejected, [])

    def test_unsafe_entries_are_skipped_with_a_reason_and_the_rest_still_load(self):
        got = self.parse(entry("10.0.0.5"), entry("8.8.8.8; rm -rf /"), entry(PUBLIC))
        self.assertEqual(list(got.desired), [PUBLIC])
        self.assertEqual([why for _, why in got.rejected],
                         ["not a public unicast address", "not an IP address"])

    def test_expired_entries_are_dropped_quietly(self):
        got = self.parse(entry(PUBLIC, NOW), entry("8.8.8.8", NOW - 5), entry("1.1.1.1", NOW + 1))
        self.assertEqual(list(got.desired), ["1.1.1.1"])
        self.assertEqual(got.expired, 2)
        self.assertEqual(got.rejected, [])

    def test_an_expiry_far_in_the_future_is_refused(self):
        got = self.parse(entry(PUBLIC, NOW + hb.MAX_TTL_S + 10), entry("8.8.8.8", NOW + hb.MAX_TTL_S))
        self.assertEqual(list(got.desired), ["8.8.8.8"])
        self.assertEqual(got.rejected[0][1], "expiry is too far away")

    def test_a_bad_expiry_is_refused(self):
        for value in ("tomorrow", None, True, [1], {"a": 1}):
            with self.subTest(expires_at=value):
                got = self.parse(entry(PUBLIC, value))
                self.assertEqual(got.desired, {})
                self.assertEqual(got.rejected[0][1], "expires_at is not a number")

    def test_nan_and_infinity_are_refused(self):
        # json.loads accepts these words even though JSON does not allow them.
        for word in ("NaN", "Infinity", "-Infinity"):
            raw = ('{"version":1,"entries":[{"ip":"45.33.32.156","expires_at":%s}]}' % word).encode()
            with self.subTest(word=word):
                got = hb.parse_entries(raw, now=NOW)
                self.assertEqual(got.desired, {})
                self.assertEqual(len(got.rejected), 1)

    def test_never_block_list_and_own_addresses_win_over_the_file(self):
        never = [ipaddress.ip_network("45.33.32.0/24"), ipaddress.ip_network("2606:4700::/32")]
        own = [ipaddress.ip_address("8.8.8.8")]
        got = self.parse(entry(PUBLIC), entry(PUBLIC_V6), entry("8.8.8.8"), entry("1.1.1.1"),
                         never_block=never, local_addresses=own)
        self.assertEqual(list(got.desired), ["1.1.1.1"])
        self.assertEqual([why for _, why in got.rejected],
                         ["on the never-block list", "on the never-block list", "this host's own address"])

    def test_the_same_ip_twice_keeps_the_later_expiry(self):
        got = self.parse(entry(PUBLIC, NOW + 100), entry(PUBLIC, NOW + 900), entry("::ffff:45.33.32.156", NOW + 500))
        self.assertEqual(got.desired, {PUBLIC: NOW + 900})

    def test_entries_that_are_not_objects_are_skipped(self):
        raw = json.dumps({"version": 1, "entries": ["8.8.8.8", 7, None, entry(PUBLIC)]}).encode()
        got = hb.parse_entries(raw, now=NOW)
        self.assertEqual(list(got.desired), [PUBLIC])
        self.assertEqual(len(got.rejected), 3)

    def test_a_whole_file_that_cannot_be_trusted_is_refused(self):
        too_many = blocklist_bytes(*[entry(PUBLIC)] * (hb.MAX_ENTRIES + 1))
        for label, raw in (("not json", b"{nope"), ("not utf-8", b"\xff\xfe\x00"), ("empty", b""),
                           ("a list", b"[]"), ("no entries", b'{"version":1}'),
                           ("entries not a list", b'{"entries":"8.8.8.8"}'), ("too many", too_many)):
            with self.subTest(label), self.assertRaises(hb.Refused):
                hb.parse_entries(raw, now=NOW)

    def test_what_the_file_said_is_shortened_and_made_printable_before_it_is_shown(self):
        got = self.parse(entry("A" * 500 + "\n\x1b[31mred"))
        shown = got.rejected[0][0]
        self.assertLessEqual(len(shown), 60)
        self.assertTrue(shown.isprintable())


class TestReadingTheFile(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def test_reads_a_normal_file(self):
        path = self.dir / "b.json"
        path.write_bytes(b"{}")
        self.assertEqual(hb.read_file(str(path)), b"{}")

    def test_missing_file_is_reported_as_missing(self):
        with self.assertRaises(FileNotFoundError):
            hb.read_file(str(self.dir / "nope.json"))

    def test_a_file_over_the_size_limit_is_refused(self):
        path = self.dir / "big.json"
        path.write_bytes(b" " * (hb.MAX_FILE_BYTES + 1))
        with self.assertRaises(hb.Refused):
            hb.read_file(str(path))

    def test_a_directory_is_refused(self):
        with self.assertRaises(hb.Refused):
            hb.read_file(str(self.dir))

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "symlink check needs POSIX")
    def test_a_symlink_is_refused(self):
        target = self.dir / "real.json"
        target.write_bytes(b"{}")
        link = self.dir / "link.json"
        os.symlink(target, link)
        with self.assertRaises(hb.Refused):
            hb.read_file(str(link))


class TestReadingTheFirewallsAnswer(unittest.TestCase):

    def test_real_set_listing(self):
        self.assertEqual(hb.parse_set_listing(REAL_SET_JSON), {"8.8.4.4": 89, PUBLIC: 3599})

    def test_an_empty_set_has_no_elem_key(self):
        self.assertEqual(hb.parse_set_listing(REAL_EMPTY_SET_JSON), {})

    def test_plain_string_elements_are_understood(self):
        doc = {"nftables": [{"set": {"name": "blocked_v4", "elem": ["8.8.8.8", {"val": "1.1.1.1", "expires": 5}]}}]}
        self.assertEqual(hb.parse_set_listing(json.dumps(doc)), {"8.8.8.8": hb.MAX_TTL_S, "1.1.1.1": 5})

    def test_things_that_are_not_single_addresses_are_ignored(self):
        doc = {"nftables": [{"set": {"elem": [{"elem": {"val": {"prefix": {"addr": "10.0.0.0", "len": 8}}}},
                                              {"elem": {"val": "not-an-ip"}}, 5, None]}}]}
        self.assertEqual(hb.parse_set_listing(json.dumps(doc)), {})

    def test_unreadable_answers_are_refused(self):
        for text in ("", "oops", "[]", '{"nftables": 3}', '{}'):
            with self.subTest(text=text), self.assertRaises(hb.Refused):
                hb.parse_set_listing(text)


class TestWorkingOutTheChanges(unittest.TestCase):

    def test_adds_removes_and_keeps(self):
        add, remove = hb.plan_changes({PUBLIC: NOW + 100, "8.8.8.8": NOW + 50, "1.1.1.1": NOW + 7},
                                      {PUBLIC: 99, "9.9.9.9": 10}, NOW)
        self.assertEqual(add, [("1.1.1.1", 7), ("8.8.8.8", 50)])
        self.assertEqual(remove, ["9.9.9.9"])

    def test_an_entry_already_in_the_firewall_is_left_alone(self):
        # nft does not lengthen the timeout of an element that is already there.
        self.assertEqual(hb.plan_changes({PUBLIC: NOW + 9999}, {PUBLIC: 5}, NOW), ([], []))

    def test_the_timeout_is_whole_seconds_rounded_up_and_never_below_one(self):
        add, _ = hb.plan_changes({PUBLIC: NOW + 0.2}, {}, NOW)
        self.assertEqual(add, [(PUBLIC, 1)])
        add, _ = hb.plan_changes({PUBLIC: int(NOW + 90)}, {}, NOW + 0.5)
        self.assertEqual(add, [(PUBLIC, 90)])

    def test_nothing_wanted_and_nothing_there(self):
        self.assertEqual(hb.plan_changes({}, {}, NOW), ([], []))


class TestIsTheFirewallTableStillRight(unittest.TestCase):

    def doc(self):
        return json.loads(REAL_TABLE_JSON)

    def healthy(self, doc):
        return hb.table_is_healthy(json.dumps(doc))

    def test_the_table_we_load_is_recognised(self):
        self.assertTrue(hb.table_is_healthy(REAL_TABLE_JSON))

    def test_each_kind_of_drift_is_caught(self):
        def drop_rule(doc, family):
            doc["nftables"] = [i for i in doc["nftables"]
                               if not (("rule" in i) and i["rule"]["expr"][0]["match"]["left"]["payload"]["protocol"] == family)]

        def edit_chain(doc, **kw):
            for i in doc["nftables"]:
                if "chain" in i:
                    i["chain"].update(kw)

        def accept_instead(doc):
            for i in doc["nftables"]:
                if "rule" in i:
                    i["rule"]["expr"][-1] = {"accept": None}

        def daddr(doc):
            for i in doc["nftables"]:
                if "rule" in i:
                    i["rule"]["expr"][0]["match"]["left"]["payload"]["field"] = "daddr"

        def drop_set(doc):
            doc["nftables"] = [i for i in doc["nftables"] if not (i.get("set", {}).get("name") == "blocked_v6")]

        cases = {
            "no ipv4 rule": lambda d: drop_rule(d, "ip"),
            "no ipv6 rule": lambda d: drop_rule(d, "ip6"),
            "later hook priority": lambda d: edit_chain(d, prio=0),
            "different hook": lambda d: edit_chain(d, hook="input"),
            "rules accept instead of drop": accept_instead,
            "matches destination, not source": daddr,
            "a set is missing": drop_set,
        }
        for label, mutate in cases.items():
            doc = self.doc()
            mutate(doc)
            with self.subTest(label):
                self.assertFalse(self.healthy(doc))

    def test_rubbish_is_not_healthy(self):
        for text in ("", "nope", "[]", '{"nftables": "x"}', "{}"):
            with self.subTest(text=text):
                self.assertFalse(hb.table_is_healthy(text))


class FakeNft:
    """Stands in for nft and ip. Records every call; answers from a small script."""

    def __init__(self, *, table=REAL_TABLE_JSON, table_exists=True, sets=None, batch_ok=True,
                 bad_lines=(), local=(), nft_missing=False, load_ok=True):
        self.table, self.table_exists, self.batch_ok = table, table_exists, batch_ok
        self.sets = sets or {"blocked_v4": REAL_EMPTY_SET_JSON, "blocked_v6": REAL_EMPTY_SET_JSON}
        self.bad_lines, self.local, self.nft_missing, self.load_ok = set(bad_lines), local, nft_missing, load_ok
        self.writes = []                      # text sent to `nft -f -`

    def __call__(self, argv, stdin=None):
        if argv[0] == "ip":
            addrs = [{"addr_info": [{"local": a}]} for a in self.local]
            return hb.Result(0, json.dumps(addrs), "")
        if self.nft_missing:
            return hb.Result(127, "", "FileNotFoundError: nft")
        if argv[:5] == ["nft", "-j", "list", "table", "inet"]:
            return hb.Result(0, self.table, "") if self.table_exists else hb.Result(1, "", "No such file")
        if argv[:4] == ["nft", "-j", "list", "set"]:
            return hb.Result(0, self.sets[argv[-1]], "")
        if argv == ["nft", "-f", "-"]:
            self.writes.append(stdin)
            if "table inet honeypot_guard {" in stdin:
                return hb.Result(0 if self.load_ok else 1, "", "" if self.load_ok else "Operation not permitted")
            lines = stdin.strip().splitlines()
            if len(lines) > 1 and not self.batch_ok:
                return hb.Result(1, "", "batch failed")
            if any(line in self.bad_lines for line in lines):
                return hb.Result(1, "", "No such file or directory")
            return hb.Result(0, "", "")
        raise AssertionError(f"unexpected command {argv}")


class TestReconcile(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.path = self.dir / "blocklist.json"
        self.kill = self.dir / "KILL"

    def write(self, *entries):
        self.path.write_bytes(blocklist_bytes(*entries))

    def run_it(self, fake, **kwargs):
        # The output goes to stdout; keep the test run quiet and look at it only on failure.
        import contextlib, io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = hb.reconcile(blocklist=str(self.path), kill_file=str(self.kill), runner=fake,
                                now=NOW, **kwargs)
        self.output = out.getvalue()
        return code

    def test_new_entries_are_added_in_one_transaction(self):
        self.write(entry(PUBLIC, NOW + 600), entry(PUBLIC_V6, NOW + 60))
        fake = FakeNft()
        self.assertEqual(self.run_it(fake), 0, self.output)
        self.assertEqual(len(fake.writes), 1)
        self.assertEqual(sorted(fake.writes[0].strip().splitlines()), [
            "add element inet honeypot_guard blocked_v4 { 45.33.32.156 timeout 600s }",
            "add element inet honeypot_guard blocked_v6 { 2606:4700:4700::1111 timeout 60s }"])

    def test_nothing_to_change_means_nothing_is_written(self):
        self.write(entry(PUBLIC, NOW + 600), entry("8.8.4.4", NOW + 600))
        fake = FakeNft(sets={"blocked_v4": REAL_SET_JSON, "blocked_v6": REAL_EMPTY_SET_JSON})
        self.assertEqual(self.run_it(fake), 0, self.output)
        self.assertEqual(fake.writes, [])
        self.assertIn("add 0, remove 0, keep 2", self.output)

    def test_an_entry_only_in_the_firewall_is_removed_and_the_rest_is_kept(self):
        self.write(entry(PUBLIC, NOW + 600))
        fake = FakeNft(sets={"blocked_v4": REAL_SET_JSON, "blocked_v6": REAL_EMPTY_SET_JSON})
        self.assertEqual(self.run_it(fake), 0, self.output)
        self.assertEqual(fake.writes, ["delete element inet honeypot_guard blocked_v4 { 8.8.4.4 }\n"])

    def test_a_missing_table_is_created_before_anything_is_added(self):
        self.write(entry(PUBLIC, NOW + 600))
        fake = FakeNft(table_exists=False)
        self.assertEqual(self.run_it(fake), 0, self.output)
        self.assertEqual(fake.writes[0], hb.RULESET)
        self.assertEqual(fake.writes[1].strip(),
                         "add element inet honeypot_guard blocked_v4 { 45.33.32.156 timeout 600s }")

    def test_a_drifted_table_is_deleted_and_rebuilt_in_one_go(self):
        self.write(entry(PUBLIC, NOW + 600))
        doc = json.loads(REAL_TABLE_JSON)
        doc["nftables"] = [i for i in doc["nftables"] if "rule" not in i]       # the drop rules vanished
        fake = FakeNft(table=json.dumps(doc))
        self.assertEqual(self.run_it(fake), 0, self.output)
        self.assertEqual(fake.writes[0], "delete table inet honeypot_guard\n" + hb.RULESET)
        self.assertEqual(len(fake.writes), 2)

    def test_expired_and_removed_entries_come_out(self):
        self.write(entry(PUBLIC, NOW - 1))
        fake = FakeNft(sets={"blocked_v4": REAL_SET_JSON, "blocked_v6": REAL_EMPTY_SET_JSON})
        self.assertEqual(self.run_it(fake), 0, self.output)
        self.assertEqual(sorted(fake.writes[0].strip().splitlines()), [
            "delete element inet honeypot_guard blocked_v4 { 45.33.32.156 }",
            "delete element inet honeypot_guard blocked_v4 { 8.8.4.4 }"])

    def test_kill_switch_removes_everything_and_adds_nothing(self):
        self.write(entry(PUBLIC, NOW + 600), entry("1.1.1.1", NOW + 600))
        self.kill.write_text("")
        fake = FakeNft(sets={"blocked_v4": REAL_SET_JSON, "blocked_v6": REAL_EMPTY_SET_JSON})
        self.assertEqual(self.run_it(fake), 0, self.output)
        self.assertIn("kill switch", self.output)
        self.assertEqual(sorted(fake.writes[0].strip().splitlines()), [
            "delete element inet honeypot_guard blocked_v4 { 45.33.32.156 }",
            "delete element inet honeypot_guard blocked_v4 { 8.8.4.4 }"])

    def test_kill_switch_works_even_when_the_block_list_is_broken(self):
        self.path.write_bytes(b"{nope")
        self.kill.write_text("")
        fake = FakeNft(sets={"blocked_v4": REAL_SET_JSON, "blocked_v6": REAL_EMPTY_SET_JSON})
        self.assertEqual(self.run_it(fake), 0, self.output)
        self.assertEqual(len(fake.writes[0].strip().splitlines()), 2)

    def test_dry_run_changes_nothing(self):
        self.write(entry(PUBLIC, NOW + 600))
        fake = FakeNft(table_exists=False, sets={"blocked_v4": REAL_SET_JSON, "blocked_v6": REAL_EMPTY_SET_JSON})
        self.assertEqual(self.run_it(fake, dry_run=True), 0, self.output)
        self.assertEqual(fake.writes, [])
        self.assertIn("dry run", self.output)
        self.assertIn("would run: nft add element", self.output)

    def test_a_broken_block_list_is_refused_and_the_firewall_is_not_touched(self):
        for raw in (b"{nope", blocklist_bytes(*[entry(PUBLIC)] * (hb.MAX_ENTRIES + 1))):
            self.path.write_bytes(raw)
            fake = FakeNft()
            with self.subTest(raw=raw[:12]):
                self.assertEqual(self.run_it(fake), 2, self.output)
                self.assertEqual(fake.writes, [])

    def test_no_block_list_yet_means_nothing_is_blocked(self):
        fake = FakeNft(sets={"blocked_v4": REAL_SET_JSON, "blocked_v6": REAL_EMPTY_SET_JSON})
        self.assertEqual(self.run_it(fake), 0, self.output)
        self.assertEqual(len(fake.writes[0].strip().splitlines()), 2)       # everything stale is removed

    def test_never_block_and_own_addresses_are_honoured(self):
        self.write(entry(PUBLIC, NOW + 600), entry("8.8.8.8", NOW + 600), entry("1.1.1.1", NOW + 600))
        fake = FakeNft(local=["8.8.8.8"])
        code = self.run_it(fake, never_block=[ipaddress.ip_network(PUBLIC + "/32")])
        self.assertEqual(code, 0, self.output)
        self.assertEqual(fake.writes[0].strip(),
                         "add element inet honeypot_guard blocked_v4 { 1.1.1.1 timeout 600s }")

    def test_if_one_line_fails_the_good_ones_still_land(self):
        # e.g. an element that expired between listing and deleting
        self.write(entry(PUBLIC, NOW + 600), entry("1.1.1.1", NOW + 600))
        bad = "add element inet honeypot_guard blocked_v4 { 1.1.1.1 timeout 600s }"
        fake = FakeNft(batch_ok=False, bad_lines=[bad])
        self.assertEqual(self.run_it(fake), 1, self.output)
        singles = [w.strip() for w in fake.writes[1:]]
        self.assertEqual(sorted(singles), sorted([
            "add element inet honeypot_guard blocked_v4 { 45.33.32.156 timeout 600s }", bad]))
        self.assertIn("nft refused", self.output)

    def test_nft_not_installed(self):
        self.write(entry(PUBLIC, NOW + 600))
        self.assertEqual(self.run_it(FakeNft(nft_missing=True)), 3, self.output)

    def test_ruleset_that_cannot_be_loaded(self):
        self.write(entry(PUBLIC, NOW + 600))
        fake = FakeNft(table_exists=False, load_ok=False)
        self.assertEqual(self.run_it(fake), 3, self.output)
        self.assertEqual(len(fake.writes), 1)       # never went on to add anything


class TestKillSwitchCheck(unittest.TestCase):

    def test_no_path_means_no_kill_switch(self):
        self.assertFalse(hb.kill_switch_on(None))
        self.assertFalse(hb.kill_switch_on(""))

    def test_a_missing_file_is_off_and_an_existing_file_is_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "KILL"
            self.assertFalse(hb.kill_switch_on(str(path)))
            path.write_text("")
            self.assertTrue(hb.kill_switch_on(str(path)))

    def test_if_we_cannot_tell_the_answer_is_on(self):
        # Removing blocks is the safe failure. os.path.exists() would have said "no" here.
        from unittest.mock import patch
        for error in (PermissionError("denied"), OSError("i/o error")):
            with self.subTest(error=type(error).__name__), patch("os.lstat", side_effect=error):
                self.assertTrue(hb.kill_switch_on("/var/lib/honeypot-guard/MITIGATION_DISABLED"))

    def test_a_dangling_symlink_still_counts_as_the_file_being_there(self):
        # lstat, not stat: the file is "there" even if what it points at is not.
        from unittest.mock import patch
        with patch("os.lstat", return_value=object()):
            self.assertTrue(hb.kill_switch_on("/x"))


class TestCommandLine(unittest.TestCase):

    def test_a_bad_never_block_value_stops_it_before_it_does_anything(self):
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = hb.main(["--blocklist", "/nonexistent.json", "--never-block", "10.0.0.0/8,banana"])
        self.assertEqual(code, 2)
        self.assertIn("banana", out.getvalue())


if __name__ == "__main__":
    unittest.main()
