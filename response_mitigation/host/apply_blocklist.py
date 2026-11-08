#!/usr/bin/env python3
"""
response_mitigation/host/apply_blocklist.py

Runs on the Linux honeypot HOST, as root, from a systemd timer. It reads the
block list the pipeline wrote (blocklist.json) and makes the nftables set match
it. Nothing else in this project touches the firewall.

This file uses the Python standard library only and imports nothing from the
rest of the project, so it can be copied to the host on its own.

The pipeline user can write blocklist.json, and this script runs as root. So the
file is treated as untrusted input:
  * every IP is parsed again here and must be a public unicast address
  * an IP on the never-block list, or one of this host's own addresses, is refused
  * nft is run with an argument list, never through a shell
  * a file that is too big, has too many entries or is not valid JSON is refused
    outright and the firewall is left as it is

Kill switch: if the kill file exists, every block is removed.
Entries come off the firewall when they expire, when they leave the file, or
when the kill switch is on.

Exit codes: 0 ok | 1 some nft command failed | 2 refused to run (bad input) |
            3 nft is missing or the ruleset could not be loaded
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import stat
import subprocess
import sys
import time
from typing import Callable, Dict, Iterable, List, NamedTuple, Optional, Tuple, Union

FAMILY = "inet"
TABLE = "honeypot_guard"
CHAIN = "pre"
SET_V4 = "blocked_v4"
SET_V6 = "blocked_v6"
HOOK_PRIORITY = -300          # "raw": before conntrack and before Docker's NAT rules

MAX_FILE_BYTES = 1_000_000
MAX_ENTRIES = 5000            # more than this in one file means a bug; refuse it
MAX_TTL_S = 30 * 24 * 3600    # same ceiling as MITIGATION_DENY_TTL_HOURS
NFT_TIMEOUT_S = 20

RULESET = f"""\
table {FAMILY} {TABLE} {{
  set {SET_V4} {{ type ipv4_addr; flags timeout; }}
  set {SET_V6} {{ type ipv6_addr; flags timeout; }}
  chain {CHAIN} {{
    type filter hook prerouting priority raw; policy accept;
    ip  saddr @{SET_V4} drop
    ip6 saddr @{SET_V6} drop
  }}
}}
"""

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class Result(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[List[str], Optional[str]], Result]


# --------------------------------------------------------------------------
# IP checks and command text
# --------------------------------------------------------------------------
def public_address(text: object) -> IPAddress:
    """The IP as an address object, or ValueError saying why it may not be blocked."""
    if not isinstance(text, str):
        raise ValueError("not text")
    try:
        addr = ipaddress.ip_address(text.strip())
    except ValueError:
        raise ValueError("not an IP address") from None
    if addr.version == 6:
        if addr.scope_id:
            raise ValueError("IPv6 scope ids are not allowed")
        if addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
    # Python calls multicast addresses "global", so test for them as well.
    if not addr.is_global or addr.is_multicast:
        raise ValueError("not a public unicast address")
    return addr


def set_name(addr: IPAddress) -> str:
    return SET_V4 if addr.version == 4 else SET_V6


def add_element_command(ip: str, timeout_s: int) -> str:
    """The nft line that blocks `ip` for `timeout_s` seconds. Raises ValueError."""
    addr = public_address(ip)
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, int) or not 1 <= timeout_s <= MAX_TTL_S:
        raise ValueError(f"timeout must be a whole number of seconds from 1 to {MAX_TTL_S}")
    return f"add element {FAMILY} {TABLE} {set_name(addr)} {{ {addr} timeout {timeout_s}s }}"


def delete_element_command(ip: str) -> str:
    # `ip` here came out of the firewall itself, but it is checked all the same.
    addr = ipaddress.ip_address(ip)
    return f"delete element {FAMILY} {TABLE} {set_name(addr)} {{ {addr} }}"


# --------------------------------------------------------------------------
# Reading blocklist.json
# --------------------------------------------------------------------------
class Refused(Exception):
    """The block list file cannot be trusted this run. The firewall stays as it is."""


class Parsed(NamedTuple):
    desired: Dict[str, int]                 # canonical ip -> expires_at (epoch seconds)
    rejected: List[Tuple[str, str]]         # (what the file said, why not)
    expired: int


def read_file(path: str) -> bytes:
    """Read the file without following a symlink; refuse anything odd or oversize."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise Refused(f"cannot open {path}: {exc.strerror or type(exc).__name__}") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused(f"{path} is not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise Refused(f"cannot read {path}: {exc.strerror or type(exc).__name__}") from None
    finally:
        os.close(fd)
    if len(data) > MAX_FILE_BYTES:
        raise Refused(f"{path} is bigger than {MAX_FILE_BYTES} bytes")
    return data


def parse_entries(raw: bytes, *, now: float, never_block: Iterable[IPNetwork] = (),
                  local_addresses: Iterable[IPAddress] = ()) -> Parsed:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refused("block list is not valid JSON") from None
    entries = doc.get("entries") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        raise Refused('block list has no "entries" list')
    if len(entries) > MAX_ENTRIES:
        raise Refused(f"block list has {len(entries)} entries; the limit is {MAX_ENTRIES}")

    never = tuple(never_block)
    local = frozenset(local_addresses)
    desired: Dict[str, int] = {}
    rejected: List[Tuple[str, str]] = []
    expired = 0
    for item in entries:
        if not isinstance(item, dict):
            rejected.append((_clip(item), "entry is not an object"))
            continue
        shown = _clip(item.get("ip"))
        until = item.get("expires_at")
        if isinstance(until, bool) or not isinstance(until, (int, float)) or not math.isfinite(until):
            rejected.append((shown, "expires_at is not a number"))
            continue
        try:
            addr = public_address(item.get("ip"))
        except ValueError as exc:
            rejected.append((shown, str(exc)))
            continue
        if any(addr in net for net in never if net.version == addr.version):
            rejected.append((shown, "on the never-block list"))
        elif addr in local:
            rejected.append((shown, "this host's own address"))
        elif until <= now:
            expired += 1
        elif until - now > MAX_TTL_S:
            rejected.append((shown, "expiry is too far away"))
        else:
            key = str(addr)
            desired[key] = max(int(math.ceil(until)), desired.get(key, 0))
    return Parsed(desired, rejected, expired)


def _clip(value: object) -> str:
    """Printable, short form of something the file said. Never echo it unbounded."""
    text = value if isinstance(value, str) else type(value).__name__
    text = "".join(ch if ch.isprintable() else "?" for ch in text)
    return text[:60]


# --------------------------------------------------------------------------
# What the firewall holds now, and what to change
# --------------------------------------------------------------------------
def parse_set_listing(stdout: str) -> Dict[str, int]:
    """ip -> seconds left, from `nft -j list set ...`. An empty set has no "elem"."""
    try:
        doc = json.loads(stdout)
    except ValueError:
        raise Refused("could not read nft's JSON output") from None
    items = doc.get("nftables") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise Refused("nft's JSON output has no 'nftables' list")
    found: Dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("set"), dict):
            continue
        for element in item["set"].get("elem", []):
            if isinstance(element, dict) and "elem" in element:
                element = element["elem"]
            value = element.get("val") if isinstance(element, dict) else element
            if not isinstance(value, str):
                continue
            try:
                key = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            left = element.get("expires") if isinstance(element, dict) else None
            found[key] = int(left) if isinstance(left, (int, float)) else MAX_TTL_S
    return found


def plan_changes(desired: Dict[str, int], current: Dict[str, int], now: float
                 ) -> Tuple[List[Tuple[str, int]], List[str]]:
    """(to add as (ip, seconds), to remove). Entries already in the set are left alone:
    nft does not lengthen the timeout of an element that is already there."""
    add = [(ip, max(1, int(math.ceil(until - now)))) for ip, until in sorted(desired.items())
           if ip not in current]
    remove = sorted(ip for ip in current if ip not in desired)
    return add, remove


def table_is_healthy(stdout: str) -> bool:
    """True if our table has both sets and a prerouting drop rule for each, at the
    priority we expect. A table that has drifted is rebuilt rather than trusted."""
    try:
        doc = json.loads(stdout)
    except ValueError:
        return False
    items = doc.get("nftables") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        return False
    items = [i for i in items if isinstance(i, dict)]
    sets = {i["set"].get("name") for i in items if isinstance(i.get("set"), dict)}
    chains = [i["chain"] for i in items if isinstance(i.get("chain"), dict)]
    chain_ok = any(c.get("name") == CHAIN and c.get("hook") == "prerouting"
                   and c.get("prio") == HOOK_PRIORITY for c in chains)
    dropped = set()
    for i in items:
        rule = i.get("rule")
        if not isinstance(rule, dict) or rule.get("chain") != CHAIN:
            continue
        text = json.dumps(rule.get("expr", []))
        if '"drop"' in text and '"saddr"' in text:
            for name in (SET_V4, SET_V6):
                if f"@{name}" in text:
                    dropped.add(name)
    return chain_ok and {SET_V4, SET_V6} <= sets and dropped == {SET_V4, SET_V6}


# --------------------------------------------------------------------------
# Doing it
# --------------------------------------------------------------------------
def run_command(argv: List[str], stdin: Optional[str] = None) -> Result:
    try:
        done = subprocess.run(argv, input=stdin, capture_output=True, text=True,
                              timeout=NFT_TIMEOUT_S, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Result(127, "", f"{type(exc).__name__}: {exc}")
    return Result(done.returncode, done.stdout, done.stderr)


def local_addresses(runner: Runner) -> List[IPAddress]:
    """This host's own addresses, so we never block ourselves. Best effort."""
    result = runner(["ip", "-j", "addr", "show"], None)
    if result.returncode != 0:
        say("warning: could not list this host's addresses; relying on the never-block list")
        return []
    found: List[IPAddress] = []
    try:
        for iface in json.loads(result.stdout):
            for info in iface.get("addr_info", []):
                try:
                    found.append(ipaddress.ip_address(info.get("local", "")))
                except ValueError:
                    pass
    except (ValueError, AttributeError, TypeError):
        say("warning: could not read the address list")
    return found


def kill_switch_on(path: Optional[str]) -> bool:
    """True if the kill file exists. If we cannot tell, say yes: removing blocks is
    the safe failure, and os.path.exists would hide a permission error as 'no'."""
    if not path:
        return False
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def say(message: str) -> None:
    print(message, flush=True)


def reconcile(*, blocklist: str, kill_file: Optional[str], never_block: Iterable[IPNetwork] = (),
              dry_run: bool = False, runner: Runner = run_command,
              now: Optional[float] = None) -> int:
    now = time.time() if now is None else now

    # 1. what do we want blocked?
    if kill_switch_on(kill_file):
        say("kill switch is on: removing every block")
        desired: Dict[str, int] = {}
    else:
        try:
            data = read_file(blocklist)
        except FileNotFoundError:
            say(f"no block list at {blocklist}; nothing to block")
            data = None
        except Refused as exc:
            say(f"refused: {exc}; the firewall was left as it is")
            return 2
        if data is None:
            desired = {}
        else:
            try:
                parsed = parse_entries(data, now=now, never_block=never_block,
                                       local_addresses=local_addresses(runner))
            except Refused as exc:
                say(f"refused: {exc}; the firewall was left as it is")
                return 2
            desired = parsed.desired
            for shown, why in parsed.rejected:
                say(f"skipped entry {shown!r}: {why}")

    # 2. is our table there and correct?
    probe = runner(["nft", "-j", "list", "table", FAMILY, TABLE], None)
    if probe.returncode == 127:
        say(f"nft could not be run: {probe.stderr.strip()}")
        return 3
    exists = probe.returncode == 0
    if exists and table_is_healthy(probe.stdout):
        rebuild = None
    else:
        rebuild = ("delete table %s %s\n" % (FAMILY, TABLE) if exists else "") + RULESET
        say("firewall table has drifted; rebuilding it" if exists else "firewall table is missing; creating it")
    if rebuild and not dry_run:
        loaded = runner(["nft", "-f", "-"], rebuild)
        if loaded.returncode != 0:
            say(f"could not load the ruleset: {loaded.stderr.strip()}")
            return 3

    # 3. what does the firewall hold now?
    current: Dict[str, int] = {}
    if rebuild is None:
        for name in (SET_V4, SET_V6):
            listed = runner(["nft", "-j", "list", "set", FAMILY, TABLE, name], None)
            if listed.returncode != 0:
                say(f"could not read set {name}: {listed.stderr.strip()}")
                return 3
            try:
                current.update(parse_set_listing(listed.stdout))
            except Refused as exc:
                say(f"refused: {exc}")
                return 3

    # 4. make it match
    add, remove = plan_changes(desired, current, now)
    lines = [add_element_command(ip, secs) for ip, secs in add] + [delete_element_command(ip) for ip in remove]
    kept = len(desired) - len(add)
    say(f"add {len(add)}, remove {len(remove)}, keep {kept}" + (" (dry run)" if dry_run else ""))
    if dry_run:
        for line in lines:
            say("  would run: nft " + line)
        return 0
    if not lines:
        return 0
    applied = runner(["nft", "-f", "-"], "\n".join(lines) + "\n")
    if applied.returncode == 0:
        return 0
    # One bad line (say, an element that expired a moment ago) fails the whole batch.
    # Run them one at a time so the good ones still land.
    failures = 0
    for line in lines:
        single = runner(["nft", "-f", "-"], line + "\n")
        if single.returncode != 0:
            failures += 1
            say(f"nft refused: {line}  ({single.stderr.strip()})")
    return 1 if failures else 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Make the nftables block set match blocklist.json.")
    ap.add_argument("--blocklist", required=True, help="path to blocklist.json")
    ap.add_argument("--kill-file", help="if this file exists, remove every block")
    ap.add_argument("--never-block", default=os.environ.get("HONEYPOT_GUARD_NEVER_BLOCK", ""),
                    help="comma-separated IPs/networks to never block (default: $HONEYPOT_GUARD_NEVER_BLOCK)")
    ap.add_argument("--dry-run", action="store_true", help="show what would change; change nothing")
    args = ap.parse_args(argv)

    networks = []
    for part in (p.strip() for p in args.never_block.split(",")):
        if part:
            try:
                networks.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                say(f"refused: --never-block has {part!r}, which is not an IP address or network")
                return 2
    return reconcile(blocklist=args.blocklist, kill_file=args.kill_file,
                     never_block=networks, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
