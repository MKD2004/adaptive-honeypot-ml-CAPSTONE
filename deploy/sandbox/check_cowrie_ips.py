#!/usr/bin/env python3
"""
deploy/sandbox/check_cowrie_ips.py

Does Cowrie see the attackers' REAL addresses?

Docker can hide them. If the connection reaches the container through a proxy process (this
happens for IPv6, and for connections made from the host itself), every attacker shows up as
Docker's own address, for example 172.17.0.1. Then every session looks like it comes from one
machine, the pipeline's per-IP counts are wrong, and a firewall block would hit the wrong
address. This reads the newest Cowrie log and says whether that is happening.

    check_cowrie_ips.py LOG_DIR [--client-ip IP] [--last N] [--allow-private]

Exit codes: 0 all good | 1 Docker/private/loopback addresses seen | 2 no connections in the log |
            3 --client-ip was given but never seen | 4 the log could not be read or --client-ip is not an IP
Standard library only.
"""
from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import sys
from pathlib import Path
from typing import Deque, List, Optional

CONNECT_EVENT = "cowrie.session.connect"
DOCKER_NET = ipaddress.ip_network("172.16.0.0/12")   # all of Docker's default bridge pools


def classify(text: object) -> str:
    """public | docker | loopback | private | invalid"""
    try:
        addr = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return "invalid"
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.version == 4 and addr in DOCKER_NET:
        return "docker"
    if addr.is_loopback:
        return "loopback"
    if addr.is_global and not addr.is_multicast:
        return "public"
    return "private"


def _plain(text: object) -> Optional[str]:
    """The one text form of an address (IPv4-mapped IPv6 unwrapped), or None if it is not one."""
    try:
        addr = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


def recent_connect_sources(log_dir: Path, last: int) -> List[str]:
    """Source IPs of the most recent `last` connect events, newest log files first."""
    files = sorted(Path(log_dir).glob("cowrie.json*"), key=lambda p: p.stat().st_mtime, reverse=True)
    found: Deque[str] = collections.deque(maxlen=last)
    for path in reversed(files[:2]):                     # the newest two, oldest of those first
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if isinstance(event, dict) and event.get("eventid") == CONNECT_EVENT and event.get("src_ip"):
                    found.append(str(event["src_ip"]))
    return list(found)


def check(log_dir: Path, *, client_ip: Optional[str] = None, last: int = 50,
          allow_private: bool = False) -> "tuple[int, List[str]]":
    """Returns (exit code, lines to show)."""
    try:
        sources = recent_connect_sources(log_dir, last)
    except OSError as exc:
        return 4, [f"cannot read the Cowrie log in {log_dir}: {exc.strerror or type(exc).__name__}"]
    if not sources:
        return 2, ["no connections in the Cowrie log yet"]

    kinds = collections.Counter(classify(ip) for ip in sources)
    lines = [f"last {len(sources)} connections: " + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items()))]
    bad = [k for k in ("docker", "loopback", "private", "invalid") if kinds[k]]
    if kinds["docker"] or kinds["invalid"] or (bad and not allow_private):
        lines.append("Cowrie is NOT seeing real addresses. Sources: "
                     + ", ".join(sorted({ip for ip in sources if classify(ip) != "public"})[:6]))
        if kinds["docker"]:
            lines.append("The Docker address means connections reach the container through a proxy. "
                         "Check that the published port is IPv4 only and that no one is connecting from this host.")
        return 1, lines
    if client_ip:
        wanted = _plain(client_ip)
        if wanted is None:
            return 4, lines + [f"--client-ip {client_ip!r} is not an IP address"]
        if wanted not in {_plain(ip) for ip in sources}:
            lines.append(f"{wanted} (the client you used) is not among them. Did the connection reach Cowrie?")
            return 3, lines
        lines.append(f"{wanted} (the client you used) was seen with its real address")
    return 0, lines


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Check that Cowrie sees attackers' real addresses.")
    ap.add_argument("log_dir", type=Path)
    ap.add_argument("--client-ip", help="the public address of the machine you connected from")
    ap.add_argument("--last", type=int, default=50, help="how many recent connections to look at")
    ap.add_argument("--allow-private", action="store_true",
                    help="lab use: private and loopback sources are fine (Docker's address still is not)")
    args = ap.parse_args(argv)
    code, lines = check(args.log_dir, client_ip=args.client_ip, last=max(1, args.last),
                        allow_private=args.allow_private)
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    sys.exit(main())
