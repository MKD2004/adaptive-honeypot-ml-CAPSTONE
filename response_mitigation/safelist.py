"""
response_mitigation/safelist.py

The never-block list: answers "is it safe to do this action to this address?"
before the engine does anything.

How strict it is depends on the action:
  OBSERVE, ALERT  never skipped. They only record or tell.
  DIVERT          skipped for a bad address, a whitelisted one, or the Docker
                  bridge (that means attribution found no real peer). Loopback
                  and private addresses are allowed, or the two-laptop demo
                  would stop working.
  DENY            only a public address that is on none of the protected lists.
                  A firewall drop of a private address could cut us off.

This module does not import traffic_gateway, so the gateway pipeline can call
the mitigation layer later without a circular import.
"""
from __future__ import annotations

import ipaddress
from typing import Callable, Iterable, Optional, Union

from .models import Action

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Docker's default bridge pools sit in 172.16.0.0/12 -- all of it, and nothing
# outside it. A "172.1" / "172.2" text prefix also matches public space such as
# 172.217.x.x, which is the bug fixed in traffic_gateway/peer_attribution.py.
DOCKER_BRIDGE_NET = ipaddress.ip_network("172.16.0.0/12")


def parse_ip(value: object) -> Optional[IPAddress]:
    """A strict parse: anything that is not exactly one IP address gives None.

    IPv4-mapped IPv6 (::ffff:1.2.3.4) is unwrapped to the IPv4 address, so a
    protected address cannot slip past in the other notation.
    """
    if not isinstance(value, str):
        return None
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if addr.version == 6:
        if addr.scope_id:
            return None
        if addr.ipv4_mapped is not None:
            return addr.ipv4_mapped
    return addr


def canonical(value: object) -> Optional[str]:
    """The one safe text form of an IP. Use this, never the raw input, anywhere
    an address ends up inside a command or a file."""
    addr = parse_ip(value)
    return str(addr) if addr is not None else None


def _in_docker_bridge(addr: IPAddress) -> bool:
    return addr.version == 4 and addr in DOCKER_BRIDGE_NET


class Safelist:
    def __init__(self,
                 never_block: Iterable[IPNetwork] = (),
                 own_addresses: Iterable[str] = (),
                 is_whitelisted: Optional[Callable[[str], bool]] = None) -> None:
        """
        never_block     admin addresses/networks that must never be denied.
        own_addresses   this host's own addresses (the cloud VM's public IP).
        is_whitelisted  asks the gateway whether an IP is trusted; it is given
                        the canonical text form.
        """
        self._never_block = tuple(never_block)
        own = []
        for text in own_addresses:
            addr = parse_ip(text)
            if addr is None:
                raise ValueError(f"own address {text!r} is not an IP address")
            own.append(addr)
        self._own = frozenset(own)
        self._is_whitelisted = is_whitelisted or (lambda _ip: False)

    def skip_reason(self, ip: str, action: Action) -> Optional[str]:
        """Why this action must not be done to `ip`, or None when it may."""
        if action in (Action.OBSERVE, Action.ALERT):
            return None

        addr = parse_ip(ip)
        if addr is None:
            return "not a valid IP address"
        if self._is_whitelisted(str(addr)):
            return "whitelisted"

        if action is Action.DIVERT:
            if _in_docker_bridge(addr):
                return "Docker bridge address (no real peer was found)"
            return None

        # DENY: the strictest check.
        if _in_docker_bridge(addr):
            return "Docker bridge address (no real peer was found)"
        # Python calls multicast addresses "global", so test for them as well.
        if not addr.is_global or addr.is_multicast:
            return "not a public unicast address (loopback, private, multicast or reserved)"
        if any(addr in net for net in self._never_block):
            return "on the never-block list"
        if addr in self._own:
            return "this host's own address"
        return None
