"""
response_mitigation/safelist.py

The never-block list: answers "is it safe to do this action to this address?"
before the engine does anything.

How strict it is depends on the action:
  OBSERVE, ALERT  never skipped. They only record or tell.
  DIVERT          skipped for a bad address, the Docker bridge (that means
                  attribution found no real peer), or anything on the
                  never-block list. A WHITELISTED address is skipped too, UNLESS
                  the verdict is strong enough to override it -- see below.
                  Loopback and private addresses are allowed, or the two-laptop
                  demo would stop working.
  DENY            only a public address that is on none of the protected lists.
                  A firewall drop of a private address could cut us off, and a
                  whitelist is NEVER overridable for DENY.

THE WHITELIST OVERRIDE (added 2026-11-04)

HONEYPOT_AUDIT.md PART 3 rated this the most serious finding in the project. The
old skip_reason(ip, action) did not receive the verdict at all, so it could not
weigh evidence: is_whitelisted short-circuited everything, and every MT3 verdict
on a whitelisted address came back "skipped: whitelisted" at ANY phase and ANY
confidence. An attacker who earned a whitelist -- about 70 minutes of good
behaviour through the promoter -- was then immune to the detection half of the
system, and the longer they behaved the safer they got.

The fix is narrow on purpose:

  - DIVERT may override the whitelist when the verdict clears BOTH
    override_min_phase and override_min_confidence. Those default stricter than
    the ordinary blacklist thresholds (phase 2 / 0.90 against phase 1 / 0.50),
    because overriding an explicit human trust decision should need more evidence
    than blocking a stranger. DIVERT only re-routes to the honeypot, and it is
    reversible.
  - DENY never overrides it. A firewall drop of a trusted address can cut off
    admin access, and that risk is not worth automating.
  - never_block and own_addresses stay DENY-only, exactly as before. They were
    designed that way ("must never be DENIED") and
    test_never_block_list_does_not_stop_a_divert asserts it: diverting an admin
    address to the decoy is disruptive but reversible, whereas firewalling it can
    lock you out. An earlier draft of this change extended them to DIVERT; that
    was scope creep past what the audit recommended, and it was reverted.

    Residual question worth a team decision, NOT settled here: an admin address is
    usually whitelisted too, so a strong verdict can now divert it. If that is
    unacceptable, put the address in never_block AND extend never_block to DIVERT
    -- but do it deliberately, with that test updated.

Callers that pass no verdict keep the old behaviour exactly: no phase and no
confidence means no evidence, so the whitelist still wins.

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
                 is_whitelisted: Optional[Callable[[str], bool]] = None,
                 override_min_phase: int = 2,
                 override_min_confidence: float = 0.90) -> None:
        """
        never_block     admin addresses/networks that must never be touched.
        own_addresses   this host's own addresses (the cloud VM's public IP).
        is_whitelisted  asks the gateway whether an IP is trusted; it is given
                        the canonical text form.
        override_min_phase / override_min_confidence
                        how strong a verdict must be before DIVERT may override a
                        whitelist. Deliberately stricter than the ordinary
                        blacklist thresholds; see the module docstring.
        """
        if not 0 <= int(override_min_phase) <= 8:
            raise ValueError(f"override_min_phase={override_min_phase}: must be 0-8")
        if not 0.0 <= float(override_min_confidence) <= 1.0:
            raise ValueError(
                f"override_min_confidence={override_min_confidence}: must be 0-1")
        self._override_min_phase = int(override_min_phase)
        self._override_min_confidence = float(override_min_confidence)
        self._never_block = tuple(never_block)
        own = []
        for text in own_addresses:
            addr = parse_ip(text)
            if addr is None:
                raise ValueError(f"own address {text!r} is not an IP address")
            own.append(addr)
        self._own = frozenset(own)
        self._is_whitelisted = is_whitelisted or (lambda _ip: False)

    def may_override_whitelist(self, phase, confidence) -> bool:
        """Is this verdict strong enough to act on a trusted address?

        Both thresholds must be cleared. Missing values mean "no evidence", so the
        answer is no -- that is what keeps old callers behaving as before. A NaN
        confidence also fails, since every comparison against NaN is False.
        """
        if phase is None or confidence is None:
            return False
        try:
            return (int(phase) >= self._override_min_phase
                    and float(confidence) >= self._override_min_confidence)
        except (TypeError, ValueError):
            return False

    def skip_reason(self, ip: str, action: Action, *,
                    phase: Optional[int] = None,
                    confidence: Optional[float] = None) -> Optional[str]:
        """Why this action must not be done to `ip`, or None when it may.

        `phase` / `confidence` are the MT3 verdict's. Supplying them lets a strong
        verdict override a whitelist for DIVERT (never for DENY). Omitting them
        reproduces the old behaviour, where a whitelist always wins.
        """
        if action in (Action.OBSERVE, Action.ALERT):
            return None

        addr = parse_ip(ip)
        if addr is None:
            return "not a valid IP address"

        if _in_docker_bridge(addr):
            return "Docker bridge address (no real peer was found)"

        if self._is_whitelisted(str(addr)):
            if not (action is Action.DIVERT
                    and self.may_override_whitelist(phase, confidence)):
                return "whitelisted"
            # strong enough verdict: fall through and divert

        if action is Action.DIVERT:
            return None

        # DENY: the strictest check.
        # Python calls multicast addresses "global", so test for them as well.
        if not addr.is_global or addr.is_multicast:
            return "not a public unicast address (loopback, private, multicast or reserved)"
        if any(addr in net for net in self._never_block):
            return "on the never-block list"
        if addr in self._own:
            return "this host's own address"
        return None
