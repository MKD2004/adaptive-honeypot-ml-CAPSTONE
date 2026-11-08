"""
response_mitigation/executors/firewall.py

DENY: put the source IP on the block list. That is all this does.

It never runs a firewall command and never needs root. It writes blocklist.json;
apply_blocklist.py on the host (run by a systemd timer, as root) reads that file
and updates the nftables set, usually within a few seconds.

The note it hands back for the audit log includes the exact nft line the host
will run, so a reader of the log can see what was asked for.
"""
from __future__ import annotations

from typing import Optional

from ..blocklist import BlocklistFile, iso_utc
from ..host.apply_blocklist import add_element_command
from ..models import PlannedAction, Verdict


class FirewallExecutor:
    def __init__(self, blocklist: BlocklistFile, *, default_ttl_s: int = 24 * 3600) -> None:
        self._blocklist = blocklist
        self._default_ttl_s = default_ttl_s

    def skip_reason(self, verdict: Verdict, planned: PlannedAction) -> Optional[str]:
        entry = self._blocklist.get(verdict.ip)
        if entry is not None:
            return f"already on the block list until {iso_utc(entry.expires_at)}"
        return None

    def apply(self, verdict: Verdict, planned: PlannedAction) -> str:
        ttl = planned.ttl_s or self._default_ttl_s
        command = add_element_command(verdict.ip, ttl)       # checks the IP again; raises if unsafe
        entry = self._blocklist.add(verdict.ip, ttl_s=ttl, reason=planned.reason,
                                    rule=planned.rule, session_id=verdict.session_id)
        return (f"on the block list until {iso_utc(entry.expires_at)}; "
                f"the host will run: nft {command}")

