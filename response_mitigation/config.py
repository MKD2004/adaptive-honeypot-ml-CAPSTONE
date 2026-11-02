"""
response_mitigation/config.py

Settings for the mitigation layer, read from environment variables.

Unset or empty -> the default. A value that is set but wrong raises
ValueError naming the variable, so a typo in a safety setting stops start-up
instead of silently using the default.

The gateway's own MT3_AUTO_BLACKLIST_MIN_PHASE / _CONF are not read here. The
engine will copy them into PolicyConfig so there is one source of truth for
what counts as an attack.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Tuple
from urllib.parse import urlsplit

from .models import Mode
from .policy import PolicyConfig
from .safelist import IPNetwork

_PACKAGE_DIR = Path(__file__).parent

_TRUE_WORDS = {"1", "true", "yes", "on"}
_FALSE_WORDS = {"0", "false", "no", "off"}


@dataclass(frozen=True)
class MitigationConfig:
    mode: Mode
    firewall: bool                   # may the firewall executor run at all?
    max_new_blocks_per_hour: int     # cap on new DENYs; 0 means block nothing
    never_block: Tuple[IPNetwork, ...]
    kill_file: Path                  # if this file exists, do nothing at all
    blocklist_path: Path             # read by the host's firewall script
    audit_path: Path
    policy: PolicyConfig
    alert_webhook: Optional[str] = None    # chat webhook for ALERT; None = log line only
    alert_max_per_hour: int = 30


def _raw(env: Mapping[str, str], name: str) -> str:
    return str(env.get(name, "") or "").strip()


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = _raw(env, name).lower()
    if not raw:
        return default
    if raw in _TRUE_WORDS:
        return True
    if raw in _FALSE_WORDS:
        return False
    raise ValueError(f"{name}={raw!r}: expected one of 1/0, true/false, yes/no, on/off")


def _int(env: Mapping[str, str], name: str, default: int, lo: int, hi: int) -> int:
    raw = _raw(env, name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name}={raw!r}: expected a whole number") from None
    if not lo <= value <= hi:
        raise ValueError(f"{name}={value}: must be between {lo} and {hi}")
    return value


def _mode(env: Mapping[str, str], name: str, default: Mode) -> Mode:
    raw = _raw(env, name).lower()
    if not raw:
        return default
    try:
        return Mode(raw)
    except ValueError:
        choices = "/".join(m.value for m in Mode)
        raise ValueError(f"{name}={raw!r}: expected one of {choices}") from None


def _path(env: Mapping[str, str], name: str, default: Path) -> Path:
    raw = _raw(env, name)
    return Path(raw) if raw else default


def _networks(env: Mapping[str, str], name: str) -> Tuple[IPNetwork, ...]:
    """Comma-separated IPs and/or CIDR networks."""
    raw = _raw(env, name)
    nets = []
    for item in (part.strip() for part in raw.split(",")):
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            raise ValueError(f"{name}: {item!r} is not an IP address or network") from None
    return tuple(nets)


def _webhook(env: Mapping[str, str], name: str) -> Optional[str]:
    """An https URL (plain http only to this machine). The URL is a secret: it is never put in an error."""
    raw = _raw(env, name)
    if not raw:
        return None
    parts = urlsplit(raw)
    host = (parts.hostname or "").lower()
    if len(raw) > 2048 or any(c.isspace() for c in raw) or parts.scheme not in ("https", "http") or not host:
        raise ValueError(f"{name}: expected one https URL with no spaces (the value is not shown: it is a secret)")
    if parts.scheme == "http" and host not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError(f"{name}: plain http is only allowed to this machine; use https")
    return raw


def load_config(env: Optional[Mapping[str, str]] = None) -> MitigationConfig:
    """Read the settings. Pass `env` in tests; defaults to os.environ."""
    env = os.environ if env is None else env
    defaults = PolicyConfig()
    policy = PolicyConfig(
        alert_min_phase=_int(env, "MITIGATION_ALERT_MIN_PHASE", defaults.alert_min_phase, 0, 8),
        deny_min_phase=_int(env, "MITIGATION_DENY_MIN_PHASE", defaults.deny_min_phase, 0, 8),
        deny_repeat_sessions=_int(env, "MITIGATION_DENY_REPEAT_SESSIONS",
                                  defaults.deny_repeat_sessions, 1, 1000),
        deny_ttl_s=_int(env, "MITIGATION_DENY_TTL_HOURS",
                        defaults.deny_ttl_s // 3600, 1, 24 * 30) * 3600,
    )
    return MitigationConfig(
        mode=_mode(env, "MITIGATION_MODE", Mode.OBSERVE),
        firewall=_bool(env, "MITIGATION_FIREWALL", False),
        max_new_blocks_per_hour=_int(env, "MITIGATION_MAX_NEW_BLOCKS_PER_HOUR", 50, 0, 1000),
        never_block=_networks(env, "MITIGATION_NEVER_BLOCK"),
        kill_file=_path(env, "MITIGATION_KILL_FILE", _PACKAGE_DIR / "MITIGATION_DISABLED"),
        blocklist_path=_path(env, "MITIGATION_BLOCKLIST_PATH", _PACKAGE_DIR / "data" / "blocklist.json"),
        audit_path=_path(env, "MITIGATION_AUDIT_PATH", _PACKAGE_DIR / "logs" / "mitigation_audit.jsonl"),
        policy=policy,
        alert_webhook=_webhook(env, "MITIGATION_ALERT_WEBHOOK"),
        alert_max_per_hour=_int(env, "MITIGATION_ALERT_MAX_PER_HOUR", 30, 0, 1000),
    )
