"""
adaptive_honeypot/configurator.py

Turns an MT3 prediction into a live honeypot configuration: the kill-chain
phase selects an interaction level (minimal -> maximum + alert), a trending CVE
whose attack type matches the phase overrides the fake service banner, and the
merged config is written to active_config.json for Cowrie/honeyports to read.
Every change is logged with the reason that caused it.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("adaptive_honeypot.configurator")

_MODULE_DIR = Path(__file__).resolve().parent
REPO_ROOT = _MODULE_DIR.parent

ACTIVE_CONFIG_PATH = _MODULE_DIR / "active_config.json"
CONFIG_LOG_PATH = REPO_ROOT / "logs" / "honeypot_config_changes.jsonl"
TRENDING_PROFILES_PATH = REPO_ROOT / "cve_intelligence" / "data" / "trending_profiles.json"

PHASE_NAMES = [
    "Reconnaissance", "Initial Access", "Execution", "Discovery",
    "Privilege Escalation", "Persistence", "Defense Evasion",
    "Lateral Movement", "Exfiltration",
]

# ── Phase band -> interaction profile ────────────────────────────────────────
# Bands come straight from the kill chain: the deeper the attacker is, the more
# we let them touch, because the intelligence value of what they do next rises
# faster than the risk of the (entirely fake) filesystem they are touching.
INTERACTION_PROFILES: Dict[str, Dict[str, Any]] = {
    "low": {
        "interaction_level": "low",
        "purpose": "Waste the attacker's time; collect source IP and tool fingerprint.",
        "filesystem": "minimal",
        "response_delay_ms": 1200,          # slow responses stall scanners
        "fake_credentials_visible": False,
        "fake_sensitive_files": False,
        "fake_ssh_keys": False,
        "allow_download": False,
        "capture_uploads": False,
        "alert": False,
    },
    "medium": {
        "interaction_level": "medium",
        "purpose": "Let the attacker reveal their tooling and techniques.",
        "filesystem": "rich",
        "response_delay_ms": 400,
        "fake_credentials_visible": True,
        "fake_sensitive_files": False,
        "fake_ssh_keys": False,
        "allow_download": True,
        "capture_uploads": True,
        "alert": False,
    },
    "high": {
        "interaction_level": "high",
        "purpose": "Capture the full toolkit and any C2 infrastructure.",
        "filesystem": "full",
        "response_delay_ms": 120,
        "fake_credentials_visible": True,
        "fake_sensitive_files": True,       # fake /etc/shadow, fake configs
        "fake_ssh_keys": True,              # plantable keys to steal
        "allow_download": True,
        "capture_uploads": True,
        "alert": False,
    },
    "maximum": {
        "interaction_level": "maximum",
        "purpose": "Attacker believes they succeeded; maximum intelligence collection.",
        "filesystem": "full",
        "response_delay_ms": 80,
        "fake_credentials_visible": True,
        "fake_sensitive_files": True,
        "fake_ssh_keys": True,
        "allow_download": True,
        "capture_uploads": True,
        "alert": True,                      # external alert fires
    },
}

PHASE_TO_LEVEL = {
    0: "low", 1: "low",                     # Recon / Initial Access
    2: "medium", 3: "medium",               # Execution / Discovery
    4: "high", 5: "high", 6: "high",        # PrivEsc / Persistence / Evasion
    7: "maximum", 8: "maximum",             # Lateral Movement / Exfiltration
}

LEVEL_RANK = {"low": 0, "medium": 1, "high": 2, "maximum": 3}

# Fake service banners per interaction level and honeypot target. A trending
# CVE profile overrides these when one matches (see _match_cve_profile).
DEFAULT_BANNERS = {
    "SSH_HONEYPOT": "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
    "WEB_HONEYPOT": "Apache/2.4.29 (Ubuntu)",
    "DB_HONEYPOT": "5.7.33-0ubuntu0.16.04.1",
}

# Which kill-chain phases a trending CVE's attack_type is plausibly relevant to.
# Used to decide whether a trending CVE should reshape the honeypot at all --
# a path-traversal CVE is not evidence for how to answer an SSH brute-forcer.
ATTACK_TYPE_PHASES: Dict[str, List[int]] = {
    "authentication bypass": [0, 1],
    "broken access control": [1, 3, 4],
    "path traversal": [3, 8],
    "sql injection": [1, 3],
    "remote code execution": [2, 4],
    "command injection": [2, 4],
    "deserialization": [2, 4],
    "privilege escalation": [4],
    "information disclosure": [3, 8],
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_trending_profiles(path: Path = TRENDING_PROFILES_PATH) -> List[dict]:
    try:
        with Path(path).open(encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except Exception as exc:
        log.warning("trending CVE profiles unavailable (%s): %s", path, exc)
        return []


def _match_cve_profile(phase: int, target: str,
                       profiles: List[dict]) -> Optional[dict]:
    """Highest-priority trending CVE whose attack type fits this phase.

    Web/DB CVE profiles are only applied to web/db honeypots -- dressing the SSH
    honeypot as a vulnerable REST API would be visibly incoherent to an attacker
    already inside a shell.
    """
    if not profiles:
        return None
    web_like = target in ("WEB_HONEYPOT", "DB_HONEYPOT")
    best = None
    for prof in profiles:
        atype = str(prof.get("attack_type", "")).strip().lower()
        phases = ATTACK_TYPE_PHASES.get(atype)
        if phases is None:                          # "Other / Unknown" etc.
            continue
        if phase not in phases:
            continue
        svc = str(prof.get("honeypot_config", {}).get("service", "")).lower()
        if not web_like and any(w in svc for w in ("web", "api", "http", "file server")):
            continue
        if best is None or float(prof.get("priority_score", 0)) > float(
                best.get("priority_score", 0)):
            best = prof
    return best


def _banner_from_profile(profile: dict, fallback: str) -> str:
    """Pull the fake banner out of a CVE profile's config_string."""
    cfg = str(profile.get("config_string", "")
              or profile.get("honeypot_config", {}).get("config_string", ""))
    for part in cfg.split():
        if part.startswith("banner="):
            return part.split("=", 1)[1].strip('"').replace("_", "/")
    return fallback


class HoneypotConfigurator:
    """Owns active_config.json and the change log."""

    def __init__(self, config_path: Path = ACTIVE_CONFIG_PATH,
                 log_path: Path = CONFIG_LOG_PATH,
                 profiles_path: Path = TRENDING_PROFILES_PATH) -> None:
        self.config_path = Path(config_path)
        self.log_path = Path(log_path)
        self.profiles_path = Path(profiles_path)
        self._lock = threading.Lock()
        self._profiles = _load_trending_profiles(self.profiles_path)
        self.changes = 0

    # -- config state ------------------------------------------------------
    def load_active(self) -> Dict[str, Any]:
        """Current active config, or the day-zero default if none exists."""
        if self.config_path.exists():
            try:
                with self.config_path.open(encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception as exc:
                log.warning("active_config.json unreadable (%s); using default", exc)
        return self.default_config()

    def default_config(self) -> Dict[str, Any]:
        cfg = dict(INTERACTION_PROFILES["low"])
        cfg.update({
            "honeypot_target": "SSH_HONEYPOT",
            "phase": 0,
            "phase_name": PHASE_NAMES[0],
            "micro_state": None,
            "banner": DEFAULT_BANNERS["SSH_HONEYPOT"],
            "cve_profile": None,
            "updated_at": None,
            "reason": "default (no session observed yet)",
        })
        return cfg

    def build_config(self, prediction: Dict[str, Any],
                     session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """MT3 prediction -> the config that *should* be active."""
        phase = int(prediction.get("phase", 0))
        phase = min(max(phase, 0), 8)
        target = str(prediction.get("honeypot_target") or "SSH_HONEYPOT")
        level = PHASE_TO_LEVEL[phase]

        cfg = dict(INTERACTION_PROFILES[level])
        cfg.update({
            "honeypot_target": target,
            "phase": phase,
            "phase_name": PHASE_NAMES[phase],
            "micro_state": prediction.get("micro_state"),
            "confidence": prediction.get("confidence"),
            "banner": DEFAULT_BANNERS.get(target, DEFAULT_BANNERS["SSH_HONEYPOT"]),
            "cve_profile": None,
        })

        # -- CVE-aware overlay --------------------------------------------
        profile = _match_cve_profile(phase, target, self._profiles)
        if profile is not None:
            hc = profile.get("honeypot_config", {})
            cfg["banner"] = _banner_from_profile(profile, cfg["banner"])
            cfg["cve_profile"] = {
                "cve_id": profile.get("cve_id"),
                "attack_type": profile.get("attack_type"),
                "severity": profile.get("severity"),
                "cvss_score": profile.get("cvss_score"),
                "epss_score": profile.get("epss_score"),
                "is_kev": bool(profile.get("is_kev")),
                "priority_tier": profile.get("priority_tier"),
                "service": hc.get("service"),
                "endpoint": hc.get("endpoint"),
                "emulation": hc.get("emulation"),
                "fake_data": hc.get("fake_data"),
                "ports": hc.get("ports"),
            }
            # A trending CVE may only RAISE the interaction level, never lower
            # the level the observed kill-chain phase already justified.
            cve_level = str(hc.get("interaction_level", "")).lower()
            if cve_level in LEVEL_RANK and LEVEL_RANK[cve_level] > LEVEL_RANK[level]:
                cfg.update(INTERACTION_PROFILES[cve_level])
                cfg["interaction_level"] = cve_level

        if session is not None:
            cfg["last_session"] = {
                "session_id": session.get("session_id"),
                "src_ip": session.get("src_ip"),
            }
        return cfg

    # -- the fields that make a config "different" ------------------------
    _MATERIAL = ("interaction_level", "honeypot_target", "banner", "filesystem",
                 "fake_credentials_visible", "fake_sensitive_files",
                 "fake_ssh_keys", "allow_download", "alert")

    def _diff(self, old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
        changed = {k: {"from": old.get(k), "to": new.get(k)}
                   for k in self._MATERIAL if old.get(k) != new.get(k)}
        old_cve = (old.get("cve_profile") or {}).get("cve_id")
        new_cve = (new.get("cve_profile") or {}).get("cve_id")
        if old_cve != new_cve:
            changed["cve_profile"] = {"from": old_cve, "to": new_cve}
        return changed

    def _reason(self, old: Dict[str, Any], new: Dict[str, Any],
                diff: Dict[str, Any], prediction: Dict[str, Any]) -> str:
        micro = prediction.get("micro_state", "?")
        if not diff:
            return (f"No change: {micro} keeps phase {new['phase']} "
                    f"({new['phase_name']}) at {new['interaction_level']} interaction")
        bits = []
        if old.get("phase") != new.get("phase"):
            bits.append(f"Phase {old.get('phase')}->{new['phase']}")
        if "interaction_level" in diff:
            bits.append(f"interaction {diff['interaction_level']['from']}"
                        f"->{diff['interaction_level']['to']}")
        if "banner" in diff:
            bits.append(f"banner -> {diff['banner']['to']!r}")
        if "cve_profile" in diff and diff["cve_profile"]["to"]:
            bits.append(f"trending CVE {diff['cve_profile']['to']} applied")
        if new.get("alert") and not old.get("alert"):
            bits.append("EXTERNAL ALERT armed")
        head = ", ".join(bits) if bits else "config updated"
        return (f"{head}: {micro} detected, switching to "
                f"{new['interaction_level']} interaction")

    # -- public API --------------------------------------------------------
    def apply(self, prediction: Dict[str, Any],
              session: Optional[Dict[str, Any]] = None,
              *, write: bool = True) -> Dict[str, Any]:
        """Compute, persist and log the config implied by one MT3 prediction.

        Returns the `honeypot_action` block the pipeline writes to its results.
        """
        with self._lock:
            previous = self.load_active()
            new = self.build_config(prediction, session)
            diff = self._diff(previous, new)
            changed = bool(diff)
            reason = self._reason(previous, new, diff, prediction)

            new["updated_at"] = _utcnow()
            new["reason"] = reason

            if write:
                self.config_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.config_path.with_suffix(".json.tmp")
                with tmp.open("w", encoding="utf-8") as fh:
                    json.dump(new, fh, indent=2, default=str)
                tmp.replace(self.config_path)      # atomic: readers never see half a config

            if changed:
                self.changes += 1
                log.info("%s", reason)
                if write:
                    self._log_change(previous, new, diff, reason, prediction, session)
            else:
                log.debug("%s", reason)

            return {
                "previous_config": _summary(previous),
                "new_config": _summary(new),
                "changed": changed,
                "diff": diff,
                "reason": reason,
                "alert_fired": bool(new.get("alert")) and not bool(previous.get("alert")),
            }

    def _log_change(self, previous, new, diff, reason, prediction, session) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": _utcnow(),
            "reason": reason,
            "diff": diff,
            "trigger": {
                "session_id": (session or {}).get("session_id"),
                "src_ip": (session or {}).get("src_ip"),
                "micro_state": prediction.get("micro_state"),
                "phase": prediction.get("phase"),
                "confidence": prediction.get("confidence"),
            },
            "previous_config": _summary(previous),
            "new_config": _summary(new),
        }
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")

    def reset(self) -> Dict[str, Any]:
        """Return the honeypot to the day-zero low-interaction posture."""
        with self._lock:
            cfg = self.default_config()
            cfg["updated_at"] = _utcnow()
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with self.config_path.open("w", encoding="utf-8") as fh:
                json.dump(cfg, fh, indent=2, default=str)
            return cfg

    def recent_changes(self, limit: int = 20) -> List[dict]:
        if not self.log_path.exists():
            return []
        rows = []
        with self.log_path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        continue
        return rows[-limit:][::-1]


def _summary(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Compact view of a config for logs and API responses."""
    keys = ("interaction_level", "honeypot_target", "phase", "phase_name",
            "micro_state", "banner", "filesystem", "fake_credentials_visible",
            "fake_sensitive_files", "fake_ssh_keys", "alert", "response_delay_ms")
    out = {k: cfg.get(k) for k in keys}
    prof = cfg.get("cve_profile")
    out["cve_id"] = prof.get("cve_id") if prof else None
    return out


# Module-level singleton + the function the post-session pipeline discovers.
configurator = HoneypotConfigurator()


def apply_prediction(prediction: Dict[str, Any],
                     session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Entry point called by traffic_gateway.post_session_pipeline."""
    return configurator.apply(prediction, session)
