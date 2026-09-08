"""
src/parsers/cowrie_parser.py

Standalone Cowrie JSON-log parser, extracted verbatim from notebook 01
(01_process_real_data.ipynb cell 3) so the live gateway pipeline and the
frozen dataset build produce byte-identical session records from the same
events. Behaviour is intentionally unchanged -- do not "improve" it here, or
live inference drifts away from what MT3 was trained on.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

# ── Cowrie event type -> micro-state label ───────────────────────────────────
# NOTE (parity with notebook 01): "cowrie.direct-tcpip.request" is present in
# this map but build_record() never consults EVENT_MAP, so those events do not
# produce LATERAL_SSH_SPREAD. Kept as-is deliberately -- see ERRORS.md
# ("EVENT_MAP dead code in notebook 01").
EVENT_MAP: Dict[str, str] = {
    "cowrie.session.connect":       "RECON_IP_SCAN",
    "cowrie.login.failed":          "ACCESS_BRUTE_SSH",
    "cowrie.login.success":         "ACCESS_BRUTE_SSH",
    "cowrie.session.file_download": "EXEC_WGET_EXEC",
    "cowrie.session.file_upload":   "EXFIL_SCP_DATA",
    "cowrie.direct-tcpip.request":  "LATERAL_SSH_SPREAD",
}

COMMAND_PATTERNS = [
    (re.compile(r"\b(uname|hostname|id|whoami|cat /proc)\b"),      "DISC_ENV_PROBE"),
    (re.compile(r"\b(netstat|ss -|ip addr|ifconfig)\b"),           "DISC_NETSTAT_SCAN"),
    (re.compile(r"\bps\s"),                                        "DISC_PROC_ENUM"),
    (re.compile(r"find.*-perm.*4000|-perm.*-u=s"),                 "DISC_SUID_HUNT"),
    (re.compile(r"\b(wget|curl)\b.*http"),                         "EXEC_WGET_EXEC"),
    (re.compile(r"\bpython[23]?\b"),                               "EXEC_PYTHON_SCRIPT"),
    (re.compile(r"\bperl\b"),                                      "EXEC_PERL_SCRIPT"),
    (re.compile(r"bash.*-i.*>&|/dev/tcp|nc.*-e|ncat"),             "EXEC_CURL_BASH"),
    (re.compile(r"\bsudo\b"),                                      "PRIVESC_SUDO_ABUSE"),
    (re.compile(r"\bcrontab\b"),                                   "PERSIST_CRONTAB"),
    (re.compile(r"authorized_keys"),                               "PERSIST_SSH_KEY_ADD"),
    (re.compile(r"history\s*-c|>\s*/dev/null|rm.*\.bash_history"), "EVASION_HIST_ERASE"),
    (re.compile(r"rm.*(/var/log|/var/run)"),                       "EVASION_LOG_WIPE"),
    (re.compile(r"\bscp\b"),                                       "EXFIL_SCP_DATA"),
    (re.compile(r"\btar\b.*-czf"),                                 "EXFIL_STAGING_TAR"),
]

SESSION_CLOSED_EVENT = "cowrie.session.closed"


def label_command(cmd: str) -> str:
    """Map one shell command to a micro-state label (notebook 01 rules)."""
    cmd_l = cmd.lower()
    for pattern, label in COMMAND_PATTERNS:
        if pattern.search(cmd_l):
            return label
    return "EXEC_SHELL_OPEN"


def to_ts(s: str) -> float:
    """Cowrie ISO timestamp -> unix epoch seconds (0.0 when unparseable)."""
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def parse_cowrie_file(fpath: Path) -> List[List[dict]]:
    """Group every line of a Cowrie JSON log into per-session event lists."""
    sessions: Dict[str, List[dict]] = defaultdict(list)
    with open(fpath, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                sid = ev.get("session", "")
                if sid:
                    sessions[sid].append(ev)
            except Exception:
                continue
    return list(sessions.values())


def build_record(events: List[dict]) -> Optional[dict]:
    """Collapse one session's events into the flat dict the extractors expect."""
    if not events:
        return None
    events.sort(key=lambda e: e.get("timestamp", ""))
    first, last = events[0], events[-1]

    t_start = to_ts(first.get("timestamp", ""))
    t_end = to_ts(last.get("timestamp", ""))
    ts_list = [to_ts(e.get("timestamp", "")) for e in events if e.get("timestamp")]

    cmds: List[str] = []
    downloads: List[str] = []
    seq: List[str] = []
    logins = 0
    t_first_auth = t_first_cmd = None

    for ev in events:
        etype = ev.get("eventid", "")
        if etype in ("cowrie.login.failed", "cowrie.login.success"):
            logins += 1
            seq.append("ACCESS_BRUTE_SSH")
            if t_first_auth is None:
                t_first_auth = to_ts(ev.get("timestamp", ""))
        elif etype == "cowrie.command.input":
            cmd = ev.get("input", "")
            cmds.append(cmd)
            seq.append(label_command(cmd))
            if t_first_cmd is None:
                t_first_cmd = to_ts(ev.get("timestamp", ""))
        elif etype == "cowrie.session.file_download":
            downloads.append(ev.get("url", ""))
            seq.append("EXEC_WGET_EXEC")
        elif etype == "cowrie.session.file_upload":
            seq.append("EXFIL_SCP_DATA")

    if not seq:
        seq = ["RECON_IP_SCAN"]
    meaningful = [s for s in seq if not s.startswith("RECON")]
    label = meaningful[-1] if meaningful else seq[-1]

    return {
        "session_id":           first.get("session", ""),
        "src_ip":               first.get("src_ip", ""),
        "src_port":             first.get("src_port", 0),
        "dst_port":             22,
        "protocol":             "ssh",
        "t_start":              t_start,
        "t_end":                t_end,
        "t_first_auth":         t_first_auth or t_start,
        "t_first_cmd":          t_first_cmd or t_start,
        "event_timestamps":     ts_list,
        "session_duration_s":   max(0.0, t_end - t_start),
        "n_events":             len(events),
        "n_commands":           len(cmds),
        "login_attempts":       logins,
        "command_text":         " ; ".join(cmds) if cmds else "[no commands]",
        "n_downloads":          len(downloads),
        "bytes_in":             sum(e.get("size", 0) for e in events if "size" in e),
        "bytes_out":            0,
        "micro_state":          label,
        "micro_state_sequence": ",".join(seq),
        "source":               "cowrie_real",
        "associated_cve":       "",
    }


# ── Live-tailing helpers (used by the post-session pipeline) ─────────────────

def is_session_closed(events: Iterable[dict]) -> bool:
    """True once a `cowrie.session.closed` event has arrived for the session."""
    return any(e.get("eventid", "") == SESSION_CLOSED_EVENT for e in events)


def parse_lines(lines: Iterable[str]) -> Dict[str, List[dict]]:
    """Group raw JSON log lines by session id (for incremental tailing)."""
    sessions: Dict[str, List[dict]] = defaultdict(list)
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        sid = ev.get("session", "")
        if sid:
            sessions[sid].append(ev)
    return dict(sessions)


def parse_closed_sessions(fpath: Path) -> List[dict]:
    """Parse a Cowrie log and return records for CLOSED sessions only."""
    out = []
    for events in parse_cowrie_file(fpath):
        if not is_session_closed(events):
            continue
        rec = build_record(events)
        if rec is not None:
            out.append(rec)
    return out
