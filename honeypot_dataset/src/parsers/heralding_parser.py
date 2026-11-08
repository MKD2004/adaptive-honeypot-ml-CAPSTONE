"""
src/parsers/heralding_parser.py

Heralding (credential-capture honeypot) -> the session contract.

MULTI_HONEYPOT.md Phase 2. Heralding answers on HTTP/HTTPS/FTP/Telnet/SSH/POP3/
IMAP/SMTP/VNC/MySQL/Postgres/SOCKS5, accepts any credentials, and records every
username/password pair. It is the cheapest way to get a second protocol into the
pipeline, and it maps onto micro-states the taxonomy already has.

Three structural differences from Cowrie, all handled here:

1. ONE LINE IS A WHOLE SESSION. Cowrie streams many events and the pipeline
   groups them until `cowrie.session.closed`. Heralding's `log_session.json` is
   jsonlines with one complete record per session, carrying `session_ended`.
   So `LogSource.is_closed` is effectively "is this record final", and `build`
   receives a one-element list.

2. NAIVE UTC TIMESTAMPS. Heralding writes `datetime.utcnow().strftime(
   '%Y-%m-%d %H:%M:%S.%f')` -- no 'T', no 'Z', no offset. Feeding that to
   cowrie_parser.to_ts() makes `fromisoformat` read it as LOCAL time, shifting
   every session by the machine's UTC offset (measured: 19,800 s on this box).
   That would corrupt `t_start`, and `peer_attribution.resolve_peer_ip()` matches
   the gateway log BY CONNECT TIME, so attribution would silently fail. Hence
   `_utc_ts()` below, which is explicit about the timezone.

3. NO COMMANDS, ONLY CREDENTIALS. There is no shell, so `n_commands` is always 0
   and there is no command text. What `command_text` should carry instead is a
   real decision -- see `credentials_as_payload` below.

`dst_port` IS read from the log here, unlike cowrie_parser where the default must
stay 22 (see its docstring). The reason that constraint does not apply: MT3 was
trained with dst_port flattened to 22 for *Cowrie* sessions, and it has never
seen a Heralding session at all, so there is no trained constant to drift away
from. Reporting the true port is what lets honeypot_target_for() route it.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

log = logging.getLogger("heralding_parser")

__all__ = [
    "HERALDING_SESSION_GLOB", "DEFAULT_CREDENTIALS",
    "is_session_final", "build_record", "label_session",
]

HERALDING_SESSION_GLOB = "log_session.json*"

# Heralding's own timestamp format: naive UTC.
_TS_FMT = "%Y-%m-%d %H:%M:%S.%f"

# Credential pairs that mean "trying the factory defaults" rather than guessing.
# Deliberately short and uncontroversial -- a long list would start labelling
# ordinary dictionary guesses as ACCESS_DEFAULT_CRED.
DEFAULT_CREDENTIALS = frozenset({
    ("root", "root"), ("root", "toor"), ("root", ""), ("root", "admin"),
    ("admin", "admin"), ("admin", "password"), ("admin", ""), ("admin", "1234"),
    ("administrator", "administrator"), ("administrator", "password"),
    ("user", "user"), ("guest", "guest"), ("guest", ""),
    ("pi", "raspberry"), ("ubnt", "ubnt"), ("cisco", "cisco"),
    ("oracle", "oracle"), ("postgres", "postgres"), ("mysql", "mysql"),
    ("test", "test"), ("support", "support"), ("service", "service"),
})

# Heralding protocol -> (micro-state for a brute-force burst, label for a bare
# connect with no auth). Only protocols Phase 2 actually enables are mapped;
# anything else falls through to the generic pair below.
_BRUTE_BY_PROTOCOL: Dict[str, str] = {
    "http": "ACCESS_BRUTE_HTTP",
    "https": "ACCESS_BRUTE_HTTP",
    "ssh": "ACCESS_BRUTE_SSH",
    "telnet": "ACCESS_BRUTE_SSH",     # nearest available: remote-shell credential guessing
    "ftp": "ACCESS_BRUTE_HTTP",       # nearest available: service credential guessing
    "pop3": "ACCESS_BRUTE_HTTP",
    "pop3s": "ACCESS_BRUTE_HTTP",
    "imap": "ACCESS_BRUTE_HTTP",
    "imaps": "ACCESS_BRUTE_HTTP",
    "smtp": "ACCESS_BRUTE_HTTP",
    "vnc": "ACCESS_BRUTE_SSH",
    "socks5": "ACCESS_BRUTE_HTTP",
}

# Protocols with NO honest home in the frozen 45-class taxonomy. MULTI_HONEYPOT.md
# section 7.1: there is no SQL-injection or database-auth micro-state, so a
# database session can only be mapped to a neighbour. Phase 2 keeps Heralding's
# MySQL/Postgres listeners OFF for exactly this reason; if one shows up anyway we
# label it and say so loudly rather than pretending the mapping is clean.
_TAXONOMY_GAP_PROTOCOLS = frozenset({"mysql", "postgres", "postgresql", "mssql"})

_GENERIC_BRUTE = "ACCESS_BRUTE_HTTP"
_BARE_CONNECT = "RECON_IP_SCAN"

# How many distinct usernames against how few passwords counts as spraying one
# credential over many accounts (stuffing) rather than guessing one account.
_STUFFING_MIN_USERS = 3

# Below this many distinct usernames, a passwordless burst is not enumeration.
_ENUM_MIN_USERS = 2


def _utc_ts(s: Any) -> float:
    """Heralding's naive-UTC timestamp -> unix epoch seconds. 0.0 if unparseable.

    The explicit `tzinfo=utc` is the whole point: `datetime.fromisoformat` would
    accept this string and silently treat it as local time.
    """
    text = str(s or "").strip()
    if not text:
        return 0.0
    for fmt in (_TS_FMT, "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    # last resort: an ISO string with its own offset
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        log.debug("unparseable heralding timestamp: %r", text)
        return 0.0


def is_session_final(record: Dict[str, Any]) -> bool:
    """Has Heralding finished with this session?

    `session_ended` is written False on the interim record and True on the final
    one, so this is the close signal. A record missing the field is treated as
    final -- better to classify once than to wait forever for a flag that is not
    coming.
    """
    return bool(record.get("session_ended", True))


def _auth_pairs(record: Dict[str, Any]) -> List[tuple]:
    """(username, password) pairs, lowercased, from `auth_attempts`."""
    pairs: List[tuple] = []
    for att in record.get("auth_attempts") or []:
        if not isinstance(att, dict):
            continue
        u = str(att.get("username") or "")
        p = str(att.get("password") or "")
        pairs.append((u.strip().lower(), p.strip().lower()))
    return pairs


def label_session(record: Dict[str, Any]) -> str:
    """Rule-based micro-state for one Heralding session.

    This is the labelling plan from MULTI_HONEYPOT.md section 7.6, and it exists
    so there is something to compare MT3 against on unlabelled real captures.
    It is a HEURISTIC, not ground truth: agreement with it is agreement with our
    own rules, and must be reported in those words, never as accuracy.

    Precedence is deliberate -- most specific evidence first:
      1. no auth at all            -> RECON_IP_SCAN     (connected and left)
      2. >=2 usernames, no passwords -> RECON_USER_ENUM  (probing which accounts exist)
         (ONE username with no password is a passwordless default, not enum)
      3. many users, >=1 password each, few distinct passwords -> ACCESS_CRED_STUFF
      4. any factory-default pair   -> ACCESS_DEFAULT_CRED
      5. otherwise                  -> per-protocol brute force
    """
    proto = str(record.get("protocol") or "").strip().lower()
    pairs = _auth_pairs(record)

    if not pairs:
        return _BARE_CONNECT

    users = {u for u, _ in pairs if u}
    passwords = {p for _, p in pairs if p}

    # Enumeration means probing SEVERAL accounts to see which exist. A single
    # username with an empty password is not enumeration -- it is someone trying
    # a passwordless default (plenty of appliances ship root with no password),
    # so it must fall through to the ACCESS_DEFAULT_CRED check below.
    if len(users) >= _ENUM_MIN_USERS and not passwords:
        return "RECON_USER_ENUM"

    if len(users) >= _STUFFING_MIN_USERS and len(passwords) < len(users):
        return "ACCESS_CRED_STUFF"

    if any(pair in DEFAULT_CREDENTIALS for pair in pairs):
        return "ACCESS_DEFAULT_CRED"

    if proto in _TAXONOMY_GAP_PROTOCOLS:
        log.warning(
            "heralding session on %s: the 45-class taxonomy has no database-auth "
            "micro-state, labelling as %s (MULTI_HONEYPOT.md 7.1). Phase 2 should "
            "keep this listener disabled.", proto, _GENERIC_BRUTE)

    return _BRUTE_BY_PROTOCOL.get(proto, _GENERIC_BRUTE)


def build_record(records: Iterable[Dict[str, Any]], *,
                 protocol: Optional[str] = None,
                 dst_port: Optional[int] = None,
                 credentials_as_payload: bool = True,
                 sensor: str = "heralding") -> Optional[Dict[str, Any]]:
    """One Heralding session -> a record satisfying src.parsers.session_contract.

    Takes an iterable for interface parity with cowrie_parser.build_record (the
    pipeline hands `LogSource.build` a list of events); Heralding puts one whole
    session on a line, so the LAST element wins -- that is the final record, the
    one with `session_ended` true and the complete `auth_attempts`.

    `protocol` / `dst_port` override what the log says. Unlike cowrie_parser,
    the log is trusted by default: MT3 never trained on Heralding data, so there
    is no flattened constant to preserve.

    `credentials_as_payload` decides what lands in `command_text`:
      True  (default) the captured pairs as "user:pass ; user:pass", so Group C
            (payload stats: entropy, char fractions, token counts) sees the real
            attack content. Group D MUST be zero-filled regardless -- Phase 1b
            measured the shell-fitted PCA keeping only 71.4% of credential-text
            variance, and settled on zero-fill for every non-SSH protocol.
      False "[no commands]", exactly as Cowrie writes for a session that opened
            a shell and typed nothing. Use this if Group C's distribution for
            credential text turns out to matter; it has NOT been measured the way
            Group D was, which is an open item in MULTI_HONEYPOT.md.
    """
    items = [r for r in (records or []) if isinstance(r, dict)]
    if not items:
        return None
    record = items[-1]

    sid = str(record.get("session_id") or "")
    if not sid:
        return None

    t_start = _utc_ts(record.get("timestamp"))
    try:
        duration = max(0.0, float(record.get("duration") or 0.0))
    except (TypeError, ValueError):
        duration = 0.0
    t_end = t_start + duration

    pairs = _auth_pairs(record)
    auth_ts = sorted(t for t in (_utc_ts(a.get("timestamp"))
                                 for a in (record.get("auth_attempts") or [])
                                 if isinstance(a, dict)) if t > 0.0)

    # num_auth_attempts is Heralding's own count; fall back to what we can see.
    try:
        n_auth = int(record.get("num_auth_attempts", len(pairs)))
    except (TypeError, ValueError):
        n_auth = len(pairs)

    if credentials_as_payload and pairs:
        command_text = " ; ".join(f"{u}:{p}" for u, p in pairs)
    else:
        command_text = "[no commands]"

    label = label_session(record)
    event_ts = [t for t in ([t_start] + auth_ts + [t_end]) if t > 0.0]

    proto = str(protocol if protocol is not None
                else (record.get("protocol") or "")).strip().lower() or "http"
    try:
        port = int(dst_port if dst_port is not None
                   else (record.get("destination_port") or 0))
    except (TypeError, ValueError):
        port = 0
    if not (0 < port <= 65535):
        port = 80 if proto in ("http", "https") else 0

    return {
        "session_id":           sid,
        "src_ip":               str(record.get("source_ip") or ""),
        "src_port":             int(record.get("source_port") or 0),
        "dst_port":             port,
        "protocol":             proto,
        "t_start":              t_start,
        "t_end":                t_end,
        "t_first_auth":         auth_ts[0] if auth_ts else t_start,
        "t_first_cmd":          t_start,          # no shell: no first command
        "event_timestamps":     event_ts or [t_start],
        "session_duration_s":   max(0.0, t_end - t_start),
        "n_events":             1 + n_auth,
        "n_commands":           0,                # Heralding has no shell
        "login_attempts":       n_auth,
        "command_text":         command_text,
        "n_downloads":          0,
        "bytes_in":             0,                # not reported by Heralding
        "bytes_out":            0,
        "micro_state":          label,
        "micro_state_sequence": label,
        "source":               "heralding",
        "associated_cve":       "",
        "sensor":               str(record.get("sensor") or sensor),
    }
