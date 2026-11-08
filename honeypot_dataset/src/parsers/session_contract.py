"""
src/parsers/session_contract.py

The shape of a parsed session, written down and enforceable.

Every parser that feeds the live pipeline -- cowrie_parser today, Heralding /
Dionaea / TANNER later (MULTI_HONEYPOT.md Phases 2-4) -- must emit a flat dict
matching this contract. Until Phase 1 there was exactly one parser, so the
contract was whatever `cowrie_parser.build_record()` happened to return and
nothing could disagree with it. With a second parser that is no longer true, and
a mismatch does not raise: the extractors call `session.get(key, default)`
everywhere, so a missing or misspelled key silently becomes a default and 1+ of
the 128 features goes quietly wrong.

Hence `validate()`. A document drifts; a test fails.

Two groups of keys:

  REQUIRED  the 22 keys build_record() returns. A parser must supply all of them.
  OPTIONAL  keys the extractors read but build_record() never sets, so they fall
            back to a default today. A parser MAY supply them to light up
            features that are currently dead for its protocol -- e.g. a TLS-aware
            web honeypot can fill ja3_hash / tls_version / sni_hostname and give
            Group F (features 120-127) something real to work with.

Nothing here changes the feature arithmetic. It only checks that what reaches
`extract_all()` is the shape it expects.
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Tuple, Type, Union

__all__ = [
    "REQUIRED_FIELDS", "OPTIONAL_FIELDS", "ALL_FIELDS",
    "validate", "assert_valid", "describe",
]

_Num = (int, float)

# key -> (accepted types, one-line meaning)
REQUIRED_FIELDS: Dict[str, Tuple[Union[Type, Tuple[Type, ...]], str]] = {
    "session_id":           (str,   "parser-unique id for this session"),
    "src_ip":               (str,   "attacker address as the honeypot saw it"),
    "src_port":             (int,   "attacker source port"),
    "dst_port":             (int,   "port the honeypot answered on -- see the note below"),
    "protocol":             (str,   "ssh | http | https | mysql | postgres | ..."),
    "t_start":              (_Num,  "unix ts of the first event"),
    "t_end":                (_Num,  "unix ts of the last event"),
    "t_first_auth":         (_Num,  "unix ts of the first auth attempt (else t_start)"),
    "t_first_cmd":          (_Num,  "unix ts of the first command (else t_start)"),
    "event_timestamps":     (list,  "unix ts of every event, ascending"),
    "session_duration_s":   (_Num,  "t_end - t_start, never negative"),
    "n_events":             (int,   "number of events in the session"),
    "n_commands":           (int,   "number of commands issued"),
    "login_attempts":       (int,   "auth attempts, successful or not"),
    "command_text":         (str,   "commands joined by ' ; ', or '[no commands]'"),
    "n_downloads":          (int,   "files the attacker fetched"),
    "bytes_in":             (int,   "bytes from attacker to honeypot"),
    "bytes_out":            (int,   "bytes from honeypot to attacker"),
    "micro_state":          (str,   "rule-based label -- NOT MT3's answer, see note"),
    "micro_state_sequence": (str,   "comma-joined rule labels, for the KCVR check"),
    "source":               (str,   "provenance, e.g. cowrie_real | heralding"),
    "associated_cve":       (str,   "CVE id if one applies, else ''"),
}

# Keys the extractors read but build_record() never sets. Supplying them is how a
# new parser gives its protocol's features real values instead of defaults.
OPTIONAL_FIELDS: Dict[str, Tuple[Union[Type, Tuple[Type, ...]], str]] = {
    "sensor":             (str,   "the honeypot's own name -- which box saw this session. "
                                  "Cowrie writes it on every event (sensor_name in cowrie.cfg); "
                                  "a new parser should set it so results are attributable"),
    "payload_hex":        (str,   "raw payload hex -- Group C entropy/n-grams"),
    "src_country":        (str,   "ISO country code -- Group F geo risk"),
    "ja3_hash":           (str,   "JA3 TLS fingerprint -- Group F"),
    "tls_version":        (str,   "negotiated TLS version -- Group F"),
    "sni_hostname":       (str,   "TLS SNI host -- Group F"),
    "cipher_suites":      (list,  "offered cipher suites -- Group F"),
    "packets_in":         (int,   "packet count in -- Group B"),
    "packets_out":        (int,   "packet count out -- Group B"),
    "pkt_sizes_in":       (list,  "per-packet sizes in -- Group B"),
    "pkt_sizes_out":      (list,  "per-packet sizes out -- Group B"),
    "tcp_flags":          (list,  "observed TCP flags -- Group B"),
    "unique_dst_ports":   (int,   "distinct ports this source touched -- Group B"),
    "seen_before":        (bool,  "has this source been seen before -- Group E"),
    "cve_refs_count":     (int,   "CVE reference count -- Group E"),
    "exploit_db_count":   (int,   "Exploit-DB entries -- Group E"),
    "has_metasploit":     (bool,  "a Metasploit module exists -- Group E"),
    "has_nuclei":         (bool,  "a Nuclei template exists -- Group E"),
    "kev_date_added":     (str,   "CISA KEV date, '' if not listed -- Group E"),
}

ALL_FIELDS: Dict[str, Tuple[Union[Type, Tuple[Type, ...]], str]] = {
    **REQUIRED_FIELDS, **OPTIONAL_FIELDS,
}

# Keys that must never carry a value the extractors cannot use. np.nan_to_num
# saves the arrays, but a None reaching arithmetic raises TypeError instead.
_NUMERIC_KEYS = tuple(
    k for k, (t, _) in REQUIRED_FIELDS.items()
    if t is int or t is _Num
)


def validate(record: Mapping[str, Any], *, allow_extra: bool = True) -> List[str]:
    """Return a list of problems with `record`. Empty list means it conforms.

    Deliberately returns problems rather than raising, so a caller can log and
    skip one malformed session instead of killing a long-running watcher.
    """
    problems: List[str] = []

    if not isinstance(record, Mapping):
        return [f"record is {type(record).__name__}, not a mapping"]

    for key, (types, _) in REQUIRED_FIELDS.items():
        if key not in record:
            problems.append(f"missing required key: {key}")
            continue
        val = record[key]
        if val is None:
            problems.append(f"{key} is None")
            continue
        # bool is an int subclass; keep them distinguishable
        if types is int and isinstance(val, bool):
            problems.append(f"{key} is bool, expected int")
            continue
        if not isinstance(val, types):
            want = getattr(types, "__name__", None) or "/".join(t.__name__ for t in types)
            problems.append(f"{key} is {type(val).__name__}, expected {want}")

    for key, (types, _) in OPTIONAL_FIELDS.items():
        if key in record and record[key] is not None:
            if not isinstance(record[key], types):
                want = getattr(types, "__name__", None) or "/".join(t.__name__ for t in types)
                problems.append(f"{key} is {type(record[key]).__name__}, expected {want}")

    if not allow_extra:
        for key in record:
            if key not in ALL_FIELDS:
                problems.append(f"unexpected key: {key}")

    # value-level checks the type system cannot express
    if isinstance(record.get("protocol"), str) and not record["protocol"].strip():
        problems.append("protocol is empty -- honeypot_target_for() needs it set")
    dp = record.get("dst_port")
    if isinstance(dp, int) and not isinstance(dp, bool) and not (0 < dp <= 65535):
        problems.append(f"dst_port {dp} out of range 1-65535")
    dur = record.get("session_duration_s")
    if isinstance(dur, _Num) and not isinstance(dur, bool) and dur < 0:
        problems.append(f"session_duration_s is negative ({dur})")
    for key in _NUMERIC_KEYS:
        val = record.get(key)
        if isinstance(val, float) and val != val:          # NaN
            problems.append(f"{key} is NaN")

    return problems


def assert_valid(record: Mapping[str, Any], *, where: str = "record") -> None:
    """Raise ValueError listing every problem. For tests and parser self-checks."""
    problems = validate(record)
    if problems:
        raise ValueError(f"{where} violates the session contract:\n  - "
                         + "\n  - ".join(problems))


def describe() -> str:
    """Human-readable contract, for docs and `python -m`-style inspection."""
    lines = [f"REQUIRED ({len(REQUIRED_FIELDS)} keys)"]
    for k, (t, doc) in REQUIRED_FIELDS.items():
        name = getattr(t, "__name__", None) or "/".join(x.__name__ for x in t)
        lines.append(f"  {k:<22} {name:<10} {doc}")
    lines.append(f"\nOPTIONAL ({len(OPTIONAL_FIELDS)} keys, defaulted if absent)")
    for k, (t, doc) in OPTIONAL_FIELDS.items():
        name = getattr(t, "__name__", None) or "/".join(x.__name__ for x in t)
        lines.append(f"  {k:<22} {name:<10} {doc}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(describe())
