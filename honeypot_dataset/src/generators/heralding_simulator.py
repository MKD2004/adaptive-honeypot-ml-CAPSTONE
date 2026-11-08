"""
src/generators/heralding_simulator.py

Synthetic Heralding sessions, for retraining MT3 on credential-honeypot traffic.

WHY THIS EXISTS. MT3 agrees with the rule labeller on 0 of 6 Heralding scenarios
and is confidently wrong (HONEYPOT_AUDIT.md PART 7): a bare connect with no auth
attempt comes back DISC_NETSTAT_SCAN at confidence 0.998. The cause is not the
model's capacity, it is that a Heralding-shaped feature vector is nothing like
anything in the training set -- no shell, no byte counts, no packet sizes, no TCP
flags, no TLS -- so most of the 128 features are defaults and MT3 extrapolates.
The fix is training rows of that shape. This generates them.

SCOPE AND BOUNDARIES.

  - Writes `log_session.json`-format records, i.e. exactly what the real
    Heralding emits, so they go through the SAME `heralding_parser.build_record`
    as live traffic. Nothing here knows about features; the real extractors do
    that. If the parser is wrong, this is wrong in the same way, which is the
    point.
  - Does NOT touch `data/final/`. That dataset is frozen and every published
    number depends on it (CLAUDE.md). Output goes somewhere separate and the
    retrain is a separate model decision -- see DECISIONS.md.
  - Does NOT edit the existing generators. `kill_chain_simulator.py` models
    multi-state shell campaigns; a Heralding session is a single credential
    burst against one service, so the shapes do not overlap.

LABEL HONESTY. Labels come from `heralding_parser.label_session()`, the same
heuristic that labels live traffic. So the retrained model learns to agree with
our rules, not with ground truth. That is a real limitation and must be stated:
it makes MT3 a fast approximation of the labeller on this protocol, which is
worth having (it generalises to variants the rules miss) but is not independent
evidence. MULTI_HONEYPOT.md section 7.6.
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

__all__ = ["SCENARIOS", "generate_session", "generate_sessions", "write_jsonlines"]

# Heralding's own timestamp format (naive UTC) -- see heralding_parser._utc_ts.
_TS_FMT = "%Y-%m-%d %H:%M:%S.%f"

# Services Phase 2 enables. MySQL/Postgres are deliberately absent: the 45-class
# taxonomy has no database-auth micro-state (MULTI_HONEYPOT.md 7.1), so training
# rows for them would be labelled against a class that does not fit.
_SERVICES: List[Tuple[str, int]] = [
    ("http", 80), ("http", 8080), ("https", 443), ("https", 8443),
    ("ftp", 21), ("telnet", 23), ("smtp", 25), ("imap", 143), ("pop3", 110),
]

_USERNAMES = [
    "admin", "root", "administrator", "user", "test", "guest", "oracle",
    "ubuntu", "pi", "deploy", "support", "service", "web", "ftpuser", "mail",
    "info", "backup", "operator", "manager", "dev", "jenkins", "git", "tomcat",
    "alice", "bob", "carol", "dave", "erin", "frank", "grace",
]

_WEAK_PASSWORDS = [
    "123456", "password", "admin", "12345678", "qwerty", "letmein", "welcome",
    "monkey", "dragon", "football", "iloveyou", "sunshine", "princess",
    "changeme", "passw0rd", "P@ssw0rd", "Summer2026", "Winter2026", "hunter2",
]

def _default_pairs() -> List[Tuple[str, str]]:
    """The labeller's OWN default-credential set -- never a copy of it.

    An earlier version duplicated this list here, and the generator's copy was a
    subset of the parser's. The brute_force scenario filtered against the local
    copy, let ("admin", "password") through, and `label_session()` then called it
    ACCESS_DEFAULT_CRED. `generate_sessions(verify_labels=True)` caught it. One
    source of truth, imported.
    """
    import sys
    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from src.parsers.heralding_parser import DEFAULT_CREDENTIALS
    return sorted(DEFAULT_CREDENTIALS)

# scenario -> the micro-state heralding_parser.label_session() should assign.
# Asserted at generation time, so a drift between generator and labeller is
# caught here rather than silently poisoning the training set.
SCENARIOS: Dict[str, str] = {
    "bare_connect":      "RECON_IP_SCAN",
    "user_enum":         "RECON_USER_ENUM",
    "cred_stuffing":     "ACCESS_CRED_STUFF",
    "default_creds":     "ACCESS_DEFAULT_CRED",
    "brute_force":       "ACCESS_BRUTE_HTTP",
    "brute_force_shell": "ACCESS_BRUTE_SSH",
}


def _random_public_ip(rng: random.Random) -> str:
    """An address from the documentation/test ranges, never a routable one."""
    block = rng.choice([
        (192, 0, 2), (198, 51, 100), (203, 0, 113),      # RFC 5737 docs ranges
    ])
    return f"{block[0]}.{block[1]}.{block[2]}.{rng.randint(1, 254)}"


def _ts(base_epoch: float, offset: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(base_epoch + offset, timezone.utc).strftime(_TS_FMT)


def _attempts_for(scenario: str, rng: random.Random) -> List[Tuple[str, str]]:
    """The (username, password) sequence that makes the labeller pick `scenario`."""
    if scenario == "bare_connect":
        return []

    if scenario == "user_enum":
        # usernames probed with no password at all
        n = rng.randint(3, 12)
        return [(rng.choice(_USERNAMES), "") for _ in range(n)]

    if scenario == "cred_stuffing":
        # one (or very few) passwords sprayed across many distinct accounts
        users = rng.sample(_USERNAMES, rng.randint(4, 12))
        pw = rng.choice(_WEAK_PASSWORDS)
        pairs = [(u, pw) for u in users]
        if rng.random() < 0.3:                 # occasionally a second password
            pairs.append((rng.choice(users), rng.choice(_WEAK_PASSWORDS)))
        return pairs

    if scenario == "default_creds":
        # Skip empty-password defaults here: with >=2 usernames and no passwords
        # the labeller reads a passwordless burst as RECON_USER_ENUM, so mixing
        # them in makes the scenario ambiguous. The single-empty-password case is
        # covered by the labeller's own precedence and its unit tests.
        pairs = [rng.choice([pr for pr in _default_pairs() if pr[1]])]
        # a default pair may sit inside a short burst of guesses
        for _ in range(rng.randint(0, 3)):
            pairs.append((pairs[0][0], rng.choice(_WEAK_PASSWORDS)))
        return pairs

    # brute force: one or two accounts, many passwords, none of them a default
    users = [rng.choice(_USERNAMES)] if rng.random() < 0.75 else rng.sample(_USERNAMES, 2)
    n = rng.randint(3, 40)
    banned = {(a.lower(), b.lower()) for a, b in _default_pairs()}
    pairs: List[Tuple[str, str]] = []
    guard = 0
    while len(pairs) < n and guard < n * 50:
        guard += 1
        u = rng.choice(users)
        p = rng.choice(_WEAK_PASSWORDS) + (str(rng.randint(0, 999)) if rng.random() < 0.5 else "")
        if (u.strip().lower(), p.strip().lower()) in banned:
            continue                           # must not read as ACCESS_DEFAULT_CRED
        pairs.append((u, p))
    if len(pairs) < 3:                         # pathological draw; keep it a brute force
        pairs.extend((users[0], f"zz{rng.randint(1000, 9999)}") for _ in range(3 - len(pairs)))
    return pairs


def generate_session(scenario: str, rng: random.Random,
                     base_epoch: float = 1_793_000_000.0) -> Dict:
    """One synthetic `log_session.json` record for `scenario`."""
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}; expected one of {sorted(SCENARIOS)}")

    if scenario == "brute_force_shell":
        protocol, port = rng.choice([("ssh", 22), ("ssh", 2222), ("telnet", 23)])
    elif scenario == "brute_force":
        protocol, port = rng.choice([s for s in _SERVICES if s[0] in ("http", "https")])
    else:
        protocol, port = rng.choice(_SERVICES)

    attempts = _attempts_for(scenario, rng)
    start = base_epoch + rng.uniform(0, 30 * 86400)

    # Heralding reports duration as an int number of seconds, so sub-second
    # sessions legitimately round to 0 -- keep that quirk.
    if attempts:
        gap = rng.uniform(0.05, 2.5)
        auth_offsets = [round((i + 1) * gap, 6) for i in range(len(attempts))]
        duration = int(max(auth_offsets) + rng.uniform(0, 3))
    else:
        auth_offsets = []
        duration = int(rng.uniform(0, 4))

    return {
        "timestamp": _ts(start, 0.0),
        "duration": duration,
        "session_id": f"{rng.getrandbits(48):012x}",
        "source_ip": _random_public_ip(rng),
        "source_port": rng.randint(1024, 65535),
        "destination_ip": "10.0.0.2",
        "destination_port": port,
        "protocol": protocol,
        "num_auth_attempts": len(attempts),
        "auth_attempts": [
            {"timestamp": _ts(start, off), "username": u, "password": p}
            for (u, p), off in zip(attempts, auth_offsets)
        ],
        "session_ended": True,
        "auxiliary_data": {},
        "sensor": f"heralding-{rng.randint(1, 3):02d}",
    }


def generate_sessions(n_per_scenario: int = 2000, seed: int = 42,
                      scenarios: Optional[List[str]] = None,
                      verify_labels: bool = True) -> Iterator[Tuple[str, Dict]]:
    """Yield `(expected_micro_state, record)` pairs, balanced across scenarios.

    With `verify_labels` (default), every record is passed through the real
    `heralding_parser.label_session()` and a mismatch raises. A generator that
    has drifted from the labeller would otherwise quietly produce mislabelled
    training rows, which is the worst possible failure here.
    """
    rng = random.Random(seed)
    names = list(scenarios) if scenarios else list(SCENARIOS)

    if verify_labels:
        import sys
        root = Path(__file__).resolve().parents[2]
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from src.parsers.heralding_parser import label_session
    else:
        label_session = None  # type: ignore

    for name in names:
        want = SCENARIOS[name]
        for _ in range(n_per_scenario):
            rec = generate_session(name, rng)
            if label_session is not None:
                got = label_session(rec)
                if got != want:
                    raise AssertionError(
                        f"generator/labeller drift: scenario {name!r} expected "
                        f"{want} but label_session() said {got}. Record: "
                        f"{json.dumps(rec)[:400]}")
            yield want, rec


def write_jsonlines(out_path: Path, n_per_scenario: int = 2000,
                    seed: int = 42) -> Dict[str, int]:
    """Write synthetic sessions as Heralding-format jsonlines. Returns counts."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    counts: Dict[str, int] = {}
    with out_path.open("w", encoding="utf-8") as fh:
        for label, rec in generate_sessions(n_per_scenario, seed):
            fh.write(json.dumps(rec) + "\n")
            counts[label] = counts.get(label, 0) + 1
    return counts


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--out", default="data/processed/heralding_aug/log_session.json")
    ap.add_argument("--per-scenario", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    counts = write_jsonlines(Path(args.out), args.per_scenario, args.seed)
    total = sum(counts.values())
    print(f"wrote {total} sessions to {args.out}")
    for label in sorted(counts):
        print(f"  {label:<22} {counts[label]:>7}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
