"""
src/generators/cowrie_simulator.py

Synthetic Cowrie sessions emitted as COWRIE LOG EVENTS, not as feature-adjacent
scalars, so they travel the same path as real traffic:

    events -> cowrie_parser.build_record() -> pipeline.extract_all() -> 128-d

WHY THIS EXISTS (DATA_INTEGRITY.md section 4, Part 1). The frozen dataset was
built by `kill_chain_simulator.generate_balanced_sessions()`, which writes one
summary row per session and skips straight to feature-adjacent values. Two
defects follow directly from that shortcut:

  1. Derived features were GENERATED instead of COMPUTED. 39% of TabSyn rows
     have `log_session_duration != log1p(session_duration_s)`, 23% have
     `iat_mean > iat_max`. A value cannot contradict its own definition if it is
     computed from the thing it is defined in terms of -- which is what going
     through the extractors buys.
  2. Quantities with no real counterpart were invented. Measured on the 13-day
     capture (114,490 sessions) against the frozen synthetic split:

         quantity          real capture            frozen synthetic
         login_attempts    max 1                   max 552
         bytes_out         always 0                lognormal
         bytes_in          ttylog size, 85% == 86  lognormal
         n_events          p50 5, max 41           lognormal to 64
         any commands      46% of sessions         ~100%

     Real SSH brute force is ONE login attempt per TCP connection -- the bot
     reconnects rather than retrying -- so the frozen data taught MT3 that brute
     force means hundreds of attempts in one session. That single mismatch is a
     large part of why real sessions measure 226x outside the training
     distribution (REAL_DATA_2026-11-09.md).

THE PRECEDENT THIS FOLLOWS. `heralding_simulator.py` writes
`log_session.json`-format records specifically so they pass through the same
`heralding_parser.build_record` as live traffic. Same idea here, same reason:
if the parser is wrong, this is wrong in the same way, which is the point.

WHAT GOING THROUGH THE PARSER FIXES FOR FREE. `build_record()` hard-codes
`bytes_out: 0` and `associated_cve: ""`, and flattens `dst_port` to 22. So the
bytes_out skew and the `E_threat_intel` train/serve mismatch cannot recur for
this source -- not because this module is careful, but because the real path has
no way to express them. That is the whole argument for Part 1.

SCOPE AND BOUNDARIES.

  - Does NOT touch `data/final/`. That dataset is frozen and every published
    number depends on it (CLAUDE.md, DATA_INTEGRITY.md section 6).
  - Does NOT edit `kill_chain_simulator.py`. The frozen `data/final/` build used
    its `generate_balanced_sessions()`, and `tests/test_generator_timing.py`
    plus notebook 01's no-real-data fallback still call it, so it stays
    byte-compatible. (Notebook 03b was the other caller; it was deleted
    2026-11-24 with the Part 2 drop.) This module imports FROM it (`KILL_CHAIN_DAG`, the source
    address pool, the ephemeral-port draw) and never the other way round, so the
    dependency runs one direction only.
  - Does NOT reuse `generate_event_timestamps` or `generate_session_sequence`,
    and both omissions are deliberate and measured -- see the gap-bootstrap
    block and `_sequence_ending_at` for why the pooled timing fit and the
    start-anchored walk are both wrong for this job.
  - Does NOT assign `associated_cve`. DATA_INTEGRITY.md section 4 Part 1
    suggests it to revive `E_threat_intel`, but section 3c -- written later, off
    measured data -- DROPs all 14 of those features precisely because
    `associated_cve` is empty in 100% of real sessions, so populating it only in
    synthetic data is a train/serve mismatch and WORSE than a dead feature.
    Section 3c wins. `build_record` enforces it regardless.

LABEL HONESTY -- READ THIS BEFORE USING THE OUTPUT.

`cowrie_parser` can only ever emit 18 of the 45 micro-states: the 15
`COMMAND_PATTERNS` labels, the `EXEC_SHELL_OPEN` catch-all, plus `RECON_IP_SCAN`
and `ACCESS_BRUTE_SSH` from the event stream. The other 27 classes are
unreachable by the labeller BY CONSTRUCTION.

So `heralding_simulator`'s `verify_labels=True` pattern -- parser label is truth,
mismatch raises -- cannot be applied wholesale. Measured over the 135 command
templates in `sim_commands.py`, only 27 are labelled by the parser as the class
they were written for; 108 (80%) disagree, and 41 of the 45 states have at least
one template the parser calls something else.

This module therefore records BOTH labels on every row and never hides the gap:

    micro_state           the intended class (generator's assertion)
    parser_micro_state    what cowrie_parser.build_record() actually said
    parser_sequence       the parser's per-event label sequence
    label_agrees          whether they match
    label_source          "generator" always, for this source

`agreement_report()` turns that into the per-class table. Decided 2026-11-15 with
the project owner; the alternative (parser label wins) collapses the Cowrie half
of the dataset from 45 classes to 18. Training on `micro_state` means the labels
are NOT reproducible by the live rule labeller for ~80% of rows, which is a real
limitation and must be stated wherever these rows are used.

CALIBRATION. Every constant below is measured on the 13-day real capture in
`cowrie_logs/` (114,490 sessions, 754,063 events, 0 unparseable lines) and the
measurement is given next to it. Nothing here is chosen by eye.
"""
from __future__ import annotations

import json
import logging
import random
import sys
import uuid as _uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from configs.schema import (                                    # noqa: E402
    IDX_TO_PHASE, LABEL_TO_IDX, MICRO_STATES, MIN_SAMPLES_PER_CLASS, N_CLASSES,
)
from src.generators.kill_chain_simulator import (               # noqa: E402
    _DOC_BLOCKS, _ip_pool, _src_port,
)
from src.generators.sim_commands import COMMAND_TEMPLATES       # noqa: E402

log = logging.getLogger(__name__)

__all__ = [
    "generate_cowrie_events", "generate_sessions", "generate_balanced_sessions",
    "mark_repeat_visitors", "agreement_report", "write_jsonlines",
    "parse_generated_log", "SYNTHETIC_SOURCE",
]

# Cowrie's own timestamp format, copied from the real logs:
#   "2026-11-01T17:19:45.416701Z"
_TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"

# The honeypot's own identity. `dst_port` is 2222 on every one of the 754,063
# real events; `build_record` flattens it to 22 and MUST keep doing so (see its
# docstring -- MT3 has only ever seen 22/65535 in feature 39). Emitting 2222 here
# is what makes the generated events faithful to the log format while the parser
# applies the same flattening it applies to real traffic.
_DST_IP, _DST_PORT = "172.18.0.2", 2222
_SENSOR = "synthetic-cowrie-01"      # deliberately NOT the real sensor id
                                     # (7b0b4b6a20d0), so a mixed corpus can
                                     # always be split back apart by sensor.

# ── Measured presence rates, per session ─────────────────────────────────────
# Real capture, share of the 114,490 sessions carrying at least one such event:
#   client.version 98.2%   client.kex 96.7%   login.* 92.2%
#   client.size     1.1%   client.var  0.09%
# The handshake events are near-universal; a session missing them is one that
# dropped mid-negotiation.
P_CLIENT_VERSION = 0.982
P_CLIENT_KEX     = 0.967
P_CLIENT_SIZE    = 0.011
P_CLIENT_VAR     = 0.001

# Chance a session attempts authentication at all, by kill-chain phase. A
# reconnaissance session mostly does not -- see the comment in `_build_skeleton`
# for the measurement that fixes this (no-login sessions and RECON_IP_SCAN
# sessions are the same 7.8% of the real capture).
P_LOGIN_PHASE0 = 0.15
P_LOGIN_OTHER  = 0.99

# Share of command-issuing sessions that are a scripted bot re-running its
# command block. Real command counts are bimodal: 1,262 of the 52,843
# command-issuing sessions (2.4%) sit in the 25-28 band while the rest issue 1.
P_SCRIPTED_BOT = 0.024

# ── Real sessions are SINGLE-ACTION, and that is the whole shape ────────────
# Command counts per class in the 13-day capture, for every class with real
# support. These are not spread distributions -- they are near-deterministic:
#
#   ACCESS_BRUTE_SSH   52,750    0 cmds 100.0%
#   DISC_ENV_PROBE     45,712    1 cmd  100.0%  (45,710 of 45,712)
#   RECON_IP_SCAN       8,898    0 cmds 100.0%
#   EXEC_SHELL_OPEN     6,997    1: 82.2%  25: 10.1%  28: 7.6%  9: 0.1%
#   EXEC_WGET_EXEC        137    1: 75.2%  25: 17.5%  0: 7.3%
#
# A real attacker session is one action, or one scripted block re-run. It is NOT
# a multi-stage kill chain, which is why 99.7% of real traffic sits in four
# classes with one command each.
#
# WHY THIS MATTERS, MEASURED. The backwards DAG walk gave a DISC_ENV_PROBE
# session up to 8 states each contributing a command, so generated sessions ran
# 3 commands / 10 events against a real 1 / 8. Adversarial AUC tracked that
# mismatch exactly: the two classes whose generated shape already matched real
# (ACCESS_BRUTE_SSH, RECON_IP_SCAN -- both 0 commands) scored 0.65 and 0.76 on
# A_temporal, while the two that did not (DISC_ENV_PROBE, EXEC_SHELL_OPEN)
# stayed at 0.96 and 0.98 no matter how faithful the gap model became. Realistic
# gaps cannot rescue an unrealistic session shape.
#
# So for these classes the walk is forced to a single state and the command count
# is drawn from the real distribution. Classes with only a handful of real
# sessions (EVASION_HIST_ERASE 6, DISC_PROC_ENUM 1) are deliberately NOT listed:
# constraining a class on six observations is overfitting, and they keep the
# generic multi-state walk.
REAL_COMMAND_COUNTS: Dict[str, Tuple[Tuple[int, float], ...]] = {
    "ACCESS_BRUTE_SSH": ((0, 100.0),),
    "RECON_IP_SCAN":    ((0, 100.0),),
    "DISC_ENV_PROBE":   ((1, 100.0),),
    "EXEC_SHELL_OPEN":  ((1, 82.2), (25, 10.1), (28, 7.6), (9, 0.1)),
    "EXEC_WGET_EXEC":   ((1, 75.2), (25, 17.5), (0, 7.3)),
}


# ── Real command text, bootstrapped per class ───────────────────────────────
# `sim_commands.COMMAND_TEMPLATES` are plausible-looking attacker commands that
# this honeypot never actually caught. Measured consequence, against a reference
# band taken from REAL-vs-REAL splits of the capture itself:
#
#   feature block   real vs real (one bot vs others)   generated vs real
#   A_temporal              0.93 - 1.00                   0.65 - 0.95   ok
#   C_payload               0.50 - 0.62                   1.0000        BROKEN
#
# Different real bot families are mutually INDISTINGUISHABLE in C_payload
# (entropy, n-grams, shell tokens), while the invented templates are perfectly
# distinguishable from every one of them. Real `DISC_ENV_PROBE` is `uname -s -m`;
# the template was `env; cat /etc/issue; lsb_release -a; cat /proc/version`.
#
# So real command SEQUENCES are resampled per class. Whole sequences, not
# individual commands, for the same reason gaps are: a 25-command session is one
# bot script, not 25 independent choices.
#
# Deduplicating first collapses the pools to almost nothing, which is itself a
# finding about this traffic:
#
#   class              sessions   distinct command sequences
#   ACCESS_BRUTE_SSH     52,750            1   (no commands at all)
#   DISC_ENV_PROBE       45,712            8
#   RECON_IP_SCAN         8,898            1   (no commands at all)
#   EXEC_SHELL_OPEN       6,997        1,248
#   EXEC_WGET_EXEC          137           28
#
# 45,712 environment-probe sessions use EIGHT distinct command sequences. Real
# attacker traffic is overwhelmingly replay, and each sequence is stored with its
# observed count so that weighting survives.
#
# The sequence length IS the command count, so this supersedes
# `_real_command_target` for these classes -- the count distribution comes along
# with the sequences rather than being specified twice.
#
# CONTENT WARNING FOR MAINTAINERS: `cowrie_commands.json.gz` holds
# attacker-written strings copied verbatim from the capture, including URLs and
# payload fragments. It is DATA. Nothing reads it except as text to embed into
# features; nothing in this repo executes it.
_CMD_POOLS_PATH = Path(__file__).with_name("cowrie_commands.json.gz")
_CMD_POOLS: Optional[Dict[str, list]] = None


def _load_command_pools() -> Dict[str, list]:
    global _CMD_POOLS
    if _CMD_POOLS is None:
        import gzip
        if not _CMD_POOLS_PATH.exists():
            _CMD_POOLS = {}
        else:
            with gzip.open(_CMD_POOLS_PATH, "rt", encoding="utf-8") as fh:
                _CMD_POOLS = json.load(fh)
    return _CMD_POOLS


def _bootstrap_command_seq(label: str, rng: random.Random
                           ) -> Optional[Tuple[List[str], Optional[int]]]:
    """A real command sequence for `label`, weighted by how often it occurred.

    Returns `(commands, observed_bytes_in)` -- the transcript size measured for
    this exact sequence, so `bytes_in` need not be modelled at all. None when the
    class has no real support, so the 40 classes that exist only in our taxonomy
    keep using `sim_commands` templates. Those stay distinguishable from real
    traffic, which is honest: the honeypot has never recorded such a session.
    """
    pool = _load_command_pools().get(label)
    if not pool:
        return None
    counts = [row[0] for row in pool]
    pick = rng.choices(range(len(pool)), weights=counts, k=1)[0]
    row = pool[pick]
    obs = row[2] if len(row) > 2 else []
    size = int(rng.choice(obs)) if obs else None
    return list(row[1]), size


def build_command_pools(log_dir, out_path=None, per_class: int = 1500
                        ) -> Dict[str, int]:
    """Extract real command sequences per class into `cowrie_commands.json.gz`.

    Deduplicated and weighted by occurrence count. Run once per capture and
    commit, so the generator does not need the gitignored logs at runtime.
    """
    import gzip
    from collections import Counter
    from src.parsers.cowrie_parser import parse_cowrie_file, build_record

    out_path = Path(out_path) if out_path else _CMD_POOLS_PATH
    seqs: Dict[str, Counter] = {}
    sizes: Dict[tuple, List[int]] = {}
    for fp in sorted(Path(log_dir).glob("cowrie.json*")):
        for events in parse_cowrie_file(fp):
            rec = build_record(events)
            if rec is None or rec["micro_state"] not in REAL_COMMAND_COUNTS:
                continue
            cmds = tuple(e.get("input", "") for e in events
                         if e.get("eventid") == "cowrie.command.input")
            seqs.setdefault(rec["micro_state"], Counter())[cmds] += 1
            # The TTY transcript size is a property of WHICH command ran, not of
            # how many: a 1-command DISC_ENV_PROBE session is 86 bytes (99.9% of
            # 45,710) while a 1-command EXEC_SHELL_OPEN session is 5 bytes (99.5%
            # of 5,749). A count-keyed table cannot express that and gave both
            # 86, which left B_network separable at AUC 0.93 for EXEC_SHELL_OPEN.
            # Carrying the observed size with the sequence makes bytes_in exact.
            key = (rec["micro_state"], cmds)
            if len(sizes.setdefault(key, [])) < 24:
                sizes[key].append(int(rec["bytes_in"]))

    payload = {cls: [[cnt, list(k), sizes.get((cls, k), [])]
                     for k, cnt in c.most_common(per_class)]
               for cls, c in seqs.items()}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out_path, "wt", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return {k: len(v) for k, v in sorted(payload.items())}


def _real_command_target(label: str, rng: random.Random) -> Optional[int]:
    """Command count drawn from the real distribution, or None if unsupported."""
    dist = REAL_COMMAND_COUNTS.get(label)
    if dist is None:
        return None
    return int(rng.choices([v for v, _ in dist],
                           weights=[w for _, w in dist], k=1)[0])


# Implant upload, conditional on session depth -- see the measurement in
# `_build_skeleton`. 557 of 1,273 sessions with 5+ commands carry one; 16 of
# 51,570 shallower ones do.
P_UPLOAD_DEEP    = 0.438
P_UPLOAD_SHALLOW = 0.0003

# Of sessions that authenticate at all, how many FAILED. Real: 1,216 failed vs
# 104,385 succeeded = 1.15%. NOTE this is a property of the VM's `userdb`
# (which accepts almost anything), not of attacker behaviour -- the local
# `cowrie/userdb.txt` denies common passwords and would invert the ratio. It is
# calibrated to the VM because the VM is what produced the real capture.
P_LOGIN_FAILED = 0.0115

# Share of post-auth commands that Cowrie could not emulate and logged as
# `command.failed` instead of `command.input`. Real: 2,535 of 87,350 = 2.9%.
# This matters to n_events but NOT to n_commands or command_text, because
# `build_record` only reads `cowrie.command.input` -- an asymmetry the generator
# has to reproduce or n_events comes out systematically low.
P_COMMAND_FAILED = 0.029

# ── Measured client fingerprints ─────────────────────────────────────────────
# Real `client.version` strings, top of 112,478 events. Overwhelmingly Go and
# libssh bot frameworks, not interactive clients.
_CLIENT_VERSIONS: Tuple[Tuple[str, float], ...] = (
    ("SSH-2.0-Go",                           54549),
    ("SSH-2.0-libssh_0.9.6",                 27932),
    ("SSH-2.0-libssh_0.10.6",                12040),
    ("SSH-2.0-libssh_0.11.3",                10951),
    ("SSH-2.0-libssh_0.10.4",                 4525),
    ("SSH-2.0-libssh_0.11.5",                  822),
    ("SSH-2.0-PuTTY_Release_0.84",             650),
    ("SSH-2.0-libssh_0.9.0",                   404),
    ("SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4", 102),
    ("SSH-2.0-ZGrab ZGrab SSH Survey",           59),
)

# Real `client.kex` hassh values, top 3 of 110,726 events. A hassh is a hash of
# the offered algorithm lists, so it is a client-library fingerprint and only a
# handful of distinct values appear.
_HASSH_POOL: Tuple[Tuple[str, float], ...] = (
    ("0a07365cc01fa9fc82608ba4019af499", 45502),
    ("36552e78a2db7dedc976010ba15578e9", 14108),
    ("3335afa7a75e84f8348f05c623c5ecf9", 13730),
)

_KEX_ALGS = [
    "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521", "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group-exchange-sha256",
]
_ENC_ALGS = ["aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com",
             "aes128-cbc", "3des-cbc"]
_MAC_ALGS = ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
             "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"]
_KEY_ALGS = ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]

# Real `login.*` credentials, top of 105,601 attempts. Counts are the weights.
_USERNAMES: Tuple[Tuple[str, float], ...] = (
    ("root", 43767), ("ubuntu", 17237), ("admin", 14083), ("user", 3388),
    ("deploy", 760), ("test", 617), ("support", 434), ("user1", 425),
    ("claude", 355), ("postgres", 304), ("ubnt", 190), ("oracle", 160),
    ("git", 140), ("pi", 120), ("jenkins", 90), ("ftpuser", 70),
)
_PASSWORDS: Tuple[Tuple[str, float], ...] = (
    ("123456", 2633), ("123", 1372), ("1234", 1088), ("12345678", 723),
    ("1", 627), ("root", 618), ("12345", 562), ("password", 531),
    ("123456789", 415), ("support", 333), ("admin", 300), ("ubuntu", 280),
    ("3245gs5662d34", 250), ("1234567890", 200), ("P@ssw0rd", 150),
    ("", 120),
)

# Real `session.params` arch strings.
_ARCH_POOL = ("linux-x64-lsb", "linux-x86-lsb", "linux-arm-lsb", "linux-aarch64-lsb")

# Real `client.var` names.
_CLIENT_VARS = (("LANG", "en_GB.UTF-8"), ("LANG", "en_US.UTF-8"),
                ("LC_ALL", "C"), ("TERM", "xterm"))

# ── Measured ttylog sizes -> bytes_in ────────────────────────────────────────
# `build_record` computes `bytes_in` as the sum of every `size` field in the
# session, and `cowrie.log.closed` is the ONLY real event type that carries one
# (53,466 of 754,063 events). So bytes_in IS the TTY transcript size, and it is
# 0 for the 54% of sessions that never open a shell. The frozen generator drew it
# from a lognormal instead, which is why real and synthetic bytes_in do not
# overlap.
#
# Size conditioned on the commands inside the TTY block (53,464 blocks):
#
#    cmds   n        size distribution
#      1   51,652    86: 88.4%   5: 11.1%   93/0/11: 0.3%
#      2       13    45: 84.6%   42: 7.7%   48: 7.7%
#      3      532   240: 85.0%  252: 12.0%  244/256: 3.0%
#     27    1,262  3926: 40.4% 3924: 24.3% 3954: 10.5% 3922: 6.7% 3952: 5.5%
#
# Command counts the capture never produced (4-26, 28+) need a model rather than
# a table. Regressed over all 53,464 blocks, size is 1.13x the echoed command
# text for blocks of 3 or more commands (3 cmds: 210 chars -> 240 bytes;
# 27 cmds: 3,472 chars -> 3,926 bytes), with a small constant. The 1-command
# case sits apart at a near-constant 86 bytes because its output, not its echo,
# dominates. So: use the empirical table where the capture has one, and fall back
# to the fit where it does not.
_TTYLOG_TABLE: Dict[int, Tuple[Tuple[int, float], ...]] = {
    1: ((86, 88.4), (5, 11.1), (93, 0.13), (0, 0.06), (11, 0.06), (96, 0.03)),
    2: ((45, 84.6), (42, 7.7), (48, 7.7)),
    3: ((240, 85.0), (252, 12.0), (244, 1.7), (256, 1.3)),
}
_TTY_CHARS_SLOPE = 1.13      # bytes of transcript per byte of echoed command
_TTY_BLOCK_CONST = 3         # fitted intercept, blocks of >= 3 commands

# ── Measured inter-arrival gaps: BOOTSTRAPPED, not fitted ───────────────────
# Gaps are drawn by resampling ACTUAL gaps from the real capture, keyed by the
# event each gap arrives at AND the kind of session it belongs to.
#
# WHY NOT A FITTED DISTRIBUTION -- this was measured, not assumed. The first
# version sampled a 10-point quantile grid per event type by inverse CDF with
# log-linear interpolation. It reproduced every summary statistic that was
# checked: duration medians per session type within 15%, the long-pause rate
# within 0.5 percentage points in all four buckets, the pooled sub-100ms share
# within 6 points. A gradient-boosted tree still told real from generated Cowrie
# sessions at AUC 0.9782-0.9956 using the A_temporal block ALONE, within a single
# micro-state (so it was not class composition doing the work).
#
# Matching the percentiles is not matching the distribution. A 10-point grid
# leaves kinks at the decile boundaries that a tree splits on, real gaps are
# partly quantised (Cowrie's 120 s idle timeout recurs near-exactly), and no
# independent per-gap draw reproduces correlation within a session.
#
# Resampling real gaps reproduces all of that by construction, and it deletes
# code: the fitted version needed 60 lines of quantile tables plus a long-pause
# gate with four calibrated probabilities to re-impose structure that the pools
# simply carry.
#
# SESSION BUCKETS. The same event means different things in different sessions --
# the gap into `session.closed` has p50 0.0007 s when a shell ran and 4.6 s when
# nobody authenticated. Bucketing is what removes the need for explicit pause
# gating, because the concentration of long pauses lives in the pool it was
# measured from:
#
#   bucket                     real sessions with ANY gap > 30 s
#   no_login                                 23.52%
#   login_nocmd                               0.42%
#   login_shallow (1-4 cmds)                  0.24%
#   login_deep    (5+ cmds)                  37.31%
#
# Pools live in `cowrie_gaps.npz` beside this module, built by `build_gap_pools()`
# and committed, so the generator never needs the gitignored capture at runtime.
_GAP_POOLS_PATH = Path(__file__).with_name("cowrie_gaps.npz")
_GAP_POOLS: Optional[Dict[str, object]] = None

# Below this, a pool cannot support resampling and the broader fallback is used.
_MIN_POOL = 40

# The busiest real session ran 392.42 s.
_DURATION_MAX = 400.0


def _session_bucket(did_login: bool, n_commands: int) -> str:
    """Which gap pool a session draws from. MUST match `build_gap_pools()`."""
    if not did_login:
        return "no_login"
    if n_commands == 0:
        return "login_nocmd"
    if n_commands <= 4:
        return "login_shallow"
    return "login_deep"


def _load_gap_pools() -> Dict[str, object]:
    global _GAP_POOLS
    if _GAP_POOLS is None:
        import numpy as np
        if not _GAP_POOLS_PATH.exists():
            raise FileNotFoundError(
                f"{_GAP_POOLS_PATH} is missing -- it holds the real gaps this "
                f"generator resamples. Rebuild from a capture with:\n"
                f"  python -m src.generators.cowrie_simulator build-gaps "
                f"--logs <dir>")
        with np.load(_GAP_POOLS_PATH) as z:
            _GAP_POOLS = {k: z[k] for k in z.files}
    return _GAP_POOLS


def _bootstrap_gap(eventid: str, bucket: str, rng: random.Random) -> float:
    """One real gap, resampled with replacement.

    Falls back (event, bucket) -> (event, any bucket) -> (any, any), so a
    combination the capture never produced still yields a plausible gap instead
    of raising. The fallback is explicit rather than silent: a missing pool for a
    COMMON event type means the capture used to build the pools was too small.
    """
    pools = _load_gap_pools()
    for key in (f"{eventid}|{bucket}", f"{eventid}|*", "*|*"):
        arr = pools.get(key)
        if arr is not None and len(arr) >= _MIN_POOL:
            return float(arr[rng.randrange(len(arr))])
    raise RuntimeError(f"no gap pool for {eventid!r} / {bucket!r}")


def build_gap_pools(log_dir, out_path=None, per_pool: int = 1500,
                    per_seq: int = 2500, seed: int = 42) -> Dict[str, int]:
    """Extract real inter-arrival gaps from a Cowrie capture into `.npz`.

    Run once per capture; commit the output so the generator does not depend on
    the irreplaceable, gitignored logs at runtime. Returns pool sizes.

    Only timestamps and event ids are read. Everything else in the capture is
    attacker-written data and nothing from it is executed.
    """
    import numpy as np
    from src.parsers.cowrie_parser import parse_cowrie_file, to_ts

    out_path = Path(out_path) if out_path else _GAP_POOLS_PATH
    raw: Dict[str, List[float]] = {}
    sequences: Dict[str, List[List[float]]] = {}
    from src.parsers.cowrie_parser import build_record as _br
    for fp in sorted(Path(log_dir).glob("cowrie.json*")):
        for events in parse_cowrie_file(fp):
            events.sort(key=lambda e: e.get("timestamp", ""))
            ids = [e.get("eventid", "") for e in events]
            ts = [to_ts(e.get("timestamp", "")) for e in events]
            rec = _br(list(events)) or {}
            bucket = _session_bucket(
                any(i.startswith("cowrie.login") for i in ids),
                ids.count("cowrie.command.input"))
            this_seq: List[float] = []
            for i in range(len(events) - 1):
                gap = ts[i + 1] - ts[i]
                if gap < 0.0:
                    continue            # clock skew; the walk must stay ascending
                for key in (f"{ids[i + 1]}|{bucket}", f"{ids[i + 1]}|*", "*|*"):
                    raw.setdefault(key, []).append(gap)
                this_seq.append(gap)
            if this_seq:
                # Keyed by CLASS as well as bucket. A bucket mixes classes whose
                # timing genuinely differs: `login_shallow` is 88.6%
                # DISC_ENV_PROBE and 11.1% EXEC_SHELL_OPEN, and their real
                # medians are 2.123 s / 0.16874 s against 6.240 s / 0.37917 s --
                # 2.9x on duration, 2.2x on the typical gap. A class-blind pool
                # therefore hands a generated EXEC_SHELL_OPEN session
                # DISC_ENV_PROBE's rhythm 88.6% of the time, which is why its
                # A_temporal AUC stayed at 0.9756 while donor LENGTH matching was
                # already 100%. Length was never the binding constraint; class was.
                sequences.setdefault(bucket, []).append(this_seq)
                cls = rec.get("micro_state")
                if cls:
                    sequences.setdefault(f"{cls}|{bucket}", []).append(this_seq)

    # Whole-session gap SEQUENCES, per bucket. The per-event pools above match
    # every MARGINAL; they cannot match the JOINT distribution, because gaps
    # inside one session are correlated and an independent per-gap draw throws
    # that away. Measured: after per-gap bootstrapping, no single temporal
    # feature separated real from generated better than AUC 0.626, yet the tree
    # using all 24 together still reached 0.96 -- the signal was purely in the
    # correlations. Copying a real session's gap vector reproduces them exactly.
    #
    # Aligned from the START of the session, not a random window, because real
    # Cowrie skeletons are stereotyped (90% of sessions are one of two event
    # orders), so gap i of a same-bucket real session is the same kind of gap.
    seq_rng = np.random.RandomState(seed + 1)
    for bucket, seqs in list(sequences.items()):
        if not seqs:
            continue
        if len(seqs) > per_seq:
            seqs = [seqs[i] for i in seq_rng.choice(len(seqs), per_seq, replace=False)]
        flat = np.concatenate([np.asarray(x, dtype=np.float32) for x in seqs])
        offs = np.cumsum([0] + [len(x) for x in seqs]).astype(np.int32)
        raw[f"SEQ|{bucket}|flat"] = flat
        raw[f"SEQ|{bucket}|offs"] = offs

    rng = np.random.RandomState(seed)
    pools = {}
    for key, vals in raw.items():
        if key.startswith("SEQ|"):
            pools[key] = np.asarray(vals)
            continue
        a = np.asarray(vals, dtype=np.float32)
        if len(a) > per_pool:
            a = a[rng.choice(len(a), per_pool, replace=False)]
        pools[key] = a
    out_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(out_path, **pools)
    return {k: len(v) for k, v in sorted(pools.items())}


# Real capture max was 28 commands in one session and 41 events. 48 leaves the
# deep synthetic phases a little headroom without inventing sessions the
# honeypot has never seen.
COMMANDS_CEILING = 32

# States that produce NO shell commands, because they happen before or during
# authentication and the honeypot sees them only as connection and login events.
# This is measured, not assumed: all 8,898 real RECON_IP_SCAN sessions and all
# 52,750 real ACCESS_BRUTE_SSH sessions carry ZERO commands.
_PREAUTH_PREFIXES = ("RECON_", "ACCESS_")

# ── The labelled state must be the session's DEEPEST, not its first ──────────
# `kill_chain_simulator.generate_session_sequence(force_start=label)` pins the
# label to the START of the walk and then advances through the DAG. So a session
# labelled RECON_IP_SCAN routinely escalated into phase 2-4 and issued commands,
# and a session labelled PERSIST_BASHRC had persistence as its SHALLOWEST
# behaviour. Measured on a phase-0 corpus built that way: 57.5% of
# RECON-labelled sessions issued shell commands, which no real reconnaissance
# session does.
#
# That is the same labelling defect DATA_INTEGRITY.md section 3d records for the
# real capture, in mirror image: `build_record` takes `meaningful[-1]`, so
# `PRIVESC_SUDO_ABUSE` appears in 532 real sessions and reaches the final label
# in zero of them, and the doc's fix is to label by DEEPEST kill-chain phase.
# A generator whose label is the shallowest state cannot be trained against that
# rule.
#
# So the walk is built BACKWARDS from the intended label through the DAG's
# reverse edges. The label ends up the terminal, deepest state, the corpus stays
# balanced (one session per class per draw), and the generated
# `micro_state_sequence` is a path the DAG actually permits -- `is_valid_sequence`
# and `is_phase_monotone` both still hold, because a reversed reverse-path is a
# forward path.
_REVERSE_DAG: Dict[str, Tuple[str, ...]] = {}


def _reverse_dag() -> Dict[str, Tuple[str, ...]]:
    global _REVERSE_DAG
    if not _REVERSE_DAG:
        from src.generators.kill_chain_simulator import KILL_CHAIN_DAG
        rev: Dict[str, set] = {}
        for src, dsts in KILL_CHAIN_DAG.items():
            for d in dsts:
                if d == src:
                    continue
                rev.setdefault(d, set()).add(src)
        _REVERSE_DAG = {k: tuple(sorted(v)) for k, v in rev.items()}
    return _REVERSE_DAG


def _sequence_ending_at(label: str, rng: random.Random,
                        min_len: int = 1, max_len: int = 8) -> List[str]:
    """A DAG-valid walk whose LAST and deepest state is `label`."""
    want = rng.randint(min_len, max_len)
    rev = _reverse_dag()
    seq = [label]
    while len(seq) < want:
        preds = [p for p in rev.get(seq[0], ())
                 if IDX_TO_PHASE[LABEL_TO_IDX[p]] <= IDX_TO_PHASE[LABEL_TO_IDX[seq[0]]]]
        if not preds:
            break
        choice = rng.choice(preds)
        if choice in seq:            # the DAG has same-phase cycles; do not loop
            break
        seq.insert(0, choice)
    return seq


def _weighted(pool: Sequence[Tuple[str, float]], rng: random.Random) -> str:
    return rng.choices([p[0] for p in pool], weights=[p[1] for p in pool], k=1)[0]


def _ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime(_TS_FMT)


def _sha256_like(rng: random.Random) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(64))


def _ttylog_size(cmds: Sequence[str], rng: random.Random) -> int:
    """Transcript size for one TTY block -- the only source of `bytes_in`.

    Empirical table for the command counts the real capture actually produced,
    the fitted 1.13x-of-echoed-text model for the ones it did not.
    """
    n = len(cmds)
    if n in _TTYLOG_TABLE:
        return int(_weighted(tuple((str(v), w) for v, w in _TTYLOG_TABLE[n]), rng))
    chars = sum(len(c) for c in cmds)
    size = _TTY_CHARS_SLOPE * chars + _TTY_BLOCK_CONST
    # The real sizes cluster tightly around the fit (median absolute error 8.5
    # bytes over 53,464 blocks), so the jitter is small and multiplicative.
    return max(0, int(round(size * rng.uniform(0.98, 1.03))))






def _bootstrap_sequence(bucket: str, n_gaps: int, eventids: Sequence[str],
                        rng: random.Random,
                        label: Optional[str] = None) -> List[float]:
    """`n_gaps` gaps copied from ONE real session of the same bucket.

    Preserves within-session correlation, which per-gap draws cannot: after
    per-gap bootstrapping no single temporal feature separated real from
    generated better than AUC 0.626, yet all 24 together still reached 0.96, so
    the remaining signal was entirely in the correlations.

    DONOR LENGTH MUST MATCH, and that is measured, not cosmetic. Gaps are copied
    from the START (real Cowrie skeletons are stereotyped, so gap i is the same
    kind of gap), which means truncating a long donor discards its TAIL -- and in
    a real deep session the tail is where the 92-second implant-upload pause
    sits. Copying the first 10 gaps of a 35-gap donor dropped the deep-session
    long-pause rate from a measured 37.3% to 0.5%. So a donor is only used when
    its length is close to what is needed; otherwise per-event bootstrapping
    takes over, which reproduces the per-bucket pause rate correctly on its own.

    The 36 micro-states with no real counterpart always land in the fallback.
    That is honest rather than a gap: there is no real session of that shape to
    copy from.
    """
    pools = _load_gap_pools()
    # The class's OWN donors first, then the bucket's. Timing differs by class
    # inside a bucket (see build_gap_pools), so a bucket-level donor imports
    # whichever class dominates the bucket.
    keys = ([f"SEQ|{label}|{bucket}"] if label else []) + [f"SEQ|{bucket}"]
    for key in keys:
        flat = pools.get(f"{key}|flat")
        offs = pools.get(f"{key}|offs")
        if flat is None or offs is None or len(offs) <= 2:
            continue
        best = None
        for _ in range(24):
            k = rng.randrange(len(offs) - 1)
            a, b = int(offs[k]), int(offs[k + 1])
            if b - a >= n_gaps and (best is None or (b - a) < best[1] - best[0]):
                best = (a, b)
        # Only a donor within 50% of the required length preserves the tail.
        if best is not None and (best[1] - best[0]) <= max(n_gaps + 2,
                                                           int(n_gaps * 1.5)):
            return [float(x) for x in flat[best[0]:best[0] + n_gaps]]
    return [_bootstrap_gap(eventids[i + 1], bucket, rng) for i in range(n_gaps)]


def _event_timestamps(t_start: float,
                      eventids: Sequence[str],
                      rng: random.Random,
                      *,
                      did_login: bool = True,
                      n_commands: int = 0,
                      label: Optional[str] = None) -> List[float]:
    """Ascending timestamps for an event stream, each gap a resampled real one.

    `session_duration_s` is the SUM of these gaps -- derived, never drawn.

    There is no long-pause gating and no 30 s cap. The previous version needed
    both because it drew gaps from a fitted distribution and then had to bolt the
    measured per-session-type pause rates back on. Resampling from the session's
    own bucket brings that structure along for free: a `no_login` session draws
    from gaps measured in real no-login sessions, 23.52% of which contain a pause
    over 30 s, and a `login_shallow` one draws from a pool where 0.24% do.
    """
    n = len(eventids)
    if n <= 1:
        return [float(t_start)]
    bucket = _session_bucket(did_login, n_commands)
    gaps = _bootstrap_sequence(bucket, n - 1, eventids, rng, label)
    total = sum(gaps)
    if total > _DURATION_MAX:
        # Trim the single longest gap rather than rescaling everything, so the
        # remaining pauses keep the length they were measured at.
        j = max(range(len(gaps)), key=lambda k: gaps[k])
        gaps[j] = max(1e-6, gaps[j] - (total - _DURATION_MAX))
    out = [float(t_start)]
    acc = 0.0
    for g in gaps:
        acc += g
        out.append(float(t_start) + acc)
    return out


# ── Command selection ────────────────────────────────────────────────────────
def _commands_for_sequence(seq: Sequence[str], rng: random.Random,
                           repeat: int = 1) -> List[List[str]]:
    """Per-state command lists for one kill-chain walk.

    One entry per state in `seq`; pre-auth states contribute an EMPTY list.
    `repeat` issues each state's commands that many times, which is how the real
    scripted bots produce their 25-28 command sessions.

    This replaces `sim_commands.add_command_text`, which keys only off the
    session's single `micro_state` label. That left the frozen rows internally
    inconsistent: a session whose `micro_state_sequence` held five states carried
    command text drawn from ONE of them. Here every state in the walk contributes
    its own commands, so the command stream and the state sequence describe the
    same session.
    """
    out: List[List[str]] = []
    for state in seq:
        if state.startswith(_PREAUTH_PREFIXES):
            out.append([])
            continue
        pool = COMMAND_TEMPLATES.get(state)
        if not pool:
            out.append([])
            continue
        # A template is itself a ' ; '-joined line of 1-3 commands, which is how
        # `sim_commands` wrote them and how real bots issue them. Split so each
        # becomes its own `cowrie.command.input` event, the way Cowrie logs them.
        chosen = rng.choice(pool)
        parts = [p.strip() for p in chosen.split(" ; ") if p.strip()] or [chosen]
        out.append(parts * repeat)
    return out


# ── Event stream construction ────────────────────────────────────────────────
def _build_skeleton(label: str,
                    seq: Sequence[str],
                    rng: random.Random
                    ) -> Tuple[List[Tuple[str, dict]], List[str], bool]:
    """The ordered (eventid, payload) list for one session, WITHOUT timestamps.

    `n_events` falls out of this as `len(skeleton)` -- it is derived, not drawn.
    That is the structural half of the Part 1 fix: in the real capture n_events
    is almost perfectly determined by the command count (0 commands -> 5 events,
    1 -> 8, 25 -> 35, 28 -> 41), because Cowrie's event stream is a fixed
    protocol skeleton with a shell transcript threaded through it:

        connect
        [client.version] [client.kex] [client.size]
        [login.failed | login.success]
        [client.var]
        { session.params  (command.input | command.failed)+  log.closed }*
        [session.file_upload | session.file_download]
        session.closed

    90% of real sessions are one of just two instances of it:
      45.0%  connect version kex login.success closed
      44.9%  connect version kex login.success params cmd log.closed closed

    Returns (skeleton, commands_issued, did_login). `commands_issued` is the
    `command.input` text in order -- what `build_record` will read -- and
    `did_login` says whether the session authenticated, which the timestamp
    walk needs to decide whether a long pause is allowed.
    """
    ev: List[Tuple[str, dict]] = [("cowrie.session.connect", {})]

    if rng.random() < P_CLIENT_VERSION:
        ev.append(("cowrie.client.version", {"version": _weighted(_CLIENT_VERSIONS, rng)}))
    if rng.random() < P_CLIENT_KEX:
        hassh = _weighted(_HASSH_POOL, rng)
        ev.append(("cowrie.client.kex", {
            "hassh": hassh,
            "hasshAlgorithms": ";".join([",".join(_KEX_ALGS), ",".join(_ENC_ALGS),
                                         ",".join(_MAC_ALGS), "none"]),
            "kexAlgs": list(_KEX_ALGS), "keyAlgs": list(_KEY_ALGS),
            "encCS": list(_ENC_ALGS), "macCS": list(_MAC_ALGS),
            "compCS": ["none", "zlib@openssh.com"], "langCS": [""],
        }))

    # Scripted-bot repetition. Real command counts are strongly bimodal --
    # {0: 61,647, 1: 51,567, 25: 730, 28: 532} -- and the 25/28 cluster is one
    # botnet family re-running its command block, not a long interactive
    # session. Tying commands to the kill-chain walk alone caps the corpus at
    # `max_len` commands (measured: max 8), so the generator could not produce
    # the deep-command sessions that genuinely exist. A session-level repeat
    # factor restores that tail without inventing a new shape: it is the same
    # commands issued again, which is what the real bot does.
    _boot = _bootstrap_command_seq(label, rng)
    real_seq, real_bytes = _boot if _boot is not None else (None, None)
    if real_seq is not None:
        # Length comes with the sequence, so no separate count draw.
        per_state = [real_seq]
        target = len(real_seq)
    else:
        target = _real_command_target(label, rng)
    if real_seq is not None:
        pass
    elif target is None:
        repeat = 1
        if rng.random() < P_SCRIPTED_BOT:
            repeat = rng.randint(2, 5)
        per_state = _commands_for_sequence(seq, rng, repeat=repeat)
    else:
        # Stretch or trim to EXACTLY the real count. Doubling is how the real
        # 25/28-command sessions arise -- one bot re-running its block -- so the
        # repetition is the mechanism, not padding.
        flat_c = [c for st in _commands_for_sequence(seq, rng, repeat=1)
                  for c in st]
        if target == 0 or not flat_c:
            per_state = [[]]
        else:
            while len(flat_c) < target:
                flat_c = flat_c + flat_c
            per_state = [flat_c[:target]]
    total_cmds = sum(len(c) for c in per_state)

    # Authentication. A session that issues commands MUST have logged in first:
    # Cowrie cannot log `command.input` for an unauthenticated connection, and
    # every one of the 52,843 real sessions with commands carries a
    # login.success. So a login is forced whenever commands follow.
    #
    # The sessions that never authenticate are the pure scans, and the real
    # capture pins that down exactly: 8,889 of 114,490 sessions (7.76%) contain
    # no login event, and the parser labels 8,898 sessions RECON_IP_SCAN -- the
    # same sessions. "No login" IS "reconnaissance" in this data.
    #
    # Worth stating plainly: the 7.76% POOLED rate cannot be a target for a
    # BALANCED corpus. Real traffic puts 99.7% of its mass in 4 classes, so
    # every pooled marginal here is dominated by brute force; a corpus with
    # 2,000 sessions per class has 13.3% of its rows in phase 0 by construction.
    # What transfers is the CONDITIONAL behaviour -- a recon session does not
    # authenticate -- not the marginal.
    phase = IDX_TO_PHASE[LABEL_TO_IDX[label]]
    p_login = P_LOGIN_PHASE0 if phase == 0 else P_LOGIN_OTHER
    did_login = False
    if total_cmds > 0 or rng.random() < p_login:
        failed = (total_cmds == 0) and (rng.random() < P_LOGIN_FAILED)
        if rng.random() < P_CLIENT_SIZE:
            ev.append(("cowrie.client.size",
                       {"width": rng.choice([80, 132, 240]), "height": 24}))
        ev.append((
            "cowrie.login.failed" if failed else "cowrie.login.success",
            {"username": _weighted(_USERNAMES, rng),
             "password": _weighted(_PASSWORDS, rng)},
        ))
        did_login = not failed
        if did_login and rng.random() < P_CLIENT_VAR:
            name, value = rng.choice(_CLIENT_VARS)
            ev.append(("cowrie.client.var", {"name": name, "value": value}))

    issued: List[str] = []
    if did_login and total_cmds > 0:
        # ONE TTY block for the whole walk, not one per state. An attacker opens
        # a shell and runs everything in it, and the real capture is emphatic:
        # of the 52,843 command-issuing sessions, 52,297 (98.97%) carry exactly
        # ONE `log.closed`, 534 carry two, 12 carry more.
        #
        # Emitting a block per state was measurably wrong -- it added a
        # `session.params` (real p50 gap 0.88 s) and a `log.closed` (0.24 s) per
        # state, which inflated a 3-command session from 10 events to 14 and its
        # duration from 2.2 s to 6.4 s against the real figures.
        flat = [c for state_cmds in per_state for c in state_cmds][:COMMANDS_CEILING]

        # An implant upload and a second shell are the SAME botnet behaviour, and
        # the upload is where a deep session's time actually goes. Summed over
        # the 1,273 real sessions with 5 or more commands:
        #
        #   gap arriving at        total       n      mean    share of all time
        #   session.file_upload  51,155 s     557    91.8 s        73.7%
        #   login.success         4,971 s   1,273     3.9 s         7.2%
        #   log.closed            3,123 s   1,889     1.7 s         4.5%
        #   command.input         2,484 s  33,241    0.075 s        3.6%
        #
        # So 74% of the time in a deep session is ONE gap -- the SFTP transfer --
        # and the effect on duration is decisive: deep sessions WITH an upload
        # run a median 70.23 s, those without 8.08 s.
        #
        # The rate is therefore conditional on depth, not a flat per-session
        # chance: 557 of 1,273 sessions with 5+ commands carry an upload (43.8%)
        # against 16 of 51,570 shallower ones (0.03%). 97% of all real uploads
        # are in deep sessions.
        has_upload = rng.random() < (P_UPLOAD_DEEP if len(flat) >= 5
                                     else P_UPLOAD_SHALLOW)
        # Upload between two shells is the 532-session archetype exactly:
        #   ... log.closed -> file_upload -> params -> command.input -> log.closed
        # the bot drops its implant, reopens a shell, then chmods and runs it.
        split = len(flat)
        if has_upload and len(flat) > 1:
            split = max(1, len(flat) - rng.randint(1, max(1, len(flat) // 4)))

        chunks = [flat[:split], flat[split:]]
        for bi, chunk in enumerate(chunks):
            if not chunk:
                continue
            if bi == 1 and has_upload:
                sha = _sha256_like(rng)
                ev.append(("cowrie.session.file_upload", {
                    "filename": rng.choice([".16", ".x", "bot", ".sshd", "a"]),
                    "outfile": f"var/lib/cowrie/downloads/{sha}", "shasum": sha,
                }))
            ev.append(("cowrie.session.params", {"arch": rng.choice(_ARCH_POOL)}))
            block: List[str] = []
            n_in_block = 0
            for ci, cmd in enumerate(chunk):
                # Cowrie logs a command it cannot emulate as `command.failed`,
                # which `build_record` IGNORES -- it counts toward n_events but
                # not n_commands or command_text. 2,535 real events, 2.9% of
                # commands.
                #
                # Two constraints the real data imposes, and both matter:
                #
                #  - A failure never happens alone. All 2,535 real
                #    `command.failed` events sit in sessions that ALSO issued
                #    `command.input` (the 25/28-command bot archetype carries
                #    27 inputs and 2 failures). Only 7 of 53,464 real TTY blocks
                #    contain zero `command.input`.
                #  - So a block must keep at least one input. An independent
                #    per-command coin flip breaks that for single-command
                #    blocks: 2.9% of them came out with a `log.closed` and no
                #    command at all, giving a 0-command session a non-zero
                #    `bytes_in` at ~200x the real rate.
                last_chance = (ci == len(chunk) - 1) and n_in_block == 0
                if (len(chunk) > 1 and not last_chance
                        and rng.random() < P_COMMAND_FAILED):
                    ev.append(("cowrie.command.failed", {"input": cmd}))
                else:
                    ev.append(("cowrie.command.input", {"input": cmd}))
                    issued.append(cmd)
                    n_in_block += 1
                block.append(cmd)
            # Measured size for this exact command sequence when we have one;
            # only the first block takes it, since bytes_in is its sum and the
            # second block exists only in the rare upload case.
            if real_bytes is not None and bi == 0:
                size = int(real_bytes)
            else:
                size = _ttylog_size(block, rng)
            sha = _sha256_like(rng)
            ev.append(("cowrie.log.closed", {
                "ttylog": f"var/lib/cowrie/tty/{sha}", "size": size,
                "shasum": sha, "duplicate": False,
            }))

        # A single-shell session that still uploaded: the upload lands after the
        # only TTY block.
        if has_upload and not chunks[1]:
            sha = _sha256_like(rng)
            ev.append(("cowrie.session.file_upload", {
                "filename": rng.choice([".16", ".x", "bot", ".sshd", "a"]),
                "outfile": f"var/lib/cowrie/downloads/{sha}", "shasum": sha,
            }))

        # Cowrie fetching from an attacker-supplied URL. Rare: 31 real events.
        if rng.random() < 0.0003:
            sha = _sha256_like(rng)
            ev.append(("cowrie.session.file_download", {
                "url": f"http://{rng.randint(1,223)}.{rng.randint(0,255)}."
                       f"{rng.randint(0,255)}.{rng.randint(1,254)}/"
                       f"{rng.choice(['bot','x.sh','m','xmrig'])}",
                "outfile": f"var/lib/cowrie/downloads/{sha}", "shasum": sha,
                "duplicate": False,
            }))

    ev.append(("cowrie.session.closed", {}))
    return ev, issued, did_login


def generate_cowrie_events(label: str,
                           rng: random.Random,
                           *,
                           src_ip: Optional[str] = None,
                           t_start: Optional[float] = None,
                           session_id: Optional[str] = None,
                           min_len: int = 1,
                           max_len: int = 8) -> Tuple[List[dict], List[str]]:
    """One synthetic session as a list of Cowrie log events.

    Returns `(events, micro_state_sequence)`. The events are the same shape the
    real honeypot writes, so `cowrie_parser.parse_cowrie_file` /
    `build_record` consume them with no special casing.
    """
    if label not in LABEL_TO_IDX:
        raise ValueError(f"unknown micro-state {label!r}")

    if label in REAL_COMMAND_COUNTS:
        # Real sessions of these classes are a single action -- see
        # REAL_COMMAND_COUNTS. A multi-state walk here produces a session shape
        # the honeypot has never recorded, and no gap model can hide that.
        seq = [label]
    else:
        seq = _sequence_ending_at(label, rng, min_len=min_len, max_len=max_len)
    skeleton, issued, did_login = _build_skeleton(label, seq, rng)

    if t_start is None:
        # Spread over the real capture's own 13-day window, so the calendar
        # features carry genuine spread. The frozen build gave all 60,000
        # real-derived netflow rows ONE shared `t_start`, which is why
        # `session_hour` is 98.1% hour 22 and `is_business_hours` is constant
        # (DATA_INTEGRITY.md 3c).
        t_start = rng.uniform(1_793_000_000.0, 1_793_000_000.0 + 13 * 86400)

    eventids = [e[0] for e in skeleton]
    ts = _event_timestamps(t_start, eventids, rng,
                           did_login=did_login, n_commands=len(issued),
                           label=label)
    duration = ts[-1] - ts[0]            # DERIVED from the event stream

    sid = session_id or f"{rng.getrandbits(48):012x}"
    sess_uuid = str(_uuid.UUID(int=rng.getrandbits(128), version=4))
    ip = src_ip or (lambda b: f"{b[0]}.{b[1]}.{b[2]}.{rng.randint(1, 254)}")(
        rng.choice(_DOC_BLOCKS))
    sport = _src_port(rng)

    events: List[dict] = []
    for (eventid, payload), t in zip(skeleton, ts):
        ev = {
            "session": sid, "protocol": "ssh",
            "src_ip": ip, "src_port": sport,
            "dst_ip": _DST_IP, "dst_port": _DST_PORT,
        }
        ev.update(payload)
        ev["eventid"] = eventid
        ev["sensor"] = _SENSOR
        ev["uuid"] = sess_uuid
        ev["timestamp"] = _ts(t)
        if eventid == "cowrie.session.closed":
            ev["duration_ms"] = int(round(duration * 1000))
            ev["message"] = f"Connection lost after {ev['duration_ms']} milliseconds"
        elif eventid == "cowrie.session.connect":
            ev["message"] = (f"New connection: {ip}:{sport} "
                             f"({_DST_IP}:{_DST_PORT}) [session: {sid}]")
        elif eventid == "cowrie.log.closed":
            ev["duration_ms"] = int(round(duration * 1000))
            ev["message"] = (f"Closing TTY Log: {payload.get('ttylog','')} "
                             f"after {ev['duration_ms']} milliseconds")
        elif eventid in ("cowrie.command.input", "cowrie.command.failed"):
            ev["message"] = f"CMD: {payload.get('input','')}"
        elif eventid in ("cowrie.login.success", "cowrie.login.failed"):
            verb = "succeeded" if eventid.endswith("success") else "failed"
            ev["message"] = (f"login attempt [{payload.get('username','')}/"
                             f"{payload.get('password','')}] {verb}")
        else:
            ev["message"] = ""
        events.append(ev)

    return events, seq


# ── Balanced corpus ──────────────────────────────────────────────────────────
def generate_sessions(n_total: int,
                      seed: int = 42,
                      labels: Optional[Sequence[str]] = None,
                      per_class: Optional[int] = None
                      ) -> Iterator[Tuple[str, List[str], List[dict]]]:
    """Yield `(intended_label, micro_state_sequence, events)`, balanced per class.

    `per_class` overrides the balance, INCLUDING the `MIN_SAMPLES_PER_CLASS`
    floor. Use it only for tests and smoke runs: the floor exists because the
    dataset targets a minimum 2,000 sessions per class, so a corpus built below
    it is not a training corpus. Without the override, `n_total` smaller than
    45 x 2,000 silently produces 90,000 sessions rather than the number asked
    for -- which is a surprise worth being able to opt out of.
    """
    rng = random.Random(seed)
    names = list(labels) if labels else [s["label"] for s in MICRO_STATES]
    per_cls = (int(per_class) if per_class is not None
               else max(MIN_SAMPLES_PER_CLASS, n_total // N_CLASSES))
    pool = _ip_pool(max(n_total, MIN_SAMPLES_PER_CLASS * N_CLASSES), rng)
    sid = 0
    for label in names:
        for _ in range(per_cls):
            events, seq = generate_cowrie_events(
                label, rng, src_ip=rng.choice(pool),
                session_id=f"sim{sid:09x}")
            sid += 1
            yield label, seq, events


def mark_repeat_visitors(records: List[dict]) -> List[dict]:
    """Set `seen_before` from `src_ip`, in corpus order.

    `tls_host.extract_tls_host` reads `seen_before` to produce
    `attacker_repeat_visitor`, but `cowrie_parser.build_record` does not emit it
    -- so going through the real parser would leave that feature dead again.

    The fix belongs HERE rather than in the generator, because it works
    identically for real and synthetic records: both carry `src_ip`, and whether
    an address has been seen before is a property of the corpus, not of the
    session. DATA_INTEGRITY.md 3c lists `attacker_repeat_visitor` as FIX for
    exactly this reason -- 641 real source addresses, top talker 3,527
    connections. The real path must call this too, or the feature is alive in
    training and dead at inference.
    """
    seen: set = set()
    for rec in records:
        ip = rec.get("src_ip", "")
        rec["seen_before"] = ip in seen
        seen.add(ip)
    return records


def generate_balanced_sessions(n_total: int, seed: int = 42,
                               per_class: Optional[int] = None):
    """Balanced synthetic corpus, built by parsing generated Cowrie events.

    Every field comes out of `cowrie_parser.build_record()` -- the same function
    the live pipeline and the real-data build call -- so no derived feature is
    ever generated. On top of the parser's 22 contract fields this adds the label
    bookkeeping described in the module docstring:
    `parser_micro_state`, `parser_sequence`, `label_agrees`, `label_source`,
    plus `micro_state_label_idx`, `phase` and `seen_before`.

    Returns a shuffled `pandas.DataFrame`.
    """
    import pandas as pd
    from src.parsers.cowrie_parser import build_record

    rows: List[dict] = []
    for label, seq, events in generate_sessions(n_total, seed, per_class=per_class):
        rec = build_record(events)
        if rec is None:
            continue
        parser_label = rec["micro_state"]
        parser_seq = rec["micro_state_sequence"]
        idx = LABEL_TO_IDX[label]
        rec.update({
            "micro_state":           label,          # intended -- the training target
            "micro_state_sequence":  ",".join(seq),  # the kill-chain walk
            "micro_state_label_idx": idx,
            "phase":                 IDX_TO_PHASE[idx],
            "parser_micro_state":    parser_label,   # what the rule labeller said
            "parser_sequence":       parser_seq,
            "label_agrees":          parser_label == label,
            "label_source":          "generator",
            "source":                "simulated_cowrie_events",
        })
        rows.append(rec)

    mark_repeat_visitors(rows)
    df = pd.DataFrame(rows).sample(frac=1, random_state=seed).reset_index(drop=True)
    log.info("Generated %d sessions from Cowrie events (%d classes); "
             "parser agreement %.1f%%",
             len(df), N_CLASSES, 100.0 * df["label_agrees"].mean())
    return df


def agreement_report(df) -> "object":
    """Per-class agreement between the intended label and the rule labeller.

    This is the number that must be reported wherever these rows are used: the
    share of sessions whose generated label the live labeller would reproduce.
    It is low by construction -- `cowrie_parser` can only emit 18 of 45 classes
    -- and reporting it is the whole point of keeping both labels.
    """
    import pandas as pd
    g = df.groupby("micro_state").agg(
        n=("label_agrees", "size"),
        agree=("label_agrees", "mean"),
        parser_says=("parser_micro_state", lambda s: s.value_counts().idxmax()),
    )
    g["agree"] = (g["agree"] * 100).round(1)
    return g.sort_values("agree")


SYNTHETIC_SOURCE = "simulated_cowrie_events"


def parse_generated_log(path: Path) -> List[dict]:
    """Parse a log written by `write_jsonlines`, stamping the real provenance.

    WHY THIS EXISTS, AND IT IS NOT A NICETY. `build_record()` hard-codes
    `source: "cowrie_real"`, because until now it only ever saw real Cowrie logs.
    Parse a generated log with `parse_closed_sessions()` and every row comes back
    claiming to be real honeypot traffic.

    This project has already been burned by exactly that confusion: 15,000
    teammate-generated Cowrie sessions were described as real for months, and
    correcting it is the whole of the provenance note in CLAUDE.md and
    DECISIONS.md. A generator that can produce logs indistinguishable from the
    real capture MUST ship the way to tell them apart.

    Two independent markers survive, and both are checked here: `source` is
    rewritten, and the events carry `sensor: "synthetic-cowrie-01"` rather than
    the real capture's `7b0b4b6a20d0`, so a mixed directory can always be split
    back apart even if a record loses its `source`.
    """
    from src.parsers.cowrie_parser import build_record, parse_cowrie_file

    out: List[dict] = []
    for events in parse_cowrie_file(Path(path)):
        rec = build_record(events)
        if rec is None:
            continue
        if any(e.get("sensor") != _SENSOR for e in events):
            raise ValueError(
                f"{path}: session {rec['session_id']!r} carries a sensor id that "
                f"is not {_SENSOR!r}. This file mixes generated and real "
                f"sessions; refusing to stamp it as synthetic.")
        rec["source"] = SYNTHETIC_SOURCE
        out.append(rec)
    return mark_repeat_visitors(out)


def write_jsonlines(out_path: Path, n_total: int, seed: int = 42,
                    per_class: Optional[int] = None) -> Dict[str, int]:
    """Write the corpus as a Cowrie-format JSON log. Returns per-label counts.

    The output IS a Cowrie log -- `cowrie_parser.parse_cowrie_file()` reads it
    directly, and so would any other Cowrie tooling. Read it back with
    `parse_generated_log()`, not `parse_closed_sessions()`, or the records come
    back labelled `cowrie_real`.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    counts: Dict[str, int] = {}
    with out_path.open("w", encoding="utf-8") as fh:
        for label, _seq, events in generate_sessions(n_total, seed,
                                                     per_class=per_class):
            for ev in events:
                fh.write(json.dumps(ev) + "\n")
            counts[label] = counts.get(label, 0) + 1
    return counts


def main() -> int:
    import argparse
    if len(sys.argv) > 1 and sys.argv[1] == "build-gaps":
        ap = argparse.ArgumentParser(prog="cowrie_simulator build-gaps")
        ap.add_argument("_cmd")
        ap.add_argument("--logs", required=True, help="dir holding cowrie.json*")
        ap.add_argument("--out", default=None)
        ap.add_argument("--per-pool", type=int, default=1500)
        a = ap.parse_args()
        sizes = build_gap_pools(a.logs, a.out, a.per_pool)
        print(f"wrote {len(sizes)} gap pools to {a.out or _GAP_POOLS_PATH}")
        for k, v in sizes.items():
            if v >= _MIN_POOL:
                print(f"  {k:<48} {v:>6}")
        return 0

    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--out", default="data/processed/cowrie_sim/cowrie.json",
                    help="Cowrie-format JSON log to write")
    ap.add_argument("--n-total", type=int, default=N_CLASSES * MIN_SAMPLES_PER_CLASS)
    ap.add_argument("--per-class", type=int, default=None,
                    help="sessions per class, overriding the 2,000 floor "
                         "(tests and smoke runs only)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--report", action="store_true",
                    help="also parse the corpus and print the agreement table")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    counts = write_jsonlines(Path(args.out), args.n_total, args.seed,
                             per_class=args.per_class)
    print(f"wrote {sum(counts.values())} sessions to {args.out}")

    if args.report:
        df = generate_balanced_sessions(args.n_total, args.seed,
                                        per_class=args.per_class)
        print(f"\nparser agreement overall: {100.0*df['label_agrees'].mean():.1f}%")
        print(agreement_report(df).to_string())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
