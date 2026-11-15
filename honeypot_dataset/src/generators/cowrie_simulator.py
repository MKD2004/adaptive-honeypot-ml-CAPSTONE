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
  - Does NOT edit `kill_chain_simulator.py`. Notebooks 01 and 03b call
    `generate_balanced_sessions()` and the frozen build used it, so it stays
    byte-compatible. This module imports FROM it (`KILL_CHAIN_DAG`, the source
    address pool, the ephemeral-port draw) and never the other way round, so the
    dependency runs one direction only.
  - Does NOT reuse `generate_event_timestamps` or `generate_session_sequence`,
    and both omissions are deliberate and measured -- see the gap-quantile block
    and `_sequence_ending_at` for why the pooled timing fit and the
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

# ── Measured inter-arrival gaps, PER EVENT TYPE ──────────────────────────────
# WHY NOT `kill_chain_simulator.generate_event_timestamps`. That function fits a
# three-component lognormal mixture to the POOLED real gap distribution and then
# shuffles the drawn gaps across the session. Pooling is the problem. Stratified
# by the event each gap arrives at, the real capture says the pacing is almost
# the OPPOSITE of intuition:
#
#   gap arriving at            n        p50 s     frac < 100 ms
#   command.input           84,815     0.0004         98.1%     <- fastest
#   client.version         112,478     0.0005         82.8%
#   session.closed         114,490     0.0470         54.4%
#   client.kex             110,726     0.1829         27.4%
#   log.closed              53,466     0.2364          0.1%
#   session.params          53,466     0.8840          0.0%
#   login.success          104,385     1.0127          0.1%     <- slowest common
#   client.size              1,269     1.6720          0.0%
#   file_upload                580    59.7255          1.2%
#   POOLED                 639,570     0.1817         42.5%
#
# Commands are the FASTEST events in a real Cowrie session, because the traffic
# is scripted bots pasting a command block -- not humans typing. Authentication
# and shell setup are the slow parts. A shuffled pooled draw gets this backwards
# and will happily put a 13-second idle pause between `connect` and
# `client.version`, which no real session contains.
#
# So gaps are drawn per event type by inverse-CDF sampling of the real quantile
# grid below (log-linear interpolation between levels, since the gaps span five
# orders of magnitude). Reproducing the real distribution directly beats fitting
# a parametric form to it: the grids are bimodal (82.8% of `client.version` gaps
# are sub-millisecond, the rest run to seconds) and no single lognormal fits that.
#
# CONSEQUENCE, AND IT IS THE POINT: `session_duration_s` is now the SUM of the
# generated gaps, not an independently drawn number. Duration, n_events,
# events_per_sec and commands_per_min are all COMPUTED from the event stream by
# `build_record` and the extractors. The frozen generator drew duration and
# n_events independently and let the timestamps be rescaled to fit, which is the
# same "generate what should be computed" mistake as the broken log1p pairs.
_Q_LEVELS: Tuple[float, ...] = (0.0, 0.05, 0.10, 0.25, 0.50, 0.75, 0.90, 0.95, 0.99, 1.00)

# The gap into `session.closed` is the one that MUST be split by session type --
# pooling it spans a factor of 7,000 and hides the idle timeout entirely:
#
#   session type            n        p50 s      p90 s     what it is
#   login + commands    52,843     0.00068     0.00096    closes the instant
#                                                          the shell exits
#   login, no commands  52,758     0.47519     1.02017    bot hangs up after
#                                                          authenticating
#   no login             8,889     4.61549   119.75893    scan connect left to
#                                                          rot until Cowrie's
#                                                          120 s idle timeout
#
# That 120 s cliff IS the `session.closed` p99 of 119.33 in the pooled grid, and
# it belongs to 8% of sessions. Keyed in `_sample_gap` via `_close_key()`.
_GAP_QUANTILES: Dict[str, Tuple[float, ...]] = {
    "cowrie.session.closed:login_cmd":
        (0.000353, 0.000584, 0.000597, 0.000622, 0.000677, 0.000746, 0.000961,
         0.002916, 0.018581, 175.007834),                        # n=52,843
    "cowrie.session.closed:login_nocmd":
        (0.000425, 0.043551, 0.064365, 0.144028, 0.475188, 0.595513, 1.020167,
         1.650137, 8.633660, 300.711041),                        # n=52,758
    "cowrie.session.closed:no_login":
        (0.000414, 0.000608, 0.000724, 0.214339, 4.615490, 22.402634,
         119.758932, 120.002069, 120.011182, 121.115121),        # n=8,889
    "cowrie.session.closed":
        (0.000353, 0.000597, 0.000616, 0.000684, 0.047005, 0.482699, 0.962759,
         4.175927, 119.330002, 300.711041),                      # n=114,490 pooled
    "cowrie.client.version":
        (0.000232, 0.000313, 0.000328, 0.000357, 0.000453, 0.022544, 0.351728,
         1.069712, 4.763479, 101.829510),                        # n=112,478
    "cowrie.client.kex":
        (0.000266, 0.000530, 0.000674, 0.074653, 0.182890, 0.244007, 0.322515,
         0.889968, 3.571490, 104.030257),                        # n=110,726
    "cowrie.login.success":
        (0.042794, 0.196807, 0.351097, 0.581543, 1.012735, 1.495806, 2.705587,
         5.298609, 17.241253, 117.457441),                       # n=104,385
    "cowrie.command.input":
        (0.000326, 0.000347, 0.000352, 0.000368, 0.000425, 0.018068, 0.068002,
         0.078072, 0.435299, 10.102933),                         # n=84,815
    "cowrie.session.params":
        (0.027905, 0.655641, 0.680933, 0.738203, 0.884024, 1.181320, 2.138575,
         5.576636, 9.874477, 262.571908),                        # n=53,466
    "cowrie.log.closed":
        (0.000421, 0.156672, 0.165449, 0.193481, 0.236429, 0.414681, 1.109676,
         2.734515, 5.133222, 299.155560),                        # n=53,466
    "cowrie.command.failed":
        (0.006760, 0.021180, 0.021366, 0.021765, 0.022656, 0.067793, 0.073104,
         0.074660, 0.082773, 0.735425),                          # n=2,535
    "cowrie.client.size":
        (0.412876, 0.916558, 1.046200, 1.292001, 1.671964, 2.766391, 4.969982,
         6.282329, 9.419098, 19.687291),                         # n=1,269
    "cowrie.login.failed":
        (0.000385, 0.447903, 0.547219, 0.682244, 1.113242, 2.807672, 7.460106,
         10.541151, 19.366091, 31.703608),                       # n=1,216
    "cowrie.session.file_upload":
        (0.000328, 21.485499, 25.505984, 34.549092, 59.725530, 138.085679,
         229.443831, 282.266800, 300.004595, 300.541831),        # n=580
    "cowrie.client.var":
        (0.290888, 0.304808, 0.307862, 0.322764, 0.335103, 0.350973, 0.364313,
         0.365801, 0.756231, 0.812946),                          # n=106
    "cowrie.session.file_download":
        (0.456054, 3.948769, 3.967697, 4.000776, 4.070902, 4.096183, 4.290676,
         4.387669, 4.758228, 4.900435),                          # n=31
}

# Pooled grid, for an event type with no measured grid of its own.
_GAP_QUANTILES_POOLED: Tuple[float, ...] = (
    0.000232, 0.000355, 0.000400, 0.000650, 0.181700, 0.784000, 1.345500,
    3.100000, 13.276000, 300.711041)                             # n=639,570

# The busiest real session ran 392.42 s. A generated session that sums past this
# is truncated by clamping its largest gap, not by rescaling every gap -- which
# is what compressed the long pauses in the previous design.
_DURATION_MAX = 400.0

# ── Long pauses belong to specific sessions, not spread evenly ───────────────
# The grids above have genuinely heavy tails (`session.closed` p99 = 119 s, the
# idle timeout). Drawing them independently per event spreads those pauses across
# every session, and the real capture says they are concentrated. Share of real
# sessions containing ANY inter-arrival gap over 30 s:
#
#   no login                n=  8,900    23.52%   <- scan connects that hang
#   login, 0 commands       n= 52,759     0.42%      until the idle timeout
#   login, 1-4 commands     n= 51,569     0.24%
#   login, 5+ commands      n=  1,273    37.31%   <- bot waiting on a payload
#
# A 65x spread between neighbouring buckets, so a single pooled rate is useless
# here -- this is the same trap DATA_INTEGRITY.md section 7 records ("pooled
# 2.3% vs 78.1% for deep sessions"). A session either qualifies for the tail or
# has every gap capped at 30 s.
#
# NOTE the deep-session figure moved between captures: 78.1% on the 8-day
# capture (507 sessions), 37.3% here on the 13-day one (1,273 sessions). These
# constants follow the 13-day capture, because that is the data they are
# calibrated against.
_LONG_PAUSE_CAP = 30.0
P_LONG_PAUSE_NO_LOGIN   = 0.235
P_LONG_PAUSE_NO_CMDS    = 0.004
P_LONG_PAUSE_FEW_CMDS   = 0.002      # 1-4 commands
P_LONG_PAUSE_MANY_CMDS  = 0.373      # 5 or more

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


def _sample_gap(eventid: str, rng: random.Random) -> float:
    """One inter-arrival gap, drawn from the real distribution for `eventid`.

    Inverse-CDF sampling on the measured quantile grid, interpolated in LOG space
    because the grids span 0.0002 s to 300 s. Log interpolation is what keeps the
    sub-millisecond bulk sub-millisecond: linear interpolation between the 50th
    (0.000425 s) and 75th (0.018 s) percentiles of `command.input` would put most
    of that band two orders of magnitude too high, and `frac_sub100ms` with it.
    """
    import math
    grid = _GAP_QUANTILES.get(eventid, _GAP_QUANTILES_POOLED)
    u = rng.random()
    for i in range(len(_Q_LEVELS) - 1):
        lo, hi = _Q_LEVELS[i], _Q_LEVELS[i + 1]
        if lo <= u <= hi:
            v_lo, v_hi = grid[i], grid[i + 1]
            w = (u - lo) / (hi - lo)
            if v_lo > 0.0 and v_hi > 0.0:
                return math.exp(math.log(v_lo) + w * (math.log(v_hi) - math.log(v_lo)))
            return v_lo + w * (v_hi - v_lo)
    return grid[-1]


def _long_pause_probability(did_login: bool, n_commands: int) -> float:
    """Chance this session contains a gap over 30 s -- see the constants above."""
    if not did_login:
        return P_LONG_PAUSE_NO_LOGIN
    if n_commands == 0:
        return P_LONG_PAUSE_NO_CMDS
    if n_commands <= 4:
        return P_LONG_PAUSE_FEW_CMDS
    return P_LONG_PAUSE_MANY_CMDS


def _event_timestamps(t_start: float,
                      eventids: Sequence[str],
                      rng: random.Random,
                      *,
                      did_login: bool = True,
                      n_commands: int = 0) -> List[float]:
    """Ascending timestamps for an event stream, one gap drawn per event type.

    `session_duration_s` is the sum of these gaps -- derived, never drawn. A
    stream that sums past the longest real session (392.42 s) has its single
    largest gap trimmed, so the long pauses that remain keep their true length
    instead of every gap being squeezed proportionally.

    Whether this session is allowed a gap over 30 s is decided once, from its
    shape, rather than per gap -- the real rate ranges from 0.24% to 37% across
    neighbouring session types.
    """
    n = len(eventids)
    if n <= 1:
        return [float(t_start)]
    allow_pause = rng.random() < _long_pause_probability(did_login, n_commands)
    close_key = ("cowrie.session.closed:"
                 + ("login_cmd" if did_login and n_commands > 0
                    else "login_nocmd" if did_login else "no_login"))
    gaps = []
    for i in range(n - 1):
        nxt = eventids[i + 1]
        g = _sample_gap(close_key if nxt == "cowrie.session.closed" else nxt, rng)
        if not allow_pause and g > _LONG_PAUSE_CAP:
            # Redraw once, then clamp. Redrawing first keeps the bulk of the
            # distribution intact instead of piling probability mass onto the
            # cap itself, which would show up as a spike at exactly 30 s.
            g = _sample_gap(close_key if nxt == "cowrie.session.closed" else nxt, rng)
            g = min(g, _LONG_PAUSE_CAP)
        gaps.append(g)

    # Being ALLOWED a pause is not the same as drawing one: a long gap sits in
    # the top few percent of its grid, so an allowed session usually still came
    # out short and the realised rate landed near 4% against a measured 37%.
    # So the pause is placed deliberately when the session qualifies -- the
    # probability above is the rate of sessions that HAVE one, which is what was
    # measured.
    if allow_pause and not any(g > _LONG_PAUSE_CAP for g in gaps):
        # Never on a command gap: 98.1% of real `command.input` gaps are
        # sub-100 ms, because the bot pastes its block. The pause is the
        # honeypot waiting -- an idle timeout before `session.closed`, or a
        # transfer mid-session.
        spots = [i for i in range(n - 1)
                 if eventids[i + 1] not in ("cowrie.command.input",
                                            "cowrie.command.failed")]
        if spots:
            i = spots[-1] if not did_login else rng.choice(spots)
            gaps[i] = rng.uniform(_LONG_PAUSE_CAP, 120.0)
    total = sum(gaps)
    if total > _DURATION_MAX:
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
    repeat = 1
    if rng.random() < P_SCRIPTED_BOT:
        repeat = rng.randint(2, 5)
    per_state = _commands_for_sequence(seq, rng, repeat=repeat)
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
                           did_login=did_login, n_commands=len(issued))
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
