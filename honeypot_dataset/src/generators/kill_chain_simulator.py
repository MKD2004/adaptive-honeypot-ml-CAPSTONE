"""
src/generators/kill_chain_simulator.py
Markov-chain kill-chain simulator for synthetic session generation.
Produces operationally valid session sequences that respect the
MITRE ATT&CK kill-chain DAG defined in configs/schema.py.
Used to (a) validate TabSyn/GReaT output and (b) generate base
session structures for feature value assignment.
"""
from __future__ import annotations
import random
import logging
import numpy as np
import pandas as pd
from typing import List, Optional, Tuple

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from configs.schema import (
    KILL_CHAIN_DAG, LABEL_TO_IDX, IDX_TO_LABEL, IDX_TO_PHASE,
    MICRO_STATES, N_CLASSES, MIN_SAMPLES_PER_CLASS
)

log = logging.getLogger(__name__)

# ── Transition probability matrices per phase ─────────────────────────────────
# Higher weight = more likely to stay in recon vs. progress to next phase
# Calibrated to match real Cowrie session distributions
_PHASE_ADVANCE_PROB = {
    0: 0.35,   # Recon: 35% chance to advance (most sessions stop here)
    1: 0.55,   # Initial Access
    2: 0.60,   # Execution
    3: 0.65,   # Discovery
    4: 0.70,   # PrivEsc
    5: 0.75,   # Persistence
    6: 0.60,   # Evasion
    7: 0.80,   # Lateral
    8: 0.00,   # Exfil = terminal
}

# Starting state distribution (weighted by real Cowrie observation frequency)
_START_WEIGHTS = {
    "RECON_DNS":        0.05,
    "RECON_IP_SCAN":    0.35,   # most common entry point
    "RECON_VERSION_PROBE": 0.20,
    "RECON_OS_DETECT":  0.10,
    "RECON_VULN_SCAN":  0.15,
    "RECON_USER_ENUM":  0.15,
}

# Typical number of events per micro-state (mean, std)
_EVENTS_PER_STATE = {
    "ACCESS_BRUTE_SSH":   (45.0, 18.0),   # many login attempts
    "ACCESS_CRED_STUFF":  (120.0, 40.0),
    "EXEC_SHELL_OPEN":    (3.0, 1.5),
    "DISC_ENV_PROBE":     (8.0, 3.0),
    "DEFAULT":            (5.0, 2.0),
}


def sample_start_state(rng: random.Random) -> str:
    states  = list(_START_WEIGHTS.keys())
    weights = list(_START_WEIGHTS.values())
    return rng.choices(states, weights=weights, k=1)[0]


def sample_next_state(current: str, rng: random.Random) -> Optional[str]:
    """
    Sample the next micro-state from the DAG neighbours.
    Returns None if current is a terminal state.
    """
    neighbours = list(KILL_CHAIN_DAG.get(current, set()))
    if not neighbours:
        return None

    curr_phase = IDX_TO_PHASE.get(LABEL_TO_IDX.get(current, 0), 0)
    advance_p  = _PHASE_ADVANCE_PROB.get(curr_phase, 0.5)

    # Filter: same-phase vs. next-phase neighbours
    same_phase_nbrs = [n for n in neighbours
                       if IDX_TO_PHASE.get(LABEL_TO_IDX.get(n,0),0) == curr_phase]
    next_phase_nbrs = [n for n in neighbours
                       if IDX_TO_PHASE.get(LABEL_TO_IDX.get(n,0),0) > curr_phase]

    if rng.random() < advance_p and next_phase_nbrs:
        return rng.choice(next_phase_nbrs)
    elif same_phase_nbrs:
        return rng.choice(same_phase_nbrs)
    elif next_phase_nbrs:
        return rng.choice(next_phase_nbrs)
    return None


def generate_session_sequence(
        rng: random.Random,
        min_len: int = 1,
        max_len: int = 12,
        force_start: Optional[str] = None) -> List[str]:
    """
    Generate one valid kill-chain micro-state sequence.

    Returns:
        List of micro-state label strings in valid DAG order.
    """
    start = force_start if force_start else sample_start_state(rng)
    seq   = [start]
    length = rng.randint(min_len, max_len)

    while len(seq) < length:
        nxt = sample_next_state(seq[-1], rng)
        if nxt is None:
            break
        seq.append(nxt)

    return seq


def is_valid_sequence(states: List[str]) -> bool:
    """Return True if every transition in the sequence is DAG-valid."""
    for i in range(len(states) - 1):
        curr, nxt = states[i], states[i+1]
        allowed   = KILL_CHAIN_DAG.get(curr, set())
        if nxt != curr and nxt not in allowed:
            return False
    return True


def is_phase_monotone(states: List[str]) -> bool:
    """Phases must be non-decreasing (no backwards movement)."""
    phases = [IDX_TO_PHASE.get(LABEL_TO_IDX.get(s, 0), 0) for s in states]
    return all(phases[i] <= phases[i+1] for i in range(len(phases)-1))


def compute_kcvr(df: pd.DataFrame,
                 seq_col: str = "micro_state_sequence") -> float:
    """
    Kill-Chain Violation Rate — fraction of sessions with invalid sequences.
    Report this in Table 4 of the paper.
    CNN-LSTM (softmax): KCVR ~ 4-8%.  MT3 (CRF): KCVR = 0.00%.
    """
    violations = total = 0
    for seq_str in df[seq_col].dropna():
        states = [s.strip() for s in str(seq_str).split(",") if s.strip()]
        if len(states) < 2:
            continue
        total += 1
        if not is_valid_sequence(states) or not is_phase_monotone(states):
            violations += 1
    return round(violations / max(total, 1), 4)


def filter_invalid_sequences(df: pd.DataFrame,
                              seq_col: str = "micro_state_sequence") -> pd.DataFrame:
    """Remove rows whose micro-state sequence violates the kill-chain DAG."""
    if seq_col not in df.columns:
        log.warning("No sequence column '%s' — skipping filter", seq_col)
        return df

    def _valid(seq_str):
        if not seq_str or pd.isna(seq_str):
            return True
        states = [s.strip() for s in str(seq_str).split(",") if s.strip()]
        if len(states) < 2:
            return True
        return is_valid_sequence(states) and is_phase_monotone(states)

    mask    = df[seq_col].apply(_valid)
    removed = (~mask).sum()
    log.info("Kill-chain filter: removed %d / %d invalid sequences", removed, len(df))
    return df[mask].reset_index(drop=True)


# ──────────────────────────────────────────────────────────────────────────────
# Event timing
# ──────────────────────────────────────────────────────────────────────────────
# WHY THIS EXISTS. Until 2026-11-09 this generator emitted `t_start`, `t_end` and
# `n_events` but NO per-event timestamps. `extractors/temporal.py` falls back to a
# single synthetic inter-arrival time when `event_timestamps` has fewer than two
# entries -- `iat = [duration / (n_events - 1)]` -- and one value has no spread,
# no shape and no runs. Seven of the 24 temporal features therefore collapsed to
# constants across the whole frozen training set:
#
#     feature                 % rows == 0   distinct values (18,900 rows sampled)
#     burst_count                   99.6%         2
#     burst_mean_size               99.6%         2
#     frac_sub100ms                 99.6%         2
#     iat_cv                        98.2%       338
#     iat_skew                      98.3%       321
#     iat_kurt                      98.4%       297
#     inter_burst_gap_std           98.2%       338
#
# The LSTM branch learned nothing from them, and on the first real capture they
# were all non-zero -- which is most of why real sessions sit 226x outside the
# training distribution (REAL_DATA_2026-11-09.md section 4).
#
# CALIBRATION. The constants below are fitted to 283,432 inter-arrival times from
# 45,648 real internet-captured Cowrie sessions, not chosen by eye. Real gaps are
# bimodal: a sub-millisecond cluster of back-to-back protocol events, a
# network/human-paced middle, and a rare long idle pause.
#
#     pooled real IAT    p10 0.0004  p25 0.0007  p50 0.176  p75 0.723
#                        p90 1.618   p99 14.74
#     frac < 100ms 0.436    frac < 1s 0.827    frac > 30s 0.004
#
# A two-component mixture reproduces p50-p90 almost exactly but gives p99 ~5.6s
# against a real 14.7s, so a third rare idle component carries the tail.
# 0.30, not the 0.436 measured directly, and the difference is a correction not a
# fudge: short sessions compress their slow gaps when those are rescaled to fit
# the duration, and a compressed slow gap can land under 100 ms and read as a
# burst. Drawing 0.436 explicitly produced an EFFECTIVE sub-100ms share of 0.568
# against a real 0.411. 0.30 lands it on target.
IAT_FAST_P = 0.30                       # share of gaps drawn at machine speed
IAT_FAST_MU, IAT_FAST_SIGMA = -7.376, 0.604      # lognormal, median 0.63 ms
IAT_SLOW_MU, IAT_SLOW_SIGMA = -0.474, 1.047      # lognormal, median 0.62 s
# Long pauses are NOT a fixed per-gap probability, and that is measured. A fixed
# one cannot fit both ends of the real data at once:
#
#   real sessions, fraction with ANY inter-arrival gap over 30 s
#     0 commands  (shallow, ~1.9 s)   n=15,912     3.6%
#     1-2 commands         (~2.2 s)   n=29,221     0.3%
#     10+ commands        (~63.6 s)   n=   507    78.1%
#
# A busy session almost always contains a long pause -- the attacker is reading
# output, fetching a payload, or thinking -- while a drive-by scan never does.
# (Note the pooled figure across all real sessions is 2.3%, which is pure
# shallow-majority artefact: 97% of real sessions issue 0-2 commands. Calibrating
# to that number would have been wrong, and nearly was.)
#
# So the per-gap idle probability rises with the number of gaps. Fitted to the
# two anchors above via 1-(1-p)^n: p(4 gaps) = 0.0095 -> 3.7%, and
# p(38 gaps) = 0.039 -> 78%.
IAT_IDLE_P_BASE  = 0.006
IAT_IDLE_P_SLOPE = 0.00087
IAT_IDLE_P_MAX   = 0.15


def _idle_probability(n_gaps: int) -> float:
    """Per-gap chance of a long pause, as a function of how busy the session is."""
    return float(min(IAT_IDLE_P_BASE + IAT_IDLE_P_SLOPE * max(0, n_gaps),
                     IAT_IDLE_P_MAX))
IAT_IDLE_MU, IAT_IDLE_SIGMA = 2.60, 0.90         # lognormal, median ~13 s

_FAST_CEILING = 0.0999   # a "fast" gap must stay under the extractor's 100 ms
                         # burst threshold, or burst detection sees nothing

# Busiest real session in the 45,648-session capture had 41 events. 64 leaves
# headroom for deep synthetic phases without inventing 1,000-event sessions.
EVENTS_CEILING = 64

# Long pauses may consume at most this share of a session, so the slow filler
# gaps always have room left and the timestamp walk stays strictly increasing.
IDLE_BUDGET = 0.80


def generate_event_timestamps(t_start: float,
                              n_events: int,
                              duration_s: float,
                              rng: random.Random) -> List[float]:
    """Per-event timestamps with realistic burst structure.

    Returns `n_events` ascending epoch values beginning at `t_start` and ending
    at `t_start + duration_s`.

    A session with a single event is a single timestamp: there are no gaps, so
    no duration can be represented in the series. That is correct rather than a
    rounding failure, and it is why a `t_end - t_start == duration_s` check must
    skip `n_events == 1`.

    `duration_s` IS PRESERVED EXACTLY for every multi-event session, which is the
    point of the design. The
    session duration distribution is already used by `session_duration_s`,
    `log_session_duration`, `events_per_sec` and `commands_per_min`, so letting
    duration emerge from a sum of sampled gaps would quietly move four features
    that were never broken. Instead the fast gaps are drawn in ABSOLUTE terms and
    kept under 100 ms, and only the slow gaps are rescaled to absorb whatever
    time is left. Burst structure becomes real; nothing else moves.

    Fast and slow gaps are interleaved by shuffling rather than grouped, because
    the real data says so: `burst_count` has a median of 3 while
    `burst_mean_size` has a median of 1, i.e. a typical session holds three
    separate single-gap bursts, not one long run.
    """
    n_events = max(1, int(n_events))
    if n_events == 1:
        return [float(t_start)]

    n_gaps = n_events - 1
    duration_s = max(float(duration_s), 1e-6)

    # 1. class each gap
    p_idle = _idle_probability(n_gaps)
    kinds = []
    for _ in range(n_gaps):
        r = rng.random()
        if r < IAT_FAST_P:
            kinds.append("fast")
        elif r < IAT_FAST_P + p_idle:
            kinds.append("idle")
        else:
            kinds.append("slow")

    # At least one gap must be able to stretch, or the fast gaps alone would have
    # to account for the whole duration and none of them could stay under 100 ms.
    if not any(k == "slow" for k in kinds):
        kinds[rng.randrange(n_gaps)] = "slow"

    # 2. draw them
    gaps = []
    for k in kinds:
        if k == "fast":
            g = min(rng.lognormvariate(IAT_FAST_MU, IAT_FAST_SIGMA), _FAST_CEILING)
        elif k == "idle":
            g = rng.lognormvariate(IAT_IDLE_MU, IAT_IDLE_SIGMA)
        else:
            g = rng.lognormvariate(IAT_SLOW_MU, IAT_SLOW_SIGMA)
        gaps.append(g)

    # 3. Rescale ONLY the slow gaps. Fast gaps and long pauses are both drawn in
    # ABSOLUTE terms, and keeping the pauses absolute is what makes a deep session
    # look real. An earlier version rescaled pauses along with the slow filler,
    # which compressed them: a 69 s session with 38 gaps left each slow gap about
    # 1.8 s, so a 13 s pause was squeezed to nothing and only 43% of deep
    # sessions ended up with a gap over 30 s against a real 78%. Raising the idle
    # probability did not help (43.0% -> 43.3%) precisely because the rescaling,
    # not the draw, was the binding constraint.
    #
    # Pauses are collectively capped at IDLE_BUDGET of the session so the slow
    # gaps always keep some room and the walk stays strictly increasing.
    idle_idx = [i for i, k in enumerate(kinds) if k == "idle"]
    idle_total = sum(gaps[i] for i in idle_idx)
    budget = IDLE_BUDGET * duration_s
    if idle_total > budget and idle_total > 0.0:
        shrink = budget / idle_total
        for i in idle_idx:
            gaps[i] *= shrink
        idle_total = budget

    fast_total = sum(g for g, k in zip(gaps, kinds) if k == "fast")
    slow_total = sum(g for g, k in zip(gaps, kinds) if k == "slow")
    slack = duration_s - fast_total - idle_total

    if slack <= 0.0:
        # Duration is shorter than the fast gaps alone. Rare, but a short session
        # with many events hits it. Scale everything down; the gaps stay ordered
        # and sub-100 ms, so burst detection still sees a single long burst --
        # which is the truthful description of a session that fast.
        factor = duration_s / max(fast_total + idle_total + slow_total, 1e-12)
        gaps = [g * factor for g in gaps]
    else:
        factor = slack / max(slow_total, 1e-12)
        gaps = [g * factor if k == "slow" else g for g, k in zip(gaps, kinds)]

    # 4. interleave, then walk the gaps into timestamps
    rng.shuffle(gaps)
    out = [float(t_start)]
    acc = 0.0
    for g in gaps:
        acc += g
        out.append(float(t_start) + acc)
    # kill floating-point drift so t_end matches to the bit
    out[-1] = float(t_start) + duration_s
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Session identity and milestones
# ──────────────────────────────────────────────────────────────────────────────
# Four features were dead because the generator never emitted the keys their
# extractors read. Measured in the real capture, every one of 11,328 parsed
# sessions carries all of them:
#
#   src_port        -> src_is_ephemeral       (generator emitted nothing -> 0.0)
#   src_ip (reused) -> attacker_repeat_visitor (generator used a fresh random
#                                               10.x per session, so no IP was
#                                               ever seen twice)
#   t_first_auth    -> time_to_first_auth_s   (absent -> clamped to 0.0)
#   t_first_cmd     -> time_to_first_cmd_s    (absent -> clamped to 0.0)

# Real source ports, 11,328 sessions: median 46,542, 98.0% at or above 32768,
# 41.1% above 49151. Drawing uniformly from the Linux default ephemeral range
# reproduces that last figure almost exactly -- (60999-49152)/(60999-32768) =
# 0.42 against a measured 0.411 -- so no extra shaping is needed.
_EPHEMERAL_LO, _EPHEMERAL_HI = 32768, 60999
_NON_EPHEMERAL_P = 0.02          # the measured 2% that sit below the range

# Documentation ranges only (RFC 5737), never routable addresses. Same choice as
# heralding_simulator._random_public_ip, for the same reason: a synthetic corpus
# must not name real hosts. The previous 10.x addresses were RFC 1918 private
# space, which no internet attacker can come from.
_DOC_BLOCKS = ((192, 0, 2), (198, 51, 100), (203, 0, 113))

# Real capture: 641 distinct sources across 45,648 sessions, about 71 sessions
# per address; 108 sources and 105 sessions each within a single day. A bounded
# pool reproduces that, and it is the only way `seen_before` is ever true.
_IP_POOL_SESSIONS_PER_ADDR = 71


def _ip_pool(n_sessions: int, rng: random.Random) -> List[str]:
    """Addresses to draw from, sized so reuse matches the real capture."""
    size = max(8, min(3 * 254, n_sessions // _IP_POOL_SESSIONS_PER_ADDR))
    pool, seen = [], set()
    while len(pool) < size:
        b = rng.choice(_DOC_BLOCKS)
        ip = f"{b[0]}.{b[1]}.{b[2]}.{rng.randint(1, 254)}"
        if ip not in seen:
            seen.add(ip)
            pool.append(ip)
    return pool


def _src_port(rng: random.Random) -> int:
    if rng.random() < _NON_EPHEMERAL_P:
        return rng.randint(1024, _EPHEMERAL_LO - 1)
    return rng.randint(_EPHEMERAL_LO, _EPHEMERAL_HI)


def _milestones(event_ts: List[float], n_login: int, n_cmds: int
                ) -> Tuple[float, float]:
    """(t_first_auth, t_first_cmd), taken FROM the event series.

    Picked as members of `event_ts` rather than computed as independent offsets,
    so they cannot contradict the timestamps -- the same reason the derived
    features are computed rather than generated. `cowrie_parser` does exactly
    this for real sessions: the milestone IS one of the session's events.

    A session with no logins or no commands reports its start, which is what the
    real parser yields and what the extractor clamps to zero.
    """
    t0 = event_ts[0]
    n = len(event_ts)
    if n < 2:
        return t0, t0
    # Authentication follows the transport handshake: connect, version, kex.
    # Real median time-to-first-auth is 0.903 s in sessions whose median total
    # duration is 2.13 s, i.e. roughly the first third of the event series.
    auth_i = min(max(1, int(n * 0.30)), n - 1) if n_login > 0 else 0
    cmd_i = min(auth_i + 1, n - 1) if n_cmds > 0 else 0
    return event_ts[auth_i], event_ts[cmd_i]


def generate_balanced_sessions(n_total: int,
                                seed: int = 42) -> pd.DataFrame:
    """
    Generate n_total session skeleton records with valid kill-chain sequences,
    balanced across all 45 micro-state labels.

    Returns a DataFrame with columns:
        session_id, micro_state, micro_state_sequence,
        t_start, session_duration_s, n_events, n_commands,
        login_attempts, source
    """
    rng = random.Random(seed)
    np.random.seed(seed)

    labels  = [s["label"] for s in MICRO_STATES]
    per_cls = max(MIN_SAMPLES_PER_CLASS, n_total // N_CLASSES)

    records = []
    sid     = 0
    ip_pool = _ip_pool(max(n_total, MIN_SAMPLES_PER_CLASS * N_CLASSES), rng)
    ips_seen: set = set()

    for label in labels:
        label_idx = LABEL_TO_IDX[label]
        phase     = IDX_TO_PHASE[label_idx]

        for _ in range(per_cls):
            seq  = generate_session_sequence(rng, force_start=label, min_len=1, max_len=8)
            # Duration and event count, recalibrated 2026-11-09 against the real
            # capture. The old baselines (phase 0: median 33 s / 12 events;
            # phase 8: 812 s / 134 events) were wrong at both ends -- real
            # shallow sessions are far shorter and real sessions never got
            # anywhere near 134 events:
            #
            #   real n_commands   sessions   dur median   events median
            #   0                   15,912        1.91 s          5
            #   1-2                 29,221        2.25 s          8
            #   10-29                  507       63.56 s         41
            #
            # The phase ramp is KEPT -- a deeper attack genuinely does run longer
            # and noisier, and the real figures above confirm it. Only the
            # endpoints move: phase 0 now lands near real shallow traffic and
            # phase 8 near the busiest real sessions instead of 6x past them.
            #
            # This also moves session_duration_s, log_session_duration,
            # events_per_sec, commands_per_min and n_commands. That is deliberate
            # and takes effect only on a regenerate -- see DECISIONS.md.
            dur  = float(np.random.lognormal(mean=0.69 + phase*0.445, sigma=1.2))
            # Floor 2, not 1: a single-event session has no inter-arrival gap at
            # all, so it contributes nothing to any of the seven features this
            # change exists to revive. Ceiling 64: the lognormal tail reached
            # 1,139 events, while the busiest session in 45,648 real ones had 41.
            n_ev = int(np.clip(np.random.lognormal(mean=1.61 + phase*0.26, sigma=0.7),
                               2, EVENTS_CEILING))

            # Every Cowrie session involves at least one authentication attempt
            # -- that is how a session begins. The previous `n_login = 0` for
            # non-brute-force labels left time_to_first_auth_s at zero for 89%
            # of generated sessions, while all 11,328 real sessions carry a
            # t_first_auth with a median 0.903 s after connect. Brute-force and
            # credential-stuffing labels keep their heavy tail on top.
            n_login = 1
            if "BRUTE" in label or "CRED" in label:
                n_login = max(1, int(np.random.lognormal(mean=3.5, sigma=1.0)))
            # n_login cannot exceed the events available to carry it, or
            # n_commands below goes negative.
            n_login = max(1, min(n_login, max(1, n_ev - 1)))

            t_start = float(np.random.uniform(1_680_000_000, 1_712_400_000))
            # Per-event timestamps, so the burst / inter-arrival features are not
            # dead constants. See generate_event_timestamps for the calibration.
            ev_ts = generate_event_timestamps(t_start, n_ev, dur, rng)
            n_cmds = max(0, n_ev - n_login - 1)
            t_auth, t_cmd = _milestones(ev_ts, n_login, n_cmds)
            src_ip = rng.choice(ip_pool)
            seen_before = src_ip in ips_seen
            ips_seen.add(src_ip)

            records.append({
                "session_id":            f"sim_{sid:08d}",
                "micro_state":           label,
                "micro_state_label_idx": label_idx,
                "phase":                 phase,
                "micro_state_sequence":  ",".join(seq),
                "t_start":               t_start,
                "t_end":                 t_start + dur,
                "session_duration_s":    dur,
                "n_events":              n_ev,
                "event_timestamps":      ev_ts,
                "t_first_auth":          t_auth,
                "t_first_cmd":           t_cmd,
                "src_port":              _src_port(rng),
                # True when this address already appeared earlier in the corpus.
                # Reads straight into tls_host's `seen_before`, which drives
                # attacker_repeat_visitor.
                "seen_before":           seen_before,
                "n_commands":            n_cmds,
                "login_attempts":        n_login,
                "bytes_in":              int(np.random.lognormal(6.0 + phase*0.5, 1.5)),
                "bytes_out":             int(np.random.lognormal(5.5 + phase*0.3, 1.5)),
                "dst_port":              22,
                "protocol":              "ssh",
                "src_ip":                src_ip,
                "source":                "simulated",
                "associated_cve":        "",
            })
            sid += 1

    df = pd.DataFrame(records).sample(frac=1, random_state=seed).reset_index(drop=True)
    log.info("Generated %d balanced simulation sessions (%d classes)", len(df), N_CLASSES)
    return df
