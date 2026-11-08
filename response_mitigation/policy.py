"""
response_mitigation/policy.py

The policy table: turns one MT3 verdict into the actions we want. Pure
function -- no files, no network, no clock -- so every row is easy to test.

Whether an action is *allowed* (never-block list, caps, kill switch, mode) is
the engine's job, not this module's. This only says what we would like.

Rows (see MITIGATION_DESIGN.md section 7):

    divert_attack      phase >= divert_min_phase, confident        -> DIVERT
    late_stage_alert   phase >= alert_min_phase, confident         -> ALERT
    repeat_offender    phase >= deny_min_phase, confident, and the
                       IP has had >= deny_repeat_sessions sessions -> DENY
    observe_only       none of the above                           -> OBSERVE

"Confident" means confidence >= min_confidence. A NaN confidence is never
confident, so it can only ever be observed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .models import Action, PlannedAction, Verdict

_MAX_PHASE = 8   # kill-chain phases are 0..8


@dataclass(frozen=True)
class PolicyConfig:
    # The defaults for the first two equal the gateway's MT3_AUTO_BLACKLIST_*
    # defaults, so DIVERT behaves exactly as the inline blacklist does today.
    min_confidence: float = 0.5
    divert_min_phase: int = 1
    # How strong a verdict must be before DIVERT may override an explicit
    # whitelist. Stricter than the two above on purpose: overriding a human trust
    # decision should need more evidence than blocking a stranger. DENY never
    # overrides a whitelist at all. See response_mitigation/safelist.py and
    # HONEYPOT_AUDIT.md PART 3 (the whitelist bypass).
    whitelist_override_min_phase: int = 2
    whitelist_override_min_confidence: float = 0.90
    # The rest are proposals that need a team decision (design doc, section 15).
    alert_min_phase: int = 7
    deny_min_phase: int = 4
    deny_repeat_sessions: int = 3
    deny_ttl_s: int = 24 * 3600

    def __post_init__(self) -> None:
        if not 0.0 <= self.min_confidence <= 1.0:
            raise ValueError(f"min_confidence={self.min_confidence}: must be between 0 and 1")
        if not 0.0 <= self.whitelist_override_min_confidence <= 1.0:
            raise ValueError(
                f"whitelist_override_min_confidence="
                f"{self.whitelist_override_min_confidence}: must be between 0 and 1")
        # Invariant: overriding an explicit trust decision must never be EASIER
        # than blocking a stranger. Clamped rather than raised, so raising
        # divert_min_phase above the override default stays a valid config instead
        # of an error -- an explicitly stricter override is still honoured.
        object.__setattr__(self, "whitelist_override_min_phase",
                           max(self.whitelist_override_min_phase, self.divert_min_phase))
        object.__setattr__(self, "whitelist_override_min_confidence",
                           max(self.whitelist_override_min_confidence, self.min_confidence))
        for name in ("divert_min_phase", "alert_min_phase", "deny_min_phase",
                     "whitelist_override_min_phase"):
            value = getattr(self, name)
            if not 0 <= value <= _MAX_PHASE:
                raise ValueError(f"{name}={value}: must be between 0 and {_MAX_PHASE}")
        if self.deny_repeat_sessions < 1:
            raise ValueError(f"deny_repeat_sessions={self.deny_repeat_sessions}: must be at least 1")
        if self.deny_ttl_s < 1:
            raise ValueError(f"deny_ttl_s={self.deny_ttl_s}: must be at least 1 second")


def _what(v: Verdict) -> str:
    return f"MT3 {v.micro_state} (phase {v.phase} {v.phase_name}, conf {v.confidence:.2f})"


def plan(verdict: Verdict, cfg: PolicyConfig = PolicyConfig()) -> List[PlannedAction]:
    """The actions this verdict calls for, least drastic first.

    The order matters: the engine carries them out in this order, so if a limit
    stops it part-way, the reversible ones have already happened.
    Always returns at least one action; OBSERVE means "record only".
    """
    confident = verdict.confidence >= cfg.min_confidence   # NaN -> False
    planned: List[PlannedAction] = []

    if confident and verdict.phase >= cfg.divert_min_phase:
        planned.append(PlannedAction(
            Action.DIVERT, "divert_attack",
            f"{_what(verdict)} is an attempted attack; send to the honeypot and keep watching"))

    if confident and verdict.phase >= cfg.alert_min_phase:
        planned.append(PlannedAction(
            Action.ALERT, "late_stage_alert",
            f"{_what(verdict)} is late in the kill chain; a person should look"))

    if (confident and verdict.phase >= cfg.deny_min_phase
            and verdict.sessions_seen >= cfg.deny_repeat_sessions):
        planned.append(PlannedAction(
            Action.DENY, "repeat_offender",
            f"{_what(verdict)}; {verdict.sessions_seen} sessions from this address",
            ttl_s=cfg.deny_ttl_s))

    if not planned:
        if not confident:
            why = f"confidence {verdict.confidence:.2f} is below the {cfg.min_confidence:.2f} floor"
        else:
            why = f"phase {verdict.phase} ({verdict.phase_name}) is below the action threshold"
        planned.append(PlannedAction(Action.OBSERVE, "observe_only", f"{why}; record only"))

    return planned
