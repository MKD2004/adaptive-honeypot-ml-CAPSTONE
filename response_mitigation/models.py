"""
response_mitigation/models.py

The small data shapes the mitigation layer passes around. No behaviour and no
I/O live here, so every other module can import it freely.
"""
from __future__ import annotations

import enum
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


class Mode(str, enum.Enum):
    """How much the layer may do. Set once, by MITIGATION_MODE."""
    OFF = "off"
    OBSERVE = "observe"
    ENFORCE = "enforce"


class Action(str, enum.Enum):
    OBSERVE = "observe"   # write it down, nothing else
    DIVERT = "divert"     # gateway blacklist: send to the honeypot, keep watching
    DENY = "deny"         # firewall drops the source for a limited time
    ALERT = "alert"       # tell a human


class Outcome(str, enum.Enum):
    APPLIED = "applied"
    WOULD_APPLY = "would_apply"   # observe mode: this is what would have happened
    SKIPPED = "skipped"           # a safety check or a limit said no; see `detail`
    FAILED = "failed"             # we tried and the executor raised; see `detail`


@dataclass(frozen=True)
class Verdict:
    """What MT3 said about one closed session, plus what we know of its source."""
    ip: str
    phase: int
    phase_name: str
    micro_state: str
    confidence: float
    session_id: str = ""
    sessions_seen: int = 1   # sessions from this IP so far, including this one


@dataclass(frozen=True)
class PlannedAction:
    """One thing the policy wants done. It has not been checked or carried out."""
    action: Action
    rule: str                      # short, stable id of the policy row
    reason: str                    # one sentence for the audit log
    ttl_s: Optional[int] = None    # only DENY has a lifetime


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _finite(value: float) -> Optional[float]:
    """NaN and infinity are not valid JSON, so they are written as null."""
    return value if math.isfinite(value) else None


@dataclass(frozen=True)
class Decision:
    """The audit-log entry: one planned action, what happened to it, and why."""
    verdict: Verdict
    planned: PlannedAction
    mode: Mode
    outcome: Outcome
    detail: str = ""
    decision_id: str = field(default_factory=_new_id)
    ts: str = field(default_factory=_now_iso)

    def to_record(self) -> Dict[str, Any]:
        v, p = self.verdict, self.planned
        return {
            "decision_id": self.decision_id,
            "ts": self.ts,
            "mode": self.mode.value,
            "ip": v.ip,
            "session_id": v.session_id,
            "action": p.action.value,
            "rule": p.rule,
            "reason": p.reason,
            "ttl_s": p.ttl_s,
            "outcome": self.outcome.value,
            "detail": self.detail,
            "phase": v.phase,
            "phase_name": v.phase_name,
            "micro_state": v.micro_state,
            "confidence": _finite(float(v.confidence)),
            "sessions_seen": v.sessions_seen,
        }
