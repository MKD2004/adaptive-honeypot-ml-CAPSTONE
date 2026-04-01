"""
traffic_gateway/ip_classifier.py

IP state machine — single source of truth for every IP's trust level.

State diagram:
                                                 score ≥ BLACKLIST
  ┌─────────┐  score ≥ SUSPICIOUS  ┌────────────┐ ──────────────► ┌─────────────┐
  │ UNKNOWN │ ──────────────────►  │ SUSPICIOUS │                  │ BLACKLISTED │
  └─────────┘                      └────────────┘ ◄──────────────  └──────┬──────┘
                                                  strike_limit             │
                                                                           │ min time + ML score < PROMOTE
                                                                           ▼
                                                                    ┌──────────────┐
                                                                    │  PROBATION   │
                                                                    └──────┬───────┘
                                                                           │ probation time + no strikes
                                                                           ▼
                                                                    ┌──────────────┐
                                                                    │ WHITELISTED  │
                                                                    └──────────────┘
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Dict, List, Optional

from .config import CONFIG
from . import gateway_logger as glog
from .gateway_logger import GatewayEvent


# ── State enum ────────────────────────────────────────────────────────────────
class IPStatus(str, Enum):
    UNKNOWN     = "unknown"
    SUSPICIOUS  = "suspicious"
    BLACKLISTED = "blacklisted"
    PROBATION   = "probation"    # watched but on a path to being trusted
    WHITELISTED = "whitelisted"


# ── Per-IP record ─────────────────────────────────────────────────────────────
@dataclass
class IPRecord:
    ip: str
    status: IPStatus = IPStatus.UNKNOWN

    # Timestamps (ISO strings so they survive JSON round-trips)
    first_seen:       str = field(default_factory=lambda: _utcnow())
    last_seen:        str = field(default_factory=lambda: _utcnow())
    status_changed_at: str = field(default_factory=lambda: _utcnow())

    # Traffic counters
    total_connections:  int = 0
    honeypot_sessions:  int = 0
    backend_sessions:   int = 0

    # Risk scoring
    risk_score:         float = 0.5   # 0.0 = safe, 1.0 = definite threat
    last_ml_score:      float = 0.5
    last_ml_assessment: str   = ""

    # Blacklist
    blacklisted_at:     Optional[str] = None
    blacklist_reason:   str           = ""

    # Promotion pipeline
    promoted_to_probation_at: Optional[str] = None
    fully_whitelisted_at:     Optional[str] = None
    promotion_reason:         str           = ""
    probation_strikes:        int           = 0

    # Review queue flags
    review_eligible: bool = False   # True once min blacklist time is served
    review_count:    int  = 0       # how many ML reviews this IP has gone through

    def seconds_in_current_status(self) -> float:
        changed = datetime.fromisoformat(self.status_changed_at)
        return (datetime.now(timezone.utc) - changed).total_seconds()

    def is_blacklist_review_eligible(self) -> bool:
        """True when IP has been blacklisted long enough to be re-evaluated."""
        if self.status != IPStatus.BLACKLISTED or not self.blacklisted_at:
            return False
        bl_time = datetime.fromisoformat(self.blacklisted_at)
        elapsed = (datetime.now(timezone.utc) - bl_time).total_seconds()
        return elapsed >= CONFIG.MIN_BLACKLIST_SEC

    def is_probation_complete(self) -> bool:
        """True when probation period has elapsed with no further misbehaviour."""
        if self.status != IPStatus.PROBATION or not self.promoted_to_probation_at:
            return False
        if self.probation_strikes >= CONFIG.PROBATION_STRIKE_LIMIT:
            return False
        start = datetime.fromisoformat(self.promoted_to_probation_at)
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        return elapsed >= CONFIG.PROBATION_SEC


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Classifier ────────────────────────────────────────────────────────────────
class IPClassifier:
    """
    Thread-safe in-memory registry of IPRecords, persisted to disk as JSON.

    Every state transition goes through set_status() so logs and persistence
    are always in sync.
    """

    def __init__(self) -> None:
        self._records: Dict[str, IPRecord] = {}
        self._lock = RLock()
        self._load()

    # ── Read ───────────────────────────────────────────────────────────────
    def get(self, ip: str) -> IPRecord:
        with self._lock:
            if ip not in self._records:
                self._records[ip] = IPRecord(ip=ip)
            rec = self._records[ip]
            rec.last_seen = _utcnow()
            return rec

    def get_status(self, ip: str) -> IPStatus:
        return self.get(ip).status

    def all_records(self) -> List[IPRecord]:
        with self._lock:
            return list(self._records.values())

    def records_by_status(self, status: IPStatus) -> List[IPRecord]:
        with self._lock:
            return [r for r in self._records.values() if r.status == status]

    # ── Write ──────────────────────────────────────────────────────────────
    def set_status(
        self,
        ip: str,
        status: IPStatus,
        *,
        reason: str = "",
        risk_score: Optional[float] = None,
    ) -> IPRecord:
        """Transition an IP to a new status. Saves and logs automatically."""
        with self._lock:
            rec = self._records.setdefault(ip, IPRecord(ip=ip))
            old_status = rec.status
            rec.status = status
            rec.status_changed_at = _utcnow()

            if risk_score is not None:
                rec.risk_score = risk_score

            # Bookkeeping per target status
            if status == IPStatus.BLACKLISTED:
                rec.blacklisted_at    = _utcnow()
                rec.blacklist_reason  = reason
                rec.review_eligible   = False
            elif status == IPStatus.PROBATION:
                rec.promoted_to_probation_at = _utcnow()
                rec.promotion_reason         = reason
                rec.probation_strikes        = 0
            elif status == IPStatus.WHITELISTED:
                rec.fully_whitelisted_at = _utcnow()
                rec.promotion_reason     = reason

        self._save()

        glog.log_event(
            GatewayEvent.IP_CLASSIFIED, ip,
            extra={
                "old_status": old_status.value,
                "new_status": status.value,
                "reason":     reason,
                "risk_score": risk_score,
            },
        )
        return rec

    def update_risk_score(self, ip: str, score: float) -> None:
        with self._lock:
            rec = self._records.setdefault(ip, IPRecord(ip=ip))
            rec.risk_score  = score
            rec.last_seen   = _utcnow()
        self._save()

    def update_ml_assessment(self, ip: str, score: float, reasoning: str) -> None:
        with self._lock:
            rec = self._records.setdefault(ip, IPRecord(ip=ip))
            rec.last_ml_score      = score
            rec.last_ml_assessment = reasoning
            rec.review_count      += 1
        self._save()

    def increment_connection(self, ip: str, *, to_honeypot: bool) -> None:
        with self._lock:
            rec = self._records.setdefault(ip, IPRecord(ip=ip))
            rec.total_connections += 1
            if to_honeypot:
                rec.honeypot_sessions += 1
            else:
                rec.backend_sessions += 1

    def add_probation_strike(self, ip: str) -> int:
        """Increment strike counter and return new count."""
        with self._lock:
            rec = self._records.setdefault(ip, IPRecord(ip=ip))
            rec.probation_strikes += 1
            count = rec.probation_strikes
        self._save()
        return count

    def mark_review_eligible(self, ip: str) -> None:
        with self._lock:
            if ip in self._records:
                self._records[ip].review_eligible = True
        self._save()

    # ── Persistence ────────────────────────────────────────────────────────
    def _load(self) -> None:
        path = CONFIG.DATA_DIR / CONFIG.IP_RECORDS_FILE
        if not path.exists():
            return
        try:
            raw = json.loads(path.read_text())
            for ip, data in raw.items():
                data["status"] = IPStatus(data["status"])
                self._records[ip] = IPRecord(**data)
            glog.info("Loaded %d IP records from disk.", len(self._records))
        except Exception as exc:
            glog.error("Failed to load IP records: %s", exc)

    def _save(self) -> None:
        path = CONFIG.DATA_DIR / CONFIG.IP_RECORDS_FILE
        try:
            raw = {
                ip: {**asdict(rec), "status": rec.status.value}
                for ip, rec in self._records.items()
            }
            path.write_text(json.dumps(raw, indent=2, default=str))
        except Exception as exc:
            glog.error("Failed to persist IP records: %s", exc)


# Module-level singleton
classifier = IPClassifier()
