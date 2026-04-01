"""
traffic_gateway/blacklist_manager.py

CRUD layer for the blacklist and whitelist.

Provides simple add / remove / query operations that:
  - Update the in-memory IPClassifier (single source of truth for status)
  - Persist the lists to separate JSON files for easy manual inspection
  - Emit structured log events for every change

The whitelist_promoter module calls promote_to_probation() and
promote_to_whitelist(); the inspection_gateway calls blacklist() when
the reputation scorer triggers it.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Dict, Optional, Set

from .config import CONFIG
from . import gateway_logger as glog
from .gateway_logger import GatewayEvent
from .ip_classifier import IPStatus, classifier


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── List manager ──────────────────────────────────────────────────────────────
class BlacklistManager:
    """
    Manages the explicit blacklist and whitelist files.

    The canonical trust state lives in ip_classifier.classifier; these files
    are a secondary, human-readable record of deliberate decisions.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._blacklist: Dict[str, dict] = {}   # ip → {reason, ts, source}
        self._whitelist: Dict[str, dict] = {}
        self._load_blacklist()
        self._load_whitelist()

    # ── Blacklist ──────────────────────────────────────────────────────────
    def blacklist(
        self,
        ip: str,
        *,
        reason: str = "manual",
        source: str = "gateway",
        risk_score: Optional[float] = None,
    ) -> None:
        """Add an IP to the blacklist and update the classifier state."""
        with self._lock:
            self._blacklist[ip] = {
                "reason":     reason,
                "source":     source,
                "blacklisted_at": _utcnow(),
            }
            self._save_blacklist()

        classifier.set_status(
            ip, IPStatus.BLACKLISTED,
            reason=reason,
            risk_score=risk_score,
        )
        glog.log_event(
            GatewayEvent.IP_BLACKLISTED, ip,
            extra={"reason": reason, "source": source, "risk_score": risk_score},
            level=logging.WARNING,
        )

    def is_blacklisted(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blacklist

    def remove_from_blacklist(self, ip: str) -> bool:
        with self._lock:
            if ip not in self._blacklist:
                return False
            del self._blacklist[ip]
            self._save_blacklist()
        return True

    def get_blacklisted_ips(self) -> Set[str]:
        with self._lock:
            return set(self._blacklist.keys())

    # ── Whitelist ──────────────────────────────────────────────────────────
    def whitelist(
        self,
        ip: str,
        *,
        reason: str = "manual",
        source: str = "admin",
    ) -> None:
        """Manually whitelist an IP (bypasses the promotion pipeline)."""
        with self._lock:
            self._whitelist[ip] = {
                "reason":        reason,
                "source":        source,
                "whitelisted_at": _utcnow(),
            }
            self._save_whitelist()

        self.remove_from_blacklist(ip)
        classifier.set_status(ip, IPStatus.WHITELISTED, reason=reason)
        glog.log_event(
            GatewayEvent.PROMOTION_APPROVED, ip,
            extra={"reason": reason, "source": source},
        )

    def is_whitelisted(self, ip: str) -> bool:
        with self._lock:
            return ip in self._whitelist

    def get_whitelisted_ips(self) -> Set[str]:
        with self._lock:
            return set(self._whitelist.keys())

    # ── Promotion pipeline helpers (called by whitelist_promoter) ──────────
    def promote_to_probation(
        self,
        ip: str,
        *,
        ml_score: float,
        reasoning: str,
    ) -> None:
        """
        Move a BLACKLISTED IP to PROBATION.

        Traffic is still forwarded to the honeypot during probation — we keep
        watching — but the IP is flagged as "under evaluation" so the promoter
        knows to check it again after PROBATION_SEC.
        """
        self.remove_from_blacklist(ip)
        classifier.set_status(
            ip, IPStatus.PROBATION,
            reason=f"ML score {ml_score:.3f}: {reasoning}",
            risk_score=ml_score,
        )
        classifier.update_ml_assessment(ip, ml_score, reasoning)

        glog.log_event(
            GatewayEvent.PROMOTION_PROBATION, ip,
            extra={"ml_score": ml_score, "reasoning": reasoning},
        )

    def promote_to_whitelist(
        self,
        ip: str,
        *,
        ml_score: float,
        reasoning: str,
    ) -> None:
        """
        Fully whitelist an IP that has completed probation without incident.
        Traffic will now be forwarded to the real backend.
        """
        with self._lock:
            self._whitelist[ip] = {
                "reason":        f"Graduated from probation. ML={ml_score:.3f}",
                "source":        "whitelist_promoter",
                "whitelisted_at": _utcnow(),
            }
            self._save_whitelist()

        classifier.set_status(
            ip, IPStatus.WHITELISTED,
            reason=f"Probation complete. ML score {ml_score:.3f}: {reasoning}",
            risk_score=ml_score,
        )
        glog.log_event(
            GatewayEvent.PROMOTION_APPROVED, ip,
            extra={"ml_score": ml_score, "reasoning": reasoning},
        )

    def revoke_probation(
        self,
        ip: str,
        *,
        reason: str,
        risk_score: Optional[float] = None,
    ) -> None:
        """
        Send a misbehaving probation IP back to the blacklist.
        """
        self.blacklist(ip, reason=reason, source="probation_violation",
                       risk_score=risk_score)
        glog.log_event(
            GatewayEvent.PROBATION_REVOKED, ip,
            extra={"reason": reason},
            level=logging.WARNING,
        )

    # ── Persistence ────────────────────────────────────────────────────────
    def _path(self, filename: str) -> Path:
        return CONFIG.DATA_DIR / filename

    def _load_blacklist(self) -> None:
        p = self._path(CONFIG.BLACKLIST_FILE)
        if p.exists():
            try:
                self._blacklist = json.loads(p.read_text())
                glog.info("Loaded %d blacklisted IPs.", len(self._blacklist))
            except Exception as exc:
                glog.error("Failed to load blacklist: %s", exc)

    def _load_whitelist(self) -> None:
        p = self._path(CONFIG.WHITELIST_FILE)
        if p.exists():
            try:
                self._whitelist = json.loads(p.read_text())
                glog.info("Loaded %d whitelisted IPs.", len(self._whitelist))
            except Exception as exc:
                glog.error("Failed to load whitelist: %s", exc)

    def _save_blacklist(self) -> None:
        try:
            self._path(CONFIG.BLACKLIST_FILE).write_text(
                json.dumps(self._blacklist, indent=2)
            )
        except Exception as exc:
            glog.error("Failed to save blacklist: %s", exc)

    def _save_whitelist(self) -> None:
        try:
            self._path(CONFIG.WHITELIST_FILE).write_text(
                json.dumps(self._whitelist, indent=2)
            )
        except Exception as exc:
            glog.error("Failed to save whitelist: %s", exc)


# Module-level singleton
blacklist_manager = BlacklistManager()
