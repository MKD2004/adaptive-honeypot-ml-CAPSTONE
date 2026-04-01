"""
traffic_gateway/whitelist_promoter.py

Whitelist Promotion Engine
══════════════════════════

This module implements the pipeline that allows a blacklisted IP to earn its
way back to trusted status, driven by the ML risk model.

──────────────────────────────────────────────────────────────────
Pipeline stages
──────────────────────────────────────────────────────────────────

  BLACKLISTED
      │
      │  ① Wait MIN_BLACKLIST_SEC (IP must have served minimum time)
      │
      ▼
  REVIEW QUEUE  ←── background loop runs every REVIEW_INTERVAL_SEC
      │
      │  ② Call ML model (ml_risk_assessment stub → CNN-LSTM in Phase 3)
      │
      ├── score ≥ SCORE_PROMOTE  →  PROMOTION_DENIED  (stay blacklisted)
      │
      └── score < SCORE_PROMOTE  →  ③ Promote to PROBATION
                                          │
                                          │  Still routed to HONEYPOT
                                          │  (we keep watching)
                                          │
                                          ├── Misbehaves (score ≥ SCORE_PROBATION_STRIKE)
                                          │     → strike++
                                          │     → if strikes ≥ PROBATION_STRIKE_LIMIT
                                          │           → PROBATION_REVOKED → BLACKLISTED
                                          │
                                          └── Behaves for PROBATION_SEC with no strikes
                                                → ④ PROMOTION_APPROVED → WHITELISTED
                                                      │
                                                      │  Now routed to REAL BACKEND
                                                      │
                                                      └── score climbs back up?
                                                            → re-blacklist via gateway


──────────────────────────────────────────────────────────────────
Integration points
──────────────────────────────────────────────────────────────────

  • inspection_gateway  calls:  promoter.notify_session_closed(ip, session)
                                so the promoter can update probation strike counts
                                in real-time as sessions arrive.

  • WhitelistPromoter   runs:   promoter.run()  as an asyncio background task
                                started by the gateway on startup.

  • To plug in the real model:  replace reputation_scorer.ml_risk_assessment()
                                — the promoter's logic does not change.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import List

from .config import CONFIG
from .ip_classifier import IPStatus, IPRecord, classifier
from .blacklist_manager import blacklist_manager
from .session_tracker import Session
from .reputation_scorer import ml_risk_assessment
from . import gateway_logger as glog
from .gateway_logger import GatewayEvent


class WhitelistPromoter:
    """
    Background asyncio service that runs the promotion pipeline.

    Start with:
        asyncio.create_task(promoter.run())
    """

    def __init__(self) -> None:
        self._running = False

    # ── Background loop ────────────────────────────────────────────────────
    async def run(self) -> None:
        """
        Main event loop.  Runs forever until stop() is called.

        Every REVIEW_INTERVAL_SEC:
          1. Mark eligible blacklisted IPs as review-ready.
          2. Run ML assessment on review-ready IPs.
          3. Graduate or keep-blacklisted based on score.
          4. Check probation IPs for completion or violation.
        """
        self._running = True
        glog.info(
            "WhitelistPromoter started. Review interval: %ds, "
            "min blacklist time: %ds, probation: %ds.",
            CONFIG.REVIEW_INTERVAL_SEC,
            CONFIG.MIN_BLACKLIST_SEC,
            CONFIG.PROBATION_SEC,
        )

        while self._running:
            try:
                await self._mark_eligible_for_review()
                await self._review_blacklisted_ips()
                await self._check_probation_ips()
            except Exception as exc:
                glog.error("Promoter loop error: %s", exc)

            await asyncio.sleep(CONFIG.REVIEW_INTERVAL_SEC)

    def stop(self) -> None:
        self._running = False

    # ── Stage ①: Mark eligible IPs ────────────────────────────────────────
    async def _mark_eligible_for_review(self) -> None:
        """
        Walk all BLACKLISTED IPs and mark those that have served the minimum
        blacklist time as review_eligible so the next stage picks them up.
        """
        blacklisted: List[IPRecord] = classifier.records_by_status(
            IPStatus.BLACKLISTED
        )
        newly_eligible = 0
        for rec in blacklisted:
            if not rec.review_eligible and rec.is_blacklist_review_eligible():
                classifier.mark_review_eligible(rec.ip)
                newly_eligible += 1
                glog.log_event(
                    GatewayEvent.PROMOTION_ELIGIBLE, rec.ip,
                    extra={
                        "blacklisted_at":   rec.blacklisted_at,
                        "blacklist_reason": rec.blacklist_reason,
                    },
                )

        if newly_eligible:
            glog.info("%d IP(s) entered the promotion review queue.", newly_eligible)

    # ── Stage ②–③: Assess and promote / deny ─────────────────────────────
    async def _review_blacklisted_ips(self) -> None:
        """
        For each review-eligible BLACKLISTED IP:
          - Call the ML risk model (async stub → real model in Phase 3)
          - Promote to PROBATION if score < SCORE_PROMOTE
          - Log denial and keep blacklisted otherwise
        """
        candidates: List[IPRecord] = [
            r for r in classifier.records_by_status(IPStatus.BLACKLISTED)
            if r.review_eligible
        ]

        if not candidates:
            return

        glog.info("Reviewing %d blacklisted IP(s) for potential promotion.", len(candidates))

        for rec in candidates:
            score, reasoning = await ml_risk_assessment(rec.ip)
            classifier.update_ml_assessment(rec.ip, score, reasoning)

            glog.log_event(
                GatewayEvent.ML_ASSESSMENT, rec.ip,
                extra={
                    "score":        round(score, 4),
                    "reasoning":    reasoning,
                    "review_count": rec.review_count + 1,
                },
            )

            if score < CONFIG.SCORE_PROMOTE:
                # ── Promote to PROBATION ──────────────────────────────────
                glog.log_event(
                    GatewayEvent.PROMOTION_PROBATION, rec.ip,
                    extra={
                        "ml_score":  round(score, 4),
                        "reasoning": reasoning,
                        "message":   "IP entering probation; still routed to honeypot.",
                    },
                )
                blacklist_manager.promote_to_probation(
                    rec.ip,
                    ml_score=score,
                    reasoning=reasoning,
                )
            else:
                # ── Deny — keep blacklisted ───────────────────────────────
                glog.log_event(
                    GatewayEvent.PROMOTION_DENIED, rec.ip,
                    extra={
                        "ml_score":  round(score, 4),
                        "threshold": CONFIG.SCORE_PROMOTE,
                        "reasoning": reasoning,
                    },
                    level=logging.WARNING,
                )
                # Reset review_eligible so it will be re-evaluated next cycle
                # after it accumulates more session data.
                classifier.mark_review_eligible(rec.ip)   # keeps it in queue
                # But update the risk score so the record stays fresh
                classifier.update_risk_score(rec.ip, score)

    # ── Stage ④: Graduate probation → whitelist ───────────────────────────
    async def _check_probation_ips(self) -> None:
        """
        For each PROBATION IP:
          - If probation period is complete and strikes < limit → WHITELIST
          - If strikes ≥ limit → revoke and re-BLACKLIST (already done by notify)
          - Run an interim ML check mid-probation to catch early recidivism
        """
        probation_recs: List[IPRecord] = classifier.records_by_status(
            IPStatus.PROBATION
        )

        for rec in probation_recs:

            # ── Probation complete → graduate ─────────────────────────────
            if rec.is_probation_complete():
                score, reasoning = await ml_risk_assessment(rec.ip)

                if score < CONFIG.SCORE_PROMOTE:
                    blacklist_manager.promote_to_whitelist(
                        rec.ip,
                        ml_score=score,
                        reasoning=reasoning,
                    )
                    glog.log_event(
                        GatewayEvent.PROMOTION_APPROVED, rec.ip,
                        extra={
                            "ml_score":  round(score, 4),
                            "reasoning": reasoning,
                            "strikes":   rec.probation_strikes,
                        },
                    )
                else:
                    # Passed time but score crept back up — re-blacklist
                    glog.log_event(
                        GatewayEvent.PROBATION_REVOKED, rec.ip,
                        extra={
                            "reason":   "ml_score_elevated_at_graduation_check",
                            "ml_score": round(score, 4),
                        },
                        level=logging.WARNING,
                    )
                    blacklist_manager.revoke_probation(
                        rec.ip,
                        reason=f"Score {score:.3f} still above threshold at graduation check",
                        risk_score=score,
                    )
                continue

            # ── Mid-probation interim check ───────────────────────────────
            # Run an ML check halfway through probation to catch recidivists early.
            if rec.promoted_to_probation_at:
                probation_start = datetime.fromisoformat(rec.promoted_to_probation_at)
                elapsed = (
                    datetime.now(timezone.utc) - probation_start
                ).total_seconds()
                midpoint = CONFIG.PROBATION_SEC / 2

                # Only run once, near the midpoint (within one review interval)
                if midpoint <= elapsed <= midpoint + CONFIG.REVIEW_INTERVAL_SEC:
                    score, reasoning = await ml_risk_assessment(rec.ip)
                    classifier.update_ml_assessment(rec.ip, score, reasoning)

                    if score >= CONFIG.SCORE_BLACKLIST:
                        glog.log_event(
                            GatewayEvent.PROBATION_REVOKED, rec.ip,
                            extra={
                                "reason":   "mid_probation_score_spike",
                                "ml_score": round(score, 4),
                            },
                            level=logging.WARNING,
                        )
                        blacklist_manager.revoke_probation(
                            rec.ip,
                            reason=f"Mid-probation score spike: {score:.3f}",
                            risk_score=score,
                        )

    # ── Real-time callback (called by inspection_gateway per session) ──────
    async def notify_session_closed(self, ip: str, session: Session) -> None:
        """
        Called by the gateway immediately after each proxy session closes.

        Checks whether a PROBATION IP has misbehaved in this session and
        applies a strike if warranted.  If strikes hit the limit the IP is
        re-blacklisted immediately — no waiting for the review loop.
        """
        rec = classifier.get(ip)
        if rec.status != IPStatus.PROBATION:
            return

        # Re-score with the fresh session included
        score, reasoning = await ml_risk_assessment(ip)
        classifier.update_ml_assessment(ip, score, reasoning)

        if score >= CONFIG.SCORE_PROBATION_STRIKE:
            strike_count = classifier.add_probation_strike(ip)
            glog.log_event(
                GatewayEvent.PROBATION_STRIKE, ip,
                extra={
                    "strike":    strike_count,
                    "limit":     CONFIG.PROBATION_STRIKE_LIMIT,
                    "ml_score":  round(score, 4),
                    "reasoning": reasoning,
                },
                level=logging.WARNING,
            )

            if strike_count >= CONFIG.PROBATION_STRIKE_LIMIT:
                glog.log_event(
                    GatewayEvent.PROBATION_REVOKED, ip,
                    extra={
                        "reason":  "strike_limit_reached",
                        "strikes": strike_count,
                    },
                    level=logging.WARNING,
                )
                blacklist_manager.revoke_probation(
                    ip,
                    reason=f"Strike limit ({CONFIG.PROBATION_STRIKE_LIMIT}) reached.",
                    risk_score=score,
                )

    # ── Admin helpers ──────────────────────────────────────────────────────
    async def force_review(self, ip: str) -> dict:
        """
        Manually trigger an immediate ML review for a specific IP,
        regardless of how long it has been blacklisted.

        Useful for admin tooling / testing.
        """
        rec = classifier.get(ip)
        if rec.status not in (IPStatus.BLACKLISTED, IPStatus.PROBATION):
            return {"error": f"IP {ip} is not blacklisted or on probation.",
                    "status": rec.status.value}

        score, reasoning = await ml_risk_assessment(ip)
        classifier.update_ml_assessment(ip, score, reasoning)
        classifier.mark_review_eligible(ip)

        result = {
            "ip":        ip,
            "ml_score":  round(score, 4),
            "reasoning": reasoning,
            "action":    "none",
        }

        if rec.status == IPStatus.BLACKLISTED and score < CONFIG.SCORE_PROMOTE:
            blacklist_manager.promote_to_probation(ip, ml_score=score, reasoning=reasoning)
            result["action"] = "promoted_to_probation"
        elif rec.status == IPStatus.PROBATION and rec.is_probation_complete():
            if score < CONFIG.SCORE_PROMOTE:
                blacklist_manager.promote_to_whitelist(ip, ml_score=score, reasoning=reasoning)
                result["action"] = "promoted_to_whitelist"

        return result

    def queue_status(self) -> dict:
        """Return a snapshot of the promotion pipeline for monitoring."""
        blacklisted = classifier.records_by_status(IPStatus.BLACKLISTED)
        probation   = classifier.records_by_status(IPStatus.PROBATION)
        whitelisted = classifier.records_by_status(IPStatus.WHITELISTED)

        return {
            "blacklisted_total":    len(blacklisted),
            "blacklisted_eligible": sum(1 for r in blacklisted if r.review_eligible),
            "probation_total":      len(probation),
            "probation_graduating": sum(1 for r in probation if r.is_probation_complete()),
            "whitelisted_total":    len(whitelisted),
        }


# Module-level singleton
promoter = WhitelistPromoter()
