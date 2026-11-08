"""
response_mitigation/engine.py

Takes one MT3 verdict and runs it through the six steps in MITIGATION_DESIGN.md
section 5: safety check, policy, mode, limits, do it, audit log.

What each mode lets through (set by MITIGATION_MODE):

                 DIVERT     ALERT       DENY
    off          -          -           -          engine does nothing at all
    observe      applied    would-apply would-apply
    enforce      applied    applied     applied only if MITIGATION_FIREWALL=1,
                                        otherwise would-apply

DIVERT is applied in observe mode because it is what the system already does
today (the auto-blacklist), it only sends the source to the honeypot, and it can
be undone. A kill-switch file turns the mode to `off` on the very next call.

The engine never raises into its caller: a failing executor or audit log is
logged, recorded where possible, and the next action still runs.
"""
from __future__ import annotations

import dataclasses
import logging
import threading
import time
import uuid
from collections import deque
from typing import Any, Callable, Deque, Dict, Iterable, List, Mapping, Optional, Protocol, Set

from .audit import AuditLog
from .blocklist import BlockEntry, BlocklistFile, iso_utc
from .config import MitigationConfig, load_config
from .executors.alert import CompositeAlertExecutor, LogAlertExecutor, WebhookAlertExecutor
from .executors.firewall import FirewallExecutor
from .executors.gateway import GatewayExecutor
from .models import Action, Decision, Mode, Outcome, PlannedAction, Verdict
from .policy import plan
from .safelist import Safelist, canonical

log = logging.getLogger("response_mitigation")

_HOUR_S = 3600


class Executor(Protocol):
    def skip_reason(self, verdict: Verdict, planned: PlannedAction) -> Optional[str]:
        """Why this executor would do nothing (e.g. already done), or None."""

    def apply(self, verdict: Verdict, planned: PlannedAction) -> str:
        """Do it. Return a short note for the audit log. Raise on failure."""


class MitigationEngine:
    def __init__(self,
                 config: MitigationConfig,
                 *,
                 safelist: Safelist,
                 audit: AuditLog,
                 executors: Mapping[Action, Executor],
                 divert_enabled: bool = True,
                 blocklist: Optional[BlocklistFile] = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.config = config
        self._blocklist = blocklist
        self._safelist = safelist
        self._audit = audit
        self._executors = dict(executors)
        self._divert_enabled = divert_enabled
        self._clock = clock
        self._lock = threading.RLock()
        self._deny_times: Deque[float] = deque()   # when each applied DENY happened
        self._sessions: Dict[str, Set[str]] = {}   # ip -> session ids seen
        try:
            for ip, ids in audit.session_ids_by_ip().items():
                self._sessions[ip] = set(ids)
        except OSError:
            log.exception("could not read the audit log; repeat-offender counts start from zero")

    # -- the one public call ------------------------------------------------
    def handle(self, verdict: Verdict) -> List[Decision]:
        """Decide and act on one verdict. Returns one Decision per planned action."""
        with self._lock:
            mode = Mode.OFF if self._kill_switch_active() else self.config.mode
            if mode is Mode.OFF:
                return []
            verdict = self._prepare(verdict)
            decisions: List[Decision] = []
            for planned in plan(verdict, self.config.policy):
                decision = self._decide(verdict, planned, mode)
                self._write(decision)
                decisions.append(decision)
            return decisions

    # -- actions by a person (dashboard, command line) ----------------------
    # These do not go through the policy table, and they work in every mode: a person
    # is in charge. They still go through the same safety checks as an automatic block
    # (an operator cannot firewall-block a private address, their own address or an
    # address on the never-block list), and every one is written to the audit log with
    # the name of who did it.
    def _manual(self, action: Action, ip: str, rule: str, reason: str, actor: str,
                outcome: Outcome, detail: str = "", ttl_s: Optional[int] = None) -> Decision:
        decision = Decision(Verdict(ip=ip, phase=-1, phase_name="manual", micro_state="manual", confidence=1.0),
                            PlannedAction(action, rule, reason, ttl_s), self.config.mode, outcome, detail,
                            actor=actor)
        self._write(decision)
        return decision

    def record_manual(self, action: Action, ip: str, *, rule: str, reason: str, actor: str,
                      outcome: Outcome = Outcome.APPLIED, detail: str = "") -> Decision:
        """Write down something a person already did (for example a dashboard BLOCK or TRUST click)."""
        with self._lock:
            return self._manual(action, str(ip), rule, reason, actor, outcome, detail)

    def firewall_block(self, ip: str, *, reason: str, actor: str, hours: Optional[int] = None) -> Decision:
        """Put `ip` on the firewall block list for `hours` (default: the configured block time)."""
        with self._lock:
            ttl = self.config.policy.deny_ttl_s if hours is None else None
            if hours is not None and isinstance(hours, int) and not isinstance(hours, bool) and 1 <= hours <= 720:
                ttl = hours * 3600

            def refuse(why: str) -> Decision:
                return self._manual(Action.DENY, str(ip), "manual_block", reason, actor, Outcome.SKIPPED, why, ttl)

            clean = canonical(ip)
            if clean is None:
                return refuse("not a valid IP address")
            if ttl is None:
                return refuse("hours must be a whole number from 1 to 720")
            if self._blocklist is None:
                return refuse("no block list is set up")
            if self._kill_switch_active():
                return refuse("the kill switch is on; the host script is removing every block")
            # No verdict here: a person is acting, so there is nothing to weigh.
            # The whitelist therefore still protects, which is what we want for a
            # firewall drop.
            why = self._safelist.skip_reason(clean, Action.DENY)
            if why:
                return refuse(why)
            try:
                self._audit.check_writable()
            except OSError as exc:
                return refuse(f"audit log is not writable ({type(exc).__name__}); refusing to block")
            try:
                existing = self._blocklist.get(clean)
                if existing is not None:
                    return refuse(f"already on the block list until {iso_utc(existing.expires_at)}")
                entry = self._blocklist.add(clean, ttl_s=ttl, reason=reason or "manual block",
                                            rule="manual_block")
            except Exception as exc:
                log.exception("manual firewall block failed for %s", clean)
                return self._manual(Action.DENY, clean, "manual_block", reason, actor, Outcome.FAILED,
                                    f"{type(exc).__name__}: {exc}", ttl)
            return self._manual(Action.DENY, clean, "manual_block", reason, actor, Outcome.APPLIED,
                                f"on the block list until {iso_utc(entry.expires_at)}; "
                                "the host script applies it within seconds", ttl)

    def firewall_unblock(self, ip: str, *, actor: str, reason: str = "") -> Decision:
        """Take `ip` off the firewall block list. Works whatever the mode or kill switch."""
        with self._lock:
            clean = canonical(ip) or str(ip)
            why = reason or "unblocked by a person"
            if self._blocklist is None:
                return self._manual(Action.DENY, clean, "manual_unblock", why, actor, Outcome.SKIPPED,
                                    "no block list is set up")
            try:
                removed = self._blocklist.remove(clean)
            except Exception as exc:
                log.exception("manual unblock failed for %s", clean)
                return self._manual(Action.DENY, clean, "manual_unblock", why, actor, Outcome.FAILED,
                                    f"{type(exc).__name__}: {exc}")
            return self._manual(Action.DENY, clean, "manual_unblock", why, actor,
                                Outcome.APPLIED if removed else Outcome.SKIPPED,
                                "taken off the block list; the host script follows within seconds" if removed
                                else "not on the block list")

    def set_kill_switch(self, on: bool, *, actor: str) -> Decision:
        """Turn the kill switch on (create the file) or off (remove it)."""
        with self._lock:
            path = self.config.kill_file
            rule = "kill_switch_on" if on else "kill_switch_off"
            try:
                if on:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(f"set by {actor} at {iso_utc(self._clock())}\n", encoding="utf-8")
                else:
                    path.unlink(missing_ok=True)
            except OSError as exc:
                return self._manual(Action.OBSERVE, "", rule, "kill switch change", actor, Outcome.FAILED,
                                    f"{type(exc).__name__}: {exc.strerror or exc}")
            return self._manual(Action.OBSERVE, "", rule, "kill switch change", actor, Outcome.APPLIED,
                                "automatic decisions are off and every firewall block is being removed" if on
                                else "automatic decisions resume; blocks that have not expired come back")

    def kill_switch_active(self) -> bool:
        return self._kill_switch_active()

    def active_blocks(self) -> List[BlockEntry]:
        return self._blocklist.entries() if self._blocklist is not None else []

    def recent_decisions(self, limit: int = 50, ip: str = "") -> List[Dict[str, Any]]:
        return self._audit.tail(limit, ip=ip)

    def status(self) -> Dict[str, Any]:
        """A snapshot for the command line and the dashboard. Contains no secrets."""
        with self._lock:
            now = self._clock()
            while self._deny_times and now - self._deny_times[0] >= _HOUR_S:
                self._deny_times.popleft()
            killed = self._kill_switch_active()
            try:
                blocks = len(self.active_blocks())
            except Exception:
                blocks = None
            return {
                "mode": self.config.mode.value,
                "effective_mode": Mode.OFF.value if killed else self.config.mode.value,
                "firewall_enabled": self.config.firewall,
                "kill_switch": killed,
                "kill_file": str(self.config.kill_file),
                "blocklist_path": str(self.config.blocklist_path),
                "audit_path": str(self.config.audit_path),
                "active_blocks": blocks,
                "new_blocks_this_hour": len(self._deny_times),
                "max_new_blocks_per_hour": self.config.max_new_blocks_per_hour,
                "block_hours": self.config.policy.deny_ttl_s // 3600,
                "never_block": [str(n) for n in self.config.never_block],
                "alert_webhook": bool(self.config.alert_webhook),
                "divert_enabled": self._divert_enabled,
            }

    # -- internals ----------------------------------------------------------
    def _kill_switch_active(self) -> bool:
        try:
            return bool(self.config.kill_file.exists())
        except OSError:
            # If we cannot tell, stop. Doing nothing is the safe failure.
            log.error("cannot check the kill-switch file; treating it as ON")
            return True

    def _prepare(self, verdict: Verdict) -> Verdict:
        """Use the clean text form of the IP and fill in how many sessions it has had."""
        ip = canonical(verdict.ip)
        if ip is None:
            return dataclasses.replace(verdict, ip=str(verdict.ip or ""), sessions_seen=1)
        ids = self._sessions.setdefault(ip, set())
        ids.add(verdict.session_id or uuid.uuid4().hex)
        return dataclasses.replace(verdict, ip=ip, sessions_seen=len(ids))

    def _holdback(self, action: Action, mode: Mode) -> Optional[str]:
        """None if this action is really carried out in this mode, else why not."""
        if action is Action.DIVERT:
            return None
        if mode is not Mode.ENFORCE:
            return "mode is observe"
        if action is Action.DENY and not self.config.firewall:
            return "firewall is switched off (MITIGATION_FIREWALL=0)"
        return None

    def _deny_cap_reason(self, now: float) -> Optional[str]:
        cap = self.config.max_new_blocks_per_hour
        while self._deny_times and now - self._deny_times[0] >= _HOUR_S:
            self._deny_times.popleft()
        if len(self._deny_times) >= cap:
            return f"hourly cap of {cap} new blocks reached"
        return None

    def _decide(self, verdict: Verdict, planned: PlannedAction, mode: Mode) -> Decision:
        def done(outcome: Outcome, detail: str = "") -> Decision:
            return Decision(verdict, planned, mode, outcome, detail)

        action = planned.action
        if action is Action.OBSERVE:
            return done(Outcome.APPLIED, "recorded")

        if action is Action.DIVERT and not self._divert_enabled:
            return done(Outcome.SKIPPED, "auto-blacklist is switched off (GATEWAY_MT3_AUTO_BLACKLIST=0)")

        # The verdict goes in so a strong one can override a whitelist for
        # DIVERT. Without it the safelist cannot weigh evidence, which is the
        # bypass HONEYPOT_AUDIT.md PART 3 describes.
        why = self._safelist.skip_reason(verdict.ip, action,
                                         phase=verdict.phase,
                                         confidence=verdict.confidence)
        if why:
            return done(Outcome.SKIPPED, why)

        why = self._holdback(action, mode)
        if why:
            return done(Outcome.WOULD_APPLY, why)

        executor = self._executors.get(action)
        if executor is None:
            return done(Outcome.SKIPPED, f"no {action.value} executor is set up")
        try:
            why = executor.skip_reason(verdict, planned)
        except Exception as exc:   # same promise as apply(): never raise into the pipeline
            log.exception("%s check failed for %s", action.value, verdict.ip)
            return done(Outcome.FAILED, f"{type(exc).__name__}: {exc}")
        if why:
            return done(Outcome.SKIPPED, why)

        now = self._clock()
        if action is Action.DENY:
            why = self._deny_cap_reason(now)
            if why:
                return done(Outcome.SKIPPED, why)
            try:
                self._audit.check_writable()
            except OSError as exc:
                return done(Outcome.SKIPPED,
                            f"audit log is not writable ({type(exc).__name__}); refusing to block")

        try:
            detail = executor.apply(verdict, planned)
        except Exception as exc:   # an executor must never take the pipeline down
            log.exception("%s failed for %s", action.value, verdict.ip)
            return done(Outcome.FAILED, f"{type(exc).__name__}: {exc}")
        if action is Action.DENY:
            self._deny_times.append(now)
        return done(Outcome.APPLIED, detail)

    def _write(self, decision: Decision) -> None:
        try:
            self._audit.write(decision)
        except OSError:
            log.exception("could not write the audit log (decision %s: %s %s -> %s)",
                          decision.decision_id, decision.planned.action.value,
                          decision.verdict.ip, decision.outcome.value)


def _alert_sink(cfg: MitigationConfig):
    """The log line always; a chat webhook too if one is configured."""
    sinks: List[Any] = [LogAlertExecutor()]
    if cfg.alert_webhook:
        sinks.append(WebhookAlertExecutor(cfg.alert_webhook, max_per_hour=cfg.alert_max_per_hour))
    return sinks[0] if len(sinks) == 1 else CompositeAlertExecutor(sinks)


def build_engine(*,
                 blacklist_manager=None,
                 divert_enabled: bool = True,
                 divert_min_phase: int = 1,
                 min_confidence: float = 0.5,
                 config: Optional[MitigationConfig] = None,
                 audit: Optional[AuditLog] = None,
                 own_addresses: Iterable[str] = ()) -> MitigationEngine:
    """The engine as the gateway pipeline uses it.

    The three divert_* / min_confidence arguments come from the gateway's own
    MT3_AUTO_BLACKLIST_* settings, so there is one source of truth for what
    counts as an attack. Settings come from the MITIGATION_* environment unless
    `config` is given.

    `blacklist_manager` may be None (the command-line tool has no gateway): DIVERT is
    then not set up and nothing is treated as whitelisted.
    """
    cfg = config if config is not None else load_config()
    cfg = dataclasses.replace(cfg, policy=dataclasses.replace(
        cfg.policy, divert_min_phase=divert_min_phase, min_confidence=min_confidence))
    blocklist = BlocklistFile(cfg.blocklist_path)
    executors: Dict[Action, Executor] = {
        Action.ALERT: _alert_sink(cfg),
        # Only reached in enforce mode with MITIGATION_FIREWALL=1; see _holdback.
        Action.DENY: FirewallExecutor(blocklist, default_ttl_s=cfg.policy.deny_ttl_s),
    }
    if blacklist_manager is not None:
        executors[Action.DIVERT] = GatewayExecutor(blacklist_manager)
    return MitigationEngine(
        cfg,
        safelist=Safelist(override_min_phase=cfg.policy.whitelist_override_min_phase,
                          override_min_confidence=cfg.policy.whitelist_override_min_confidence,
                          never_block=cfg.never_block,
                          own_addresses=own_addresses,
                          is_whitelisted=blacklist_manager.is_whitelisted if blacklist_manager is not None else None),
        audit=audit if audit is not None else AuditLog(cfg.audit_path),
        executors=executors,
        divert_enabled=divert_enabled,
        blocklist=blocklist,
    )
