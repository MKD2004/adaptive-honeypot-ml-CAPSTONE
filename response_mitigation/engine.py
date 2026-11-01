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
from typing import Callable, Deque, Dict, Iterable, List, Mapping, Optional, Protocol, Set

from .audit import AuditLog
from .blocklist import BlocklistFile
from .config import MitigationConfig, load_config
from .executors.alert import LogAlertExecutor
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
                 clock: Callable[[], float] = time.time) -> None:
        self.config = config
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

        why = self._safelist.skip_reason(verdict.ip, action)
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


def build_engine(*,
                 blacklist_manager,
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
    """
    cfg = config if config is not None else load_config()
    cfg = dataclasses.replace(cfg, policy=dataclasses.replace(
        cfg.policy, divert_min_phase=divert_min_phase, min_confidence=min_confidence))
    return MitigationEngine(
        cfg,
        safelist=Safelist(never_block=cfg.never_block,
                          own_addresses=own_addresses,
                          is_whitelisted=blacklist_manager.is_whitelisted),
        audit=audit if audit is not None else AuditLog(cfg.audit_path),
        executors={Action.DIVERT: GatewayExecutor(blacklist_manager),
                   Action.ALERT: LogAlertExecutor(),
                   # Only reached in enforce mode with MITIGATION_FIREWALL=1; see _holdback.
                   Action.DENY: FirewallExecutor(BlocklistFile(cfg.blocklist_path),
                                                 default_ttl_s=cfg.policy.deny_ttl_s)},
        divert_enabled=divert_enabled,
    )
