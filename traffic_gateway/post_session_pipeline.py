"""
traffic_gateway/post_session_pipeline.py

Watches the Cowrie log directory, and for every session that reaches
`cowrie.session.closed` runs the full post-session chain: parse -> 128 features
-> MT3 inference -> adaptive honeypot reconfiguration -> one JSON line in
logs/pipeline_results.jsonl for the dashboard. Tails incrementally by file
offset, so a session is processed exactly once.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from response_mitigation.engine import MitigationEngine, build_engine
from response_mitigation.models import Action, Outcome, Verdict

from .blacklist_manager import blacklist_manager
from .config import CONFIG
from .ext_paths import REPO_ROOT, ensure_paths
from .feature_bridge import (
    MT3Inference,
    SemanticEncoder,
    ThreatIntelCache,
    extract_features,
    group_d_mode,
    honeypot_target_for,
    kcvr_valid,
)
from .peer_attribution import looks_like_proxy, resolve_peer_ip
from .traffic_classifier import traffic_classifier

log = logging.getLogger("traffic_gateway.post_session")

# Where a live Cowrie writes its JSON log. Overridable on the CLI / constructor.
DEFAULT_COWRIE_LOG_DIR = REPO_ROOT / "honeypot_dataset" / "cowrie" / "logs"
DEFAULT_RESULTS_PATH = REPO_ROOT / "logs" / "pipeline_results.jsonl"
DEFAULT_POLL_SEC = 30.0
COWRIE_LOG_GLOB = "cowrie.json*"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


_SOURCE_TAG = re.compile(r"[A-Za-z0-9_.-]{1,40}")


def _source_tag() -> str:
    """Where this data comes from: PIPELINE_SOURCE, e.g. internet | injected | lab | demo.

    Written on every result so real internet sessions and injected or lab ones are never mixed
    up in one statistic. A value with odd characters stops start-up instead of being stored.

    Originally Anushka's (4a6ed19). Ported to main by hand ahead of the merge, and
    reconciled here. Tests live in tests/test_session_contract.py and
    tests/test_pipeline_mitigation.py.
    """
    raw = os.environ.get("PIPELINE_SOURCE", "").strip() or "unspecified"
    if not _SOURCE_TAG.fullmatch(raw):
        raise ValueError("PIPELINE_SOURCE: use 1-40 letters, digits, dots, dashes or underscores")
    return raw


def mt3_is_trusted_for(record: Dict[str, Any]) -> bool:
    """May MT3's verdict DRIVE the blacklist and the honeypot reconfiguration?

    Gated on the session's `source` (which honeypot produced it), because that
    determines the feature shape MT3 sees. See CONFIG.MT3_TRUSTED_SOURCES for the
    measurement that forced this.

    The verdict is always computed and logged regardless -- this only governs
    whether it is allowed to ACT.
    """
    src = str(record.get("source", "") or "").strip().lower()
    if not src:
        return bool(CONFIG.MT3_TRUST_UNKNOWN_SOURCE)
    if src in CONFIG.MT3_TRUSTED_SOURCES:
        return True
    return bool(CONFIG.MT3_TRUST_UNKNOWN_SOURCE)


@dataclass
class _TailState:
    """Byte offset plus the partial sessions still awaiting their close event."""
    offset: int = 0
    pending: Dict[str, List[dict]] = field(default_factory=dict)


@dataclass(frozen=True)
class LogSource:
    """One honeypot's log, and how to turn it into contract-conforming records.

    Phase 1 of MULTI_HONEYPOT.md. The pipeline used to hardcode a single Cowrie
    directory and a single `cowrie.session.closed` event name, so adding a second
    honeypot meant editing the watcher loop. Now it is a list entry.

    A new honeypot supplies:
      name        a short tag, used in logs and as the `sensor` fallback
      log_dir     directory to tail
      glob        filename pattern within it
      session_key the JSON field holding the session id
      is_closed   predicate: has this event ended the session?
      build       events -> flat record satisfying src.parsers.session_contract

    `build` is where protocol/dst_port get set. cowrie_parser.build_record()
    defaults to ssh/22 and those defaults must not change (see its docstring), so
    a non-SSH source passes its own, e.g.

        functools.partial(build_record, protocol="http", dst_port=8080)
    """
    name: str
    log_dir: Path
    glob: str
    session_key: str
    is_closed: Callable[[Dict[str, Any]], bool]
    build: Callable[[List[dict]], Optional[Dict[str, Any]]]


def cowrie_source(log_dir: Path = None) -> LogSource:  # type: ignore[assignment]
    """The one source that exists today. Behaviour identical to pre-Phase-1."""
    ensure_paths()
    from src.parsers.cowrie_parser import SESSION_CLOSED_EVENT, build_record  # type: ignore

    return LogSource(
        name="cowrie",
        log_dir=Path(DEFAULT_COWRIE_LOG_DIR if log_dir is None else log_dir),
        glob=COWRIE_LOG_GLOB,
        session_key="session",
        is_closed=lambda ev: ev.get("eventid", "") == SESSION_CLOSED_EVENT,
        build=build_record,
    )


DEFAULT_HERALDING_LOG_DIR = REPO_ROOT / "deploy" / "heralding" / "logs"


def heralding_source(log_dir: Path = None,                 # type: ignore[assignment]
                     *, credentials_as_payload: bool = True) -> LogSource:
    """Heralding, the auth-portal honeypot. MULTI_HONEYPOT.md Phase 2.

    Unlike Cowrie, one log line is a whole session (`log_session.json` is
    jsonlines with `session_ended` on the final record), so `is_closed` asks
    "is this record final" and `build` takes the last element.

    Group D note: Phase 1b decided to ZERO-FILL the semantic block for every
    non-SSH protocol -- the shell-fitted PCA keeps only 71.4% of credential-text
    variance. That is not enforced here; `feature_bridge` still applies the
    global `SemanticEncoder`. Wiring the per-protocol zero-fill is the remaining
    Phase 2 code task, and until it lands a Heralding session's Group D is
    off-domain rather than zero-filled. See DECISIONS.md 2026-11-04.
    """
    ensure_paths()
    from src.parsers import heralding_parser as hp  # type: ignore
    import functools

    return LogSource(
        name="heralding",
        log_dir=Path(DEFAULT_HERALDING_LOG_DIR if log_dir is None else log_dir),
        glob=hp.HERALDING_SESSION_GLOB,
        session_key="session_id",
        is_closed=hp.is_session_final,
        build=functools.partial(hp.build_record,
                                credentials_as_payload=credentials_as_payload),
    )


class PostSessionPipeline:
    """Cowrie log -> features -> MT3 -> honeypot config -> pipeline_results.jsonl."""

    def __init__(
        self,
        cowrie_log_dir: Path = DEFAULT_COWRIE_LOG_DIR,
        results_path: Path = DEFAULT_RESULTS_PATH,
        poll_interval: float = DEFAULT_POLL_SEC,
        *,
        from_start: bool = False,
        max_backlog: int = 0,
        configurator: Optional[Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]]] = None,
        sources: Optional[List["LogSource"]] = None,
        mitigation: Optional[MitigationEngine] = None,
    ) -> None:
        self.cowrie_log_dir = Path(cowrie_log_dir)
        # One source today. `sources=[...]` is how Phase 2+ adds Heralding etc.
        # Left None, the Cowrie source is built from cowrie_log_dir exactly as
        # before, so every existing caller keeps its behaviour.
        self._sources: List[LogSource] = (
            list(sources) if sources else [cowrie_source(self.cowrie_log_dir)]
        )
        self.results_path = Path(results_path)
        self.poll_interval = float(poll_interval)
        self.from_start = from_start
        self.max_backlog = int(max_backlog)

        self.ti = ThreatIntelCache()
        self.semantic = SemanticEncoder()
        self.mt3 = MT3Inference()
        self._configurator = configurator
        self.mitigation = mitigation   # built on first use when not given
        self.source = _source_tag()    # provenance tag written on every result

        self._tails: Dict[str, _TailState] = {}
        self._seen: Set[str] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.started = False
        self.processed = 0
        self.startup_info: Dict[str, Any] = {}

    # -- startup ------------------------------------------------------------
    def startup(self) -> Dict[str, Any]:
        """Pre-fetch KEV/EPSS, warm DistilBERT, load MT3. Safe to call twice."""
        if self.started:
            return self.startup_info

        # First, so a bad MITIGATION_* setting stops start-up before the slow loads.
        mitigation_cfg = self._get_mitigation().config
        self.results_path.parent.mkdir(parents=True, exist_ok=True)
        ti_info = self.ti.prefetch()
        sem_ok = self.semantic.load()
        self.mt3.load()
        self._load_seen()
        if not self.from_start:
            self._seek_to_end()

        self.startup_info = {
            "kev_count": ti_info["kev_count"],
            "semantic_available": sem_ok,
            "semantic_status": self.semantic.status(),
            "mt3": self.mt3.meta,
            "cowrie_log_dir": str(self.cowrie_log_dir),
            "cowrie_logs_found": len(self._log_files()),
            "sources": [{"name": src.name, "log_dir": str(src.log_dir),
                         "glob": src.glob, "logs_found": len(self._log_files(src))}
                        for src in self._sources],
            "provenance": self.source,
            "results_path": str(self.results_path),
            "already_processed": len(self._seen),
            "configurator": self._configurator_name(),
            "mitigation": {"mode": mitigation_cfg.mode.value,
                           "firewall": mitigation_cfg.firewall,
                           "audit_path": str(mitigation_cfg.audit_path)},
        }
        self.started = True
        if not sem_ok:
            log.warning("Group D (30/128 features) is zero-filled -- MT3 confidence "
                        "on command-driven classes will be degraded.")
        return self.startup_info

    def _configurator_name(self) -> str:
        fn = self._resolve_configurator()
        return "none" if fn is None else getattr(fn, "__qualname__", str(fn))

    def _resolve_configurator(self):
        """Step 4's configurator, if it has been built; None otherwise."""
        if self._configurator is not None:
            return self._configurator
        try:
            ensure_paths()
            from adaptive_honeypot.configurator import apply_prediction  # type: ignore

            self._configurator = apply_prediction
        except Exception:
            self._configurator = None
        return self._configurator

    def _get_mitigation(self) -> MitigationEngine:
        """The mitigation engine, built on first use from the MITIGATION_* settings.

        The what-counts-as-an-attack thresholds are the gateway's own
        MT3_AUTO_BLACKLIST_* settings, so there is one source of truth.
        """
        if self.mitigation is None:
            self.mitigation = build_engine(
                blacklist_manager=blacklist_manager,
                divert_enabled=CONFIG.MT3_AUTO_BLACKLIST,
                divert_min_phase=CONFIG.MT3_AUTO_BLACKLIST_MIN_PHASE,
                min_confidence=CONFIG.MT3_AUTO_BLACKLIST_CONF,
            )
        return self.mitigation

    def _mitigate(self, pred: Dict[str, Any], record: Dict[str, Any]) -> Tuple[bool, List[Dict[str, str]]]:
        """Hand MT3's verdict to the mitigation layer.

        Returns (was the source added to the blacklist, a short summary of what
        was decided for the results file). Never raises: a failure here must not
        lose the session's result.
        """
        peer_ip = str(record.get("src_ip", "") or "")
        try:
            decisions = self._get_mitigation().handle(Verdict(
                ip=peer_ip,
                phase=int(pred["phase"]),
                phase_name=str(pred["phase_name"]),
                micro_state=str(pred["micro_state"]),
                confidence=float(pred["confidence"]),
                session_id=str(record.get("session_id", "") or ""),
            ))
        except Exception:
            log.exception("mitigation failed for %s", peer_ip)
            return False, []
        blacklisted = any(d.planned.action is Action.DIVERT and d.outcome is Outcome.APPLIED
                          for d in decisions)
        summary = [{"action": d.planned.action.value, "rule": d.planned.rule,
                    "outcome": d.outcome.value} for d in decisions]
        return blacklisted, summary

    def _load_seen(self) -> None:
        """Re-read our own output so a restart never double-processes a session."""
        if not self.results_path.exists():
            return
        with self.results_path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    self._seen.add(json.loads(line)["session_id"])
                except Exception:
                    continue

    def _log_files(self, source: Optional["LogSource"] = None) -> List[Path]:
        """Log files for one source, or across every source when none is given."""
        if source is None:
            return [p for src in self._sources for p in self._log_files(src)]
        if not source.log_dir.is_dir():
            return []
        return sorted(source.log_dir.glob(source.glob))

    @staticmethod
    def _tail_key(source: "LogSource", path: Path) -> str:
        """Two honeypots may write the same filename in different folders."""
        return f"{source.name}:{path}"

    def _seek_to_end(self) -> None:
        """Start tailing at EOF so an existing 15k-session log isn't replayed."""
        for source in self._sources:
            for path in self._log_files(source):
                try:
                    self._tails[self._tail_key(source, path)] = _TailState(
                        offset=path.stat().st_size)
                except OSError:
                    continue

    # -- the chain ----------------------------------------------------------
    def process_session(self, record: Dict[str, Any], *,
                        gateway_score: Optional[float] = None,
                        gateway_verdict: Optional[Dict[str, Any]] = None,
                        write: bool = True) -> Dict[str, Any]:
        """Run one parsed session end to end and return the pipeline result.

        `gateway_verdict` is the full classify() result when the caller already
        ran the pre-filter at connection time; pass it so its signals survive
        into the log instead of being recomputed or lost.
        """
        if not self.started:
            self.startup()

        t0 = time.perf_counter()

        # (a) attribute the session to the real peer. The honeypot only ever saw
        # the gateway proxying on its behalf (127.0.0.1, or the Docker bridge
        # when Cowrie runs in a container), so recover the peer from the
        # gateway's own log by connect time.
        seen_ip = str(record.get("src_ip", "") or "")
        if looks_like_proxy(seen_ip):
            peer = resolve_peer_ip(record.get("t_start"), fallback=seen_ip)
            if peer and peer != seen_ip:
                record = {**record, "src_ip": peer, "observed_src_ip": seen_ip}

        # (b) gateway pre-filter score -- reuse Step 2 when the caller has none
        gw = gateway_verdict
        if gw is not None and gateway_score is None:
            gateway_score = gw.get("score")
        if gateway_score is None:
            gw = traffic_classifier.classify({
                "src_ip": record.get("src_ip", ""),
                "dst_port": record.get("dst_port", 22),
                "src_country": record.get("src_country", ""),
                "ja3_hash": record.get("ja3_hash", ""),
                "failed_auth_attempts": record.get("login_attempts", 0),
                "command_text": record.get("command_text", ""),
            }, record=False)
            gateway_score = gw["score"]

        # (c) 128 features, (d) MT3
        x_raw = extract_features(record, self.ti, self.semantic)
        pred = self.mt3.predict(x_raw)
        pred["honeypot_target"] = honeypot_target_for(record)

        # (d2) may this verdict act, or is it observation only?
        mt3_trusted = mt3_is_trusted_for(record)
        pred["mt3_trusted"] = mt3_trusted
        if not mt3_trusted:
            log.info("session %s from source=%r: MT3 says %s (p=%.3f) but the source is "
                     "not in MT3_TRUSTED_SOURCES, so it drives nothing. Rule label: %s",
                     record.get("session_id", ""), record.get("source", ""),
                     pred["micro_state"], pred["confidence"],
                     record.get("micro_state", "?"))

        # (e) adaptive honeypot configurator
        action: Dict[str, Any] = {"previous_config": None, "new_config": None,
                                  "changed": False, "reason": "configurator not available"}
        if not mt3_trusted:
            action = {"previous_config": None, "new_config": None, "changed": False,
                      "reason": (f"skipped: MT3 not trusted for source "
                                 f"{record.get('source', '')!r}")}
        fn = self._resolve_configurator()
        if mt3_trusted and fn is not None:
            try:
                action = fn(pred, record)
            except Exception as exc:
                log.exception("configurator failed")
                action = {"previous_config": None, "new_config": None,
                          "changed": False, "reason": f"configurator error: {exc}"}

        # (e2) response mitigation: MT3's verdict goes to the mitigation layer
        # (response_mitigation/), which decides, checks it is safe, acts and
        # writes the audit log. With default settings it does what this step
        # always did: a source MT3 puts at phase >= 1 (confidence >= 0.5) is
        # added to the blacklist, which sends it to the honeypot. Recon alone
        # (phase 0) does not trigger it. peer_ip has already been through
        # attribution (step a), so it is the real client -- 127.0.0.1 in a
        # single-laptop demo, the LAN IP with two; the layer skips the Docker
        # bridge, which means attribution found no peer.
        #
        # GATED BY mt3_trusted, and that gate belongs HERE rather than inside the
        # engine. The engine's job is "given a verdict, decide and act safely";
        # deciding whether the verdict is worth believing at all is upstream of
        # it. Without this, merging the mitigation layer would undo the fix from
        # HONEYPOT_AUDIT.md PART 7: a Heralding bare connect scores
        # DISC_NETSTAT_SCAN at confidence 1.000 (phase 3), which clears every
        # threshold the engine checks, so the engine would dutifully blacklist a
        # user for opening a TCP connection.
        if mt3_trusted:
            auto_blocked, mitigation = self._mitigate(pred, record)
        else:
            auto_blocked = False
            mitigation = [{"action": "skipped", "rule": "untrusted_source",
                           "outcome": f"MT3 not trusted for source "
                                      f"{str(record.get('source', '') or '')!r}"}]

        commands = [c for c in str(record.get("command_text", "") or "").split(" ; ")
                    if c and c != "[no commands]"]
        t_start = float(record.get("t_start", 0.0) or 0.0)

        result = {
            "session_id": record.get("session_id", ""),
            "src_ip": record.get("src_ip", ""),
            "sensor": str(record.get("sensor", "") or ""),
            "source": self.source,
            "timestamp": (datetime.fromtimestamp(t_start, tz=timezone.utc).isoformat()
                          if t_start else _utcnow()),
            "processed_at": _utcnow(),
            "duration_s": round(float(record.get("session_duration_s", 0.0) or 0.0), 3),
            "login_attempts": int(record.get("login_attempts", 0) or 0),
            "commands": commands,
            "gateway_score": round(float(gateway_score), 4),
            "gateway_verdict": (gw or {}).get("verdict"),
            "gateway_signals": (gw or {}).get("signals_fired", []),
            "mt3_trusted": mt3_trusted,
            "mt3_prediction": {
                "micro_state": pred["micro_state"],
                "phase": pred["phase"],
                "phase_name": pred["phase_name"],
                "honeypot_target": pred["honeypot_target"],
                "confidence": pred["confidence"],
                "top3": pred["top3"],
            },
            "honeypot_action": action,
            "kcvr_valid": kcvr_valid(record.get("micro_state_sequence", "")),
            "rule_label": record.get("micro_state", ""),
            "observed_src_ip": record.get("observed_src_ip"),
            "auto_blacklisted": auto_blocked,
            "mitigation": mitigation,
            "semantic_available": bool(self.semantic.available),
            "group_d_mode": group_d_mode(record),
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
        }

        # (f) append one JSON line for the dashboard
        if write:
            self._append(result)
        with self._lock:
            self._seen.add(result["session_id"])
            self.processed += 1
        return result

    def _append(self, result: Dict[str, Any]) -> None:
        with self._lock:
            with self.results_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(result, default=str) + "\n")

    # -- tailing ------------------------------------------------------------
    def scan_once(self) -> List[Dict[str, Any]]:
        """Read whatever is new in every source's logs; process closed sessions."""
        ensure_paths()
        out: List[Dict[str, Any]] = []
        for source in self._sources:
            out.extend(self._scan_source(source))
            if self.max_backlog and len(out) >= self.max_backlog:
                break
        return out

    def _scan_source(self, source: "LogSource") -> List[Dict[str, Any]]:
        """Tail one honeypot's logs. Session grouping and the close signal come
        from the source, so a honeypot that does not speak Cowrie still works."""
        out: List[Dict[str, Any]] = []
        for path in self._log_files(source):
            key = self._tail_key(source, path)
            state = self._tails.setdefault(key, _TailState())
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size < state.offset:            # rotated / truncated
                log.info("cowrie log rotated: %s", path.name)
                state.offset = 0
                state.pending.clear()
            if size == state.offset:
                continue

            with path.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(state.offset)
                chunk = fh.read()
                state.offset = fh.tell()

            closed_ids: List[str] = []
            for line in chunk.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                sid = ev.get(source.session_key, "")
                if not sid or sid in self._seen:
                    continue
                state.pending.setdefault(sid, []).append(ev)
                if source.is_closed(ev):
                    closed_ids.append(sid)

            for sid in closed_ids:
                events = state.pending.pop(sid, [])
                record = source.build(events)
                if record is None:
                    continue
                # which honeypot saw it: Cowrie writes `sensor` on every event (cowrie.cfg sensor_name)
                # falls back to the source's own name, so a honeypot whose log
                # carries no sensor field is still attributable
                record.setdefault("sensor", next(
                    (str(e["sensor"]) for e in events if e.get("sensor")), source.name))
                try:
                    out.append(self.process_session(record))
                except Exception:
                    log.exception("failed to process session %s", sid)
                if self.max_backlog and len(out) >= self.max_backlog:
                    return out
        return out

    # -- watching -----------------------------------------------------------
    def watch(self, on_result: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        """Block, processing sessions as they close. Ctrl-C to stop.

        Uses watchdog for immediate wakeups when it is installed, and always
        keeps the poll as a floor so a missed filesystem event cannot stall the
        pipeline.
        """
        if not self.started:
            self.startup()
        wake = threading.Event()
        observer = self._start_watchdog(wake)

        log.info("watching %s every %.0fs%s", self.cowrie_log_dir, self.poll_interval,
                 " (watchdog active)" if observer else " (polling only)")
        try:
            while not self._stop.is_set():
                for res in self.scan_once():
                    log.info("session %s -> %s (p=%.3f, phase %d) %s",
                             res["session_id"], res["mt3_prediction"]["micro_state"],
                             res["mt3_prediction"]["confidence"],
                             res["mt3_prediction"]["phase"],
                             "CONFIG CHANGED" if res["honeypot_action"].get("changed") else "")
                    if on_result:
                        on_result(res)
                wake.wait(self.poll_interval)
                wake.clear()
        except KeyboardInterrupt:
            log.info("watcher interrupted")
        finally:
            if observer:
                observer.stop()
                observer.join(timeout=2)

    def _start_watchdog(self, wake: threading.Event):
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except Exception:
            return None
        dirs = [src.log_dir for src in self._sources if src.log_dir.is_dir()]
        if not dirs:
            return None

        class _Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                if not event.is_directory:
                    wake.set()

        observer = Observer()
        for d in dirs:
            observer.schedule(_Handler(), str(d), recursive=False)
        observer.daemon = True
        observer.start()
        return observer

    def stop(self) -> None:
        self._stop.set()

    def stats(self) -> Dict[str, Any]:
        return {
            "started": self.started,
            "processed": self.processed,
            "seen_sessions": len(self._seen),
            "pending_sessions": sum(len(t.pending) for t in self._tails.values()),
            "cowrie_log_dir": str(self.cowrie_log_dir),
            "cowrie_logs_found": len(self._log_files()),
            "sources": [src.name for src in self._sources],
            "ti_cache_age_sec": round(self.ti.age_sec, 1) if self.ti.age_sec != float("inf") else None,
            "results_path": str(self.results_path),
        }


def read_results(results_path: Path = DEFAULT_RESULTS_PATH,
                 limit: int = 50) -> List[Dict[str, Any]]:
    """Last `limit` pipeline results, newest first (used by the API)."""
    path = Path(results_path)
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows[-limit:][::-1] if limit else rows[::-1]


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Cowrie post-session MT3 pipeline")
    ap.add_argument("--cowrie-log-dir", default=str(DEFAULT_COWRIE_LOG_DIR))
    ap.add_argument("--results", default=str(DEFAULT_RESULTS_PATH))
    ap.add_argument("--poll", type=float, default=DEFAULT_POLL_SEC)
    ap.add_argument("--from-start", action="store_true",
                    help="process the existing log backlog instead of tailing from EOF")
    ap.add_argument("--max-backlog", type=int, default=0,
                    help="stop after N sessions in one scan (0 = unlimited)")
    ap.add_argument("--once", action="store_true", help="one scan, then exit")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)-7s] %(message)s")
    pipe = PostSessionPipeline(
        Path(args.cowrie_log_dir), Path(args.results), args.poll,
        from_start=args.from_start, max_backlog=args.max_backlog,
    )
    info = pipe.startup()
    print(json.dumps(info, indent=2, default=str))
    if args.once:
        results = pipe.scan_once()
        print(f"processed {len(results)} closed session(s)")
    else:
        pipe.watch()


if __name__ == "__main__":
    main()
