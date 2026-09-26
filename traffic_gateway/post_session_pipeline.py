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
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from .blacklist_manager import blacklist_manager
from .config import CONFIG
from .ext_paths import REPO_ROOT, ensure_paths
from .feature_bridge import (
    MT3Inference,
    SemanticEncoder,
    ThreatIntelCache,
    extract_features,
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


@dataclass
class _TailState:
    """Byte offset plus the partial sessions still awaiting their close event."""
    offset: int = 0
    pending: Dict[str, List[dict]] = field(default_factory=dict)


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
    ) -> None:
        self.cowrie_log_dir = Path(cowrie_log_dir)
        self.results_path = Path(results_path)
        self.poll_interval = float(poll_interval)
        self.from_start = from_start
        self.max_backlog = int(max_backlog)

        self.ti = ThreatIntelCache()
        self.semantic = SemanticEncoder()
        self.mt3 = MT3Inference()
        self._configurator = configurator

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
            "results_path": str(self.results_path),
            "already_processed": len(self._seen),
            "configurator": self._configurator_name(),
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

    def _log_files(self) -> List[Path]:
        if not self.cowrie_log_dir.is_dir():
            return []
        return sorted(self.cowrie_log_dir.glob(COWRIE_LOG_GLOB))

    def _seek_to_end(self) -> None:
        """Start tailing at EOF so an existing 15k-session log isn't replayed."""
        for path in self._log_files():
            try:
                self._tails[str(path)] = _TailState(offset=path.stat().st_size)
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

        # (e) adaptive honeypot configurator
        action: Dict[str, Any] = {"previous_config": None, "new_config": None,
                                  "changed": False, "reason": "configurator not available"}
        fn = self._resolve_configurator()
        if fn is not None:
            try:
                action = fn(pred, record)
            except Exception as exc:
                log.exception("configurator failed")
                action = {"previous_config": None, "new_config": None,
                          "changed": False, "reason": f"configurator error: {exc}"}

        # (e2) response mitigation: MT3 classified this as an actual attack, so
        # blacklist the source. Recon alone (phase 0) does not trigger it -- an
        # attacker only earns a block once they attempt access or beyond. This
        # is the detect -> classify -> respond loop; the block is what the demo
        # shows as "IP blacklisted after MT3 identified the brute force".
        peer_ip = str(record.get("src_ip", "") or "")
        auto_blocked = False
        # peer_ip has already been through attribution (step a), so it is the
        # real client -- 127.0.0.1 in a single-laptop demo, the LAN IP with two.
        # Only skip the Docker bridge, which means attribution found no peer.
        if (CONFIG.MT3_AUTO_BLACKLIST
                and peer_ip
                and pred["phase"] >= CONFIG.MT3_AUTO_BLACKLIST_MIN_PHASE
                and float(pred["confidence"]) >= CONFIG.MT3_AUTO_BLACKLIST_CONF
                and not peer_ip.startswith(("172.1", "172.2"))
                and not blacklist_manager.is_whitelisted(peer_ip)
                and not blacklist_manager.is_blacklisted(peer_ip)):
            try:
                blacklist_manager.blacklist(
                    peer_ip,
                    reason=(f"MT3: {pred['micro_state']} "
                            f"(phase {pred['phase']} {pred['phase_name']}, "
                            f"conf {pred['confidence']:.2f})"),
                    source="mt3_pipeline",
                    risk_score=float(pred["confidence"]),
                )
                auto_blocked = True
                log.warning("auto-blacklisted %s: MT3 classified %s (p=%.2f)",
                            peer_ip, pred["micro_state"], pred["confidence"])
            except Exception:
                log.exception("auto-blacklist failed for %s", peer_ip)

        commands = [c for c in str(record.get("command_text", "") or "").split(" ; ")
                    if c and c != "[no commands]"]
        t_start = float(record.get("t_start", 0.0) or 0.0)

        result = {
            "session_id": record.get("session_id", ""),
            "src_ip": record.get("src_ip", ""),
            "timestamp": (datetime.fromtimestamp(t_start, tz=timezone.utc).isoformat()
                          if t_start else _utcnow()),
            "processed_at": _utcnow(),
            "duration_s": round(float(record.get("session_duration_s", 0.0) or 0.0), 3),
            "login_attempts": int(record.get("login_attempts", 0) or 0),
            "commands": commands,
            "gateway_score": round(float(gateway_score), 4),
            "gateway_verdict": (gw or {}).get("verdict"),
            "gateway_signals": (gw or {}).get("signals_fired", []),
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
            "semantic_available": bool(self.semantic.available),
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
        """Read whatever is new in the Cowrie logs; process closed sessions."""
        ensure_paths()
        from src.parsers.cowrie_parser import (  # type: ignore
            SESSION_CLOSED_EVENT, build_record,
        )

        out: List[Dict[str, Any]] = []
        for path in self._log_files():
            key = str(path)
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
                sid = ev.get("session", "")
                if not sid or sid in self._seen:
                    continue
                state.pending.setdefault(sid, []).append(ev)
                if ev.get("eventid", "") == SESSION_CLOSED_EVENT:
                    closed_ids.append(sid)

            for sid in closed_ids:
                events = state.pending.pop(sid, [])
                record = build_record(events)
                if record is None:
                    continue
                try:
                    out.append(self.process_session(record))
                except Exception:
                    log.exception("failed to process session %s", sid)
                if self.max_backlog and len(out) >= self.max_backlog:
                    return out
        return out

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
        if not self.cowrie_log_dir.is_dir():
            return None

        class _Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                if not event.is_directory:
                    wake.set()

        observer = Observer()
        observer.schedule(_Handler(), str(self.cowrie_log_dir), recursive=False)
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
