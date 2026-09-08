"""
traffic_gateway/api.py

CORS-enabled Flask API that exposes the live pipeline to the dashboard: the
MT3 result feed, aggregate stats and phase distribution, blacklist/whitelist
CRUD, and the honeypot's active config. Also serves the existing SOC page and
its /events SSE stream so port 5000 stays a single server.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import queue
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, Response, jsonify, request, send_file
from flask_cors import CORS

from .blacklist_manager import blacklist_manager
from .config import CONFIG
from .ext_paths import REPO_ROOT, ensure_paths
from .ip_classifier import IPStatus, classifier
from .peer_attribution import attributor, looks_like_proxy
from .post_session_pipeline import DEFAULT_RESULTS_PATH, read_results
from .rate_limiter import rate_limiter
from .traffic_classifier import traffic_classifier

log = logging.getLogger("traffic_gateway.api")

STATIC_DIR = REPO_ROOT / "dashboard" / "static"
GATEWAY_EVENT_LOG = CONFIG.DATA_DIR / CONFIG.SESSION_LOG_FILE

PHASE_NAMES = [
    "Reconnaissance", "Initial Access", "Execution", "Discovery",
    "Privilege Escalation", "Persistence", "Defense Evasion",
    "Lateral Movement", "Exfiltration",
]

app = Flask(__name__, static_folder=None)
CORS(app)

_results_path: Path = DEFAULT_RESULTS_PATH
_pipeline = None          # set by run_pipeline.py so /api/stats can report it
_dash_state = None        # dashboard.backend.DashboardState, for /events


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def configure(results_path: Optional[Path] = None, pipeline: Any = None) -> None:
    """Point the API at a results file / running pipeline before serving."""
    global _results_path, _pipeline
    if results_path is not None:
        _results_path = Path(results_path)
    if pipeline is not None:
        _pipeline = pipeline


def _valid_ip(value: Any) -> Tuple[bool, str]:
    try:
        return True, str(ipaddress.ip_address(str(value).strip()))
    except (ValueError, TypeError):
        return False, ""


def _body() -> Dict[str, Any]:
    return request.get_json(silent=True) or {}


def _configurator():
    ensure_paths()
    from adaptive_honeypot.configurator import configurator  # type: ignore

    return configurator


# ── Pipeline feed ────────────────────────────────────────────────────────────
@app.get("/api/live-feed")
def live_feed():
    """Last N pipeline results, newest first (default 50)."""
    limit = request.args.get("limit", default=50, type=int)
    rows = read_results(_results_path, limit=max(1, min(limit, 1000)))
    return jsonify({"count": len(rows), "results": rows,
                    "source": str(_results_path)})


@app.get("/api/mt3-results")
def mt3_results():
    """Just the MT3 predictions, flattened for charting."""
    limit = request.args.get("limit", default=50, type=int)
    rows = read_results(_results_path, limit=max(1, min(limit, 1000)))
    out = []
    for r in rows:
        m = r.get("mt3_prediction", {})
        out.append({
            "session_id": r.get("session_id"),
            "src_ip": r.get("src_ip"),
            "timestamp": r.get("timestamp"),
            "micro_state": m.get("micro_state"),
            "phase": m.get("phase"),
            "phase_name": m.get("phase_name"),
            "honeypot_target": m.get("honeypot_target"),
            "confidence": m.get("confidence"),
            "top3": m.get("top3", []),
            "rule_label": r.get("rule_label"),
            "gateway_score": r.get("gateway_score"),
            "kcvr_valid": r.get("kcvr_valid"),
            "config_changed": bool(r.get("honeypot_action", {}).get("changed")),
        })
    return jsonify({"count": len(out), "predictions": out})


@app.get("/api/stats")
def stats():
    """Totals, phase distribution and subsystem state."""
    rows = read_results(_results_path, limit=0)
    phases = Counter()
    states = Counter()
    targets = Counter()
    confidences: List[float] = []
    changes = 0
    alerts = 0
    for r in rows:
        m = r.get("mt3_prediction", {})
        if m.get("phase") is not None:
            phases[int(m["phase"])] += 1
        if m.get("micro_state"):
            states[m["micro_state"]] += 1
        if m.get("honeypot_target"):
            targets[m["honeypot_target"]] += 1
        if isinstance(m.get("confidence"), (int, float)):
            confidences.append(float(m["confidence"]))
        act = r.get("honeypot_action") or {}
        changes += bool(act.get("changed"))
        alerts += bool(act.get("alert_fired"))

    recs = classifier.all_records()
    ip_totals = {s.value: sum(1 for r in recs if r.status == s) for s in IPStatus}

    return jsonify({
        "generated_at": _utcnow(),
        "total_sessions": len(rows),
        "blocked_ips": len(blacklist_manager.get_blacklisted_ips()),
        "whitelisted_ips": len(blacklist_manager.get_whitelisted_ips()),
        "tracked_ips": len(recs),
        "ip_status_totals": ip_totals,
        "unique_attackers": len({r.get("src_ip") for r in rows if r.get("src_ip")}),
        "phase_distribution": [
            {"phase": i, "phase_name": PHASE_NAMES[i], "count": phases.get(i, 0)}
            for i in range(9)
        ],
        "micro_state_distribution": [
            {"micro_state": k, "count": v} for k, v in states.most_common(15)
        ],
        "honeypot_targets": dict(targets),
        "mean_confidence": round(sum(confidences) / len(confidences), 4)
        if confidences else None,
        "config_changes": changes,
        "alerts_fired": alerts,
        "gateway_classifier": traffic_classifier.stats(),
        "rate_limiter": rate_limiter.stats(),
        "pipeline": _pipeline.stats() if _pipeline is not None else None,
    })


# ── Blacklist ────────────────────────────────────────────────────────────────
@app.get("/api/blacklist")
def get_blacklist():
    with blacklist_manager._lock:
        entries = [{"ip": ip, **meta}
                   for ip, meta in blacklist_manager._blacklist.items()]
    for e in entries:
        rec = classifier.get(e["ip"])
        e["risk_score"] = rec.risk_score
        e["total_connections"] = rec.total_connections
        e["last_seen"] = rec.last_seen
    entries.sort(key=lambda e: e.get("blacklisted_at", ""), reverse=True)
    return jsonify({"count": len(entries), "blacklist": entries})


@app.post("/api/blacklist")
def add_blacklist():
    data = _body()
    ok, ip = _valid_ip(data.get("ip"))
    if not ok:
        return jsonify({"error": "invalid or missing 'ip'"}), 400
    reason = str(data.get("reason") or "manual (dashboard)")
    blacklist_manager.blacklist(ip, reason=reason, source="dashboard",
                                risk_score=data.get("risk_score"))
    log.warning("blacklist add %s: %s", ip, reason)
    return jsonify({"ok": True, "ip": ip, "reason": reason,
                    "status": classifier.get_status(ip).value}), 201


@app.delete("/api/blacklist/<ip>")
def remove_blacklist(ip: str):
    ok, ip_norm = _valid_ip(ip)
    if not ok:
        return jsonify({"error": f"invalid ip {ip!r}"}), 400
    removed = blacklist_manager.remove_from_blacklist(ip_norm)
    if not removed:
        return jsonify({"error": f"{ip_norm} is not blacklisted"}), 404
    # Drop the IP back to UNKNOWN so the gateway re-evaluates it from scratch.
    classifier.set_status(ip_norm, IPStatus.UNKNOWN,
                          reason="removed from blacklist via dashboard")
    rate_limiter.unblock(ip_norm)
    log.info("blacklist remove %s", ip_norm)
    return jsonify({"ok": True, "ip": ip_norm,
                    "status": classifier.get_status(ip_norm).value})


# ── Whitelist ────────────────────────────────────────────────────────────────
@app.get("/api/whitelist")
def get_whitelist():
    with blacklist_manager._lock:
        entries = [{"ip": ip, **meta}
                   for ip, meta in blacklist_manager._whitelist.items()]
    for e in entries:
        rec = classifier.get(e["ip"])
        e["risk_score"] = rec.risk_score
        e["total_connections"] = rec.total_connections
        e["last_seen"] = rec.last_seen
    entries.sort(key=lambda e: e.get("whitelisted_at", ""), reverse=True)
    return jsonify({"count": len(entries), "whitelist": entries})


@app.post("/api/whitelist")
def add_whitelist():
    data = _body()
    ok, ip = _valid_ip(data.get("ip"))
    if not ok:
        return jsonify({"error": "invalid or missing 'ip'"}), 400
    reason = str(data.get("reason") or "manual (dashboard)")
    blacklist_manager.whitelist(ip, reason=reason, source="dashboard")
    log.info("whitelist add %s: %s", ip, reason)
    return jsonify({"ok": True, "ip": ip, "reason": reason,
                    "status": classifier.get_status(ip).value}), 201


@app.delete("/api/whitelist/<ip>")
def remove_whitelist(ip: str):
    """Not in the Step 5 list, but the dashboard needs the inverse of POST."""
    ok, ip_norm = _valid_ip(ip)
    if not ok:
        return jsonify({"error": f"invalid ip {ip!r}"}), 400
    with blacklist_manager._lock:
        if ip_norm not in blacklist_manager._whitelist:
            return jsonify({"error": f"{ip_norm} is not whitelisted"}), 404
        del blacklist_manager._whitelist[ip_norm]
        blacklist_manager._save_whitelist()
    classifier.set_status(ip_norm, IPStatus.UNKNOWN,
                          reason="removed from whitelist via dashboard")
    return jsonify({"ok": True, "ip": ip_norm,
                    "status": classifier.get_status(ip_norm).value})


# ── Honeypot config ──────────────────────────────────────────────────────────
@app.get("/api/active-config")
def active_config():
    cfg = _configurator()
    return jsonify({
        "active_config": cfg.load_active(),
        "config_path": str(cfg.config_path),
        "changes_this_run": cfg.changes,
        "recent_changes": cfg.recent_changes(limit=10),
    })


@app.get("/api/config-changes")
def config_changes():
    limit = request.args.get("limit", default=25, type=int)
    return jsonify({"changes": _configurator().recent_changes(limit=limit)})


# ── Live access control (the two-laptop demo) ────────────────────────────────
def _tail_events(path: Path, limit: int = 4000) -> List[Dict[str, Any]]:
    """Last `limit` JSON events from the gateway event log."""
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows[-limit:]


@app.get("/api/live-access")
def live_access():
    """Every routing decision the gateway has made, newest first.

    This is what the live demo watches: who connected, what the classifier
    decided, and whether they reached the real server or the honeypot.
    """
    limit = request.args.get("limit", default=40, type=int)
    events = _tail_events(GATEWAY_EVENT_LOG)

    # index the session close events so each decision can show its byte counts
    closes: Dict[str, Dict[str, Any]] = {}
    for e in events:
        if e.get("event") == "CONN_CLOSED" and e.get("session_id"):
            closes[e["session_id"]] = e
    session_by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for e in events:
        if e.get("event") == "PROXY_CONNECTED":
            session_by_ip.setdefault(e.get("ip", ""), []).append(e)

    decisions: List[Dict[str, Any]] = []
    for e in events:
        if e.get("event") != "CONN_ROUTED":
            continue
        ip = e.get("ip", "")
        rec = classifier.get(ip)
        target_type = e.get("target_type", "")
        decisions.append({
            "ts": e.get("ts"),
            "ip": ip,
            "verdict": e.get("verdict"),
            "score": e.get("score"),
            "signals": e.get("signals", []),
            "reason": e.get("reason"),
            "target_type": target_type,
            "target": e.get("target"),
            "destination": ("REAL SERVER" if target_type == "backend"
                            else "HONEYPOT" if target_type == "honeypot"
                            else "REJECTED"),
            "ip_status": e.get("ip_status") or rec.status.value,
            "total_connections": rec.total_connections,
            "is_blacklisted": blacklist_manager.is_blacklisted(ip),
            "is_whitelisted": blacklist_manager.is_whitelisted(ip),
        })

    rejects = [e for e in events if e.get("event") == "CONN_REJECTED"]
    for e in rejects:
        decisions.append({
            "ts": e.get("ts"), "ip": e.get("ip", ""), "verdict": None, "score": None,
            "signals": [], "reason": e.get("reason"), "target_type": "reject",
            "target": None, "destination": "REJECTED",
            "ip_status": classifier.get(e.get("ip", "")).status.value,
            "total_connections": classifier.get(e.get("ip", "")).total_connections,
            "is_blacklisted": blacklist_manager.is_blacklisted(e.get("ip", "")),
            "is_whitelisted": blacklist_manager.is_whitelisted(e.get("ip", "")),
        })

    decisions.sort(key=lambda d: str(d.get("ts") or ""), reverse=True)
    decisions = decisions[:max(1, min(limit, 500))]

    # per-IP rollup for the "who is connected" panel
    peers: Dict[str, Dict[str, Any]] = {}
    for d in decisions:
        p = peers.setdefault(d["ip"], {
            "ip": d["ip"], "connections": 0, "to_real": 0, "to_honeypot": 0,
            "rejected": 0, "last_seen": d["ts"], "last_verdict": d["verdict"],
            "last_score": d["score"], "ip_status": d["ip_status"],
            "is_blacklisted": d["is_blacklisted"], "is_whitelisted": d["is_whitelisted"],
        })
        p["connections"] += 1
        p["to_real"] += d["target_type"] == "backend"
        p["to_honeypot"] += d["target_type"] == "honeypot"
        p["rejected"] += d["target_type"] == "reject"

    return jsonify({
        "count": len(decisions),
        "decisions": decisions,
        "peers": sorted(peers.values(), key=lambda p: str(p["last_seen"]), reverse=True),
        "classifier_routing": bool(CONFIG.CLASSIFIER_ROUTING),
        "real_backend": str(CONFIG.REAL_BACKEND),
        "honeypots": [str(t) for t in CONFIG.HONEYPOT_TARGETS],
    })


@app.get("/api/footprints")
def footprints():
    """What attackers actually typed inside the honeypot, newest first."""
    limit = request.args.get("limit", default=60, type=int)
    ip_filter = request.args.get("ip")
    cowrie_log = (REPO_ROOT / "honeypot_dataset" / "cowrie" / "logs" / "cowrie.json")

    rows: List[Dict[str, Any]] = []
    session_starts: Dict[str, Any] = {}
    if cowrie_log.exists():
        # first pass: when did each session open?
        with cowrie_log.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or "session.connect" not in line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if e.get("eventid") == "cowrie.session.connect" and e.get("session"):
                    session_starts[e["session"]] = e.get("timestamp")
        with cowrie_log.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if e.get("eventid") not in (
                    "cowrie.command.input", "cowrie.login.failed",
                    "cowrie.login.success", "cowrie.session.connect",
                ):
                    continue
                kind = e["eventid"].rsplit(".", 1)[-1]
                seen = str(e.get("src_ip", "") or "")
                # the honeypot saw the proxy, not the peer -- recover the peer
                sid = e.get("session", "")
                if looks_like_proxy(seen):
                    peer = attributor.resolve(
                        session_starts.get(sid, e.get("timestamp")), fallback=seen)
                else:
                    peer = seen
                if ip_filter and peer != ip_filter:
                    continue
                rows.append({
                    "ts": e.get("timestamp"),
                    "ip": peer,
                    "observed_ip": seen if peer != seen else None,
                    "session": e.get("session"),
                    "kind": kind,
                    "detail": (e.get("input") if kind == "input"
                               else f"{e.get('username','')} / {e.get('password','')}"
                               if kind in ("failed", "success") else "session opened"),
                })
    rows.sort(key=lambda r: str(r.get("ts") or ""), reverse=True)
    return jsonify({"count": len(rows[:limit]), "footprints": rows[:max(1, min(limit, 500))],
                    "log": str(cowrie_log)})


def lan_ip() -> str:
    """This machine's LAN address -- what peers must connect to."""
    import socket as _s

    try:
        with _s.socket(_s.AF_INET, _s.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))       # no packet is sent
            return sock.getsockname()[0]
    except Exception:
        return "127.0.0.1"


@app.get("/api/health")
def health():
    return jsonify({
        "ok": True,
        "time": _utcnow(),
        "lan_ip": lan_ip(),
        "gateway_port": CONFIG.GATEWAY_PORT,
        "classifier_routing": bool(CONFIG.CLASSIFIER_ROUTING),
        "results_file": str(_results_path),
        "results_exist": _results_path.exists(),
        "pipeline_started": bool(_pipeline and _pipeline.started),
        "mt3": (_pipeline.mt3.meta if _pipeline and _pipeline.started else None),
    })


# ── Dashboard pages + the existing SSE stream ────────────────────────────────
@app.get("/")
def index():
    return send_file(STATIC_DIR / "index.html")


@app.get("/pipeline")
def pipeline_page():
    page = STATIC_DIR / "pipeline.html"
    if not page.exists():
        return jsonify({"error": "pipeline.html not built"}), 404
    return send_file(page)


@app.get("/live")
def live_page():
    """Live access-control view for the two-laptop demo."""
    page = STATIC_DIR / "live.html"
    if not page.exists():
        return jsonify({"error": "live.html not built"}), 404
    return send_file(page)


@app.get("/events")
def events():
    """SSE feed of gateway events -- what dashboard/static/index.html expects."""
    if _dash_state is None:
        return jsonify({"error": "event stream not started"}), 503
    from dashboard import backend as dash  # type: ignore

    q: "queue.Queue[str]" = queue.Queue(maxsize=300)
    with dash._ql:
        dash._qs.append(q)
    init = json.dumps({"type": "init", "demo_mode": False,
                       **_dash_state.full_state()}, default=str)

    def gen():
        try:
            yield f"data: {init}\n\n"
            while True:
                try:
                    yield q.get(timeout=20)
                except queue.Empty:
                    yield ": hb\n\n"
        finally:
            with dash._ql:
                try:
                    dash._qs.remove(q)
                except ValueError:
                    pass

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/state")
def api_state():
    """Full gateway-event state (the legacy dashboard's bootstrap endpoint)."""
    if _dash_state is None:
        return jsonify({"error": "event stream not started"}), 503
    return jsonify(_dash_state.full_state())


@app.get("/api/demo")
def api_demo():
    return jsonify({"demo_mode": False})


def start_event_stream(log_path: Path = GATEWAY_EVENT_LOG) -> bool:
    """Tail the gateway event log in a daemon thread to feed /events."""
    global _dash_state
    if _dash_state is not None:
        return True
    try:
        ensure_paths()
        from dashboard import backend as dash  # type: ignore

        _dash_state = dash.DashboardState()
        threading.Thread(target=dash._tail, args=(Path(log_path), _dash_state),
                         daemon=True, name="gateway_event_tail").start()
        return True
    except Exception as exc:
        log.warning("gateway event stream unavailable: %s", exc)
        return False


def serve(host: str = "0.0.0.0", port: int = 5000, *,
          results_path: Optional[Path] = None, pipeline: Any = None,
          events: bool = True, debug: bool = False) -> None:
    configure(results_path, pipeline)
    if events:
        start_event_stream()
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host=host, port=port, threaded=True, debug=debug,
            use_reloader=False)


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Adaptive honeypot gateway API")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--results", default=str(DEFAULT_RESULTS_PATH))
    ap.add_argument("--no-events", action="store_true",
                    help="do not tail the gateway event log for /events")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)-7s] %(message)s")
    print(f"  API       : http://localhost:{args.port}/api/live-feed")
    print(f"  Dashboard : http://localhost:{args.port}/")
    print(f"  Pipeline  : http://localhost:{args.port}/pipeline")
    serve(args.host, args.port, results_path=Path(args.results),
          events=not args.no_events)


if __name__ == "__main__":
    main()
