"""
response_mitigation/replay.py

Feed recorded sessions through the mitigation policy and report what it WOULD do, and, if you know
which sources were really attackers, how often it would have been wrong.

    results = pipeline_results.jsonl lines (one session each: src_ip + mt3_prediction)
    labels  = {"1.2.3.4": "attack", "5.6.7.8": "benign", ...}     (optional)

Nothing real happens: the gateway is an in-memory stand-in, the block list and audit log are in a
temporary folder that is deleted afterwards, and no firewall or webhook is touched.

Time is simulated from each line's `processed_at`, so "at most 50 new blocks an hour" and "a block
lasts 24 hours" behave as they would live, not as if all the sessions arrived in one second.

Scoring (when labels are given), for each action separately:
    TP  an attacker the policy acted on        FP  a benign source the policy acted on
    FN  an attacker it did not act on          TN  a benign source it left alone
The false-positive rate, FP / (FP + TN), is the number the design asks for: how many benign
sources would have been diverted or blocked.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Set, Tuple

from .audit import AuditLog
from .blocklist import BlocklistFile
from .config import load_config
from .engine import MitigationEngine
from .executors.alert import LogAlertExecutor
from .executors.firewall import FirewallExecutor
from .executors.gateway import GatewayExecutor
from .models import Action, Outcome, Verdict
from .safelist import Safelist, canonical

_ACTED = {Outcome.APPLIED, Outcome.WOULD_APPLY}


class _Gateway:
    """Stands in for the gateway's blacklist manager."""

    def __init__(self, whitelisted: Iterable[str] = ()) -> None:
        self.white: Set[str] = {canonical(w) or w for w in whitelisted}
        self.black: Set[str] = set()

    def is_whitelisted(self, ip: str) -> bool:
        return ip in self.white

    def is_blacklisted(self, ip: str) -> bool:
        return ip in self.black

    def blacklist(self, ip: str, *, reason: str, source: str, risk_score: Any) -> None:
        self.black.add(ip)


def read_results(path: Path) -> Tuple[List[Dict[str, Any]], int]:
    """(usable session records in file order, number of lines that were skipped)."""
    rows: List[Dict[str, Any]] = []
    skipped = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                pred = rec["mt3_prediction"]
                int(pred["phase"]), float(pred["confidence"])
                if not isinstance(rec.get("src_ip"), str):
                    raise KeyError("src_ip")
            except (ValueError, KeyError, TypeError):
                skipped += 1
                continue
            rows.append(rec)
    return rows, skipped


def read_labels(path: Path) -> Dict[str, str]:
    """{"ip": "attack"|"benign"}. Anything else is refused, so a typo cannot quietly change a score."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("the labels file must be one JSON object: {\"1.2.3.4\": \"attack\", ...}")
    labels: Dict[str, str] = {}
    for ip, label in raw.items():
        clean = canonical(ip)
        if clean is None or label not in ("attack", "benign"):
            raise ValueError(f"bad label entry {ip!r}: {label!r} (an IP address and \"attack\" or \"benign\")")
        labels[clean] = label
    return labels


def _epoch(rec: Dict[str, Any], previous: float) -> float:
    try:
        return _dt.datetime.fromisoformat(str(rec["processed_at"])).timestamp()
    except (KeyError, ValueError, TypeError):
        return previous + 1.0


def _score(acted: Set[str], labels: Mapping[str, str], seen: Set[str]) -> Dict[str, Any]:
    attack = {ip for ip in seen if labels.get(ip) == "attack"}
    benign = {ip for ip in seen if labels.get(ip) == "benign"}
    tp, fp = len(acted & attack), len(acted & benign)
    fn, tn = len(attack - acted), len(benign - acted)

    def ratio(a: int, b: int) -> Optional[float]:
        return round(a / b, 4) if b else None

    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn), "false_positive_rate": ratio(fp, fp + tn),
            "benign_sources_hit": sorted(acted & benign)}


def replay(records: Iterable[Dict[str, Any]], *, mode: str = "observe", firewall: bool = False,
           labels: Optional[Mapping[str, str]] = None, whitelist: Iterable[str] = (),
           env: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """Run `records` through a fresh engine. `env` takes the same MITIGATION_* settings as a live run
    (policy thresholds, block time, hourly cap, never-block list); paths are always temporary."""
    labels = labels or {}
    with tempfile.TemporaryDirectory(prefix="mitigation-replay-") as tmp:
        tmp_path = Path(tmp)
        cfg = load_config({**(env or {}), "MITIGATION_MODE": mode, "MITIGATION_FIREWALL": "1" if firewall else "0",
                           "MITIGATION_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
                           "MITIGATION_BLOCKLIST_PATH": str(tmp_path / "blocklist.json"),
                           "MITIGATION_KILL_FILE": str(tmp_path / "STOP"),
                           "MITIGATION_ALERT_WEBHOOK": ""})
        cfg = dataclasses.replace(cfg, alert_webhook=None)
        now = [0.0]
        gateway = _Gateway(whitelist)
        blocklist = BlocklistFile(cfg.blocklist_path, clock=lambda: now[0])
        engine = MitigationEngine(
            cfg, safelist=Safelist(never_block=cfg.never_block, is_whitelisted=gateway.is_whitelisted),
            audit=AuditLog(cfg.audit_path),
            executors={Action.DIVERT: GatewayExecutor(gateway), Action.ALERT: LogAlertExecutor(),
                       Action.DENY: FirewallExecutor(blocklist, default_ttl_s=cfg.policy.deny_ttl_s)},
            blocklist=blocklist, clock=lambda: now[0])

        counts: Counter = Counter()
        skip_reasons: Counter = Counter()
        seen: Set[str] = set()
        acted: Dict[str, Set[str]] = {a.value: set() for a in Action}
        sessions = 0
        for rec in records:
            pred = rec["mt3_prediction"]
            now[0] = _epoch(rec, now[0])
            ip = canonical(rec["src_ip"]) or str(rec["src_ip"])
            seen.add(ip)
            sessions += 1
            verdict = Verdict(ip=ip, phase=int(pred["phase"]), phase_name=str(pred.get("phase_name", "")),
                              micro_state=str(pred.get("micro_state", "")), confidence=float(pred["confidence"]),
                              session_id=str(rec.get("session_id", "")))
            # keep the gateway's own blacklist out of it: each session is judged on the policy alone
            for decision in engine.handle(verdict):
                action, outcome = decision.planned.action, decision.outcome
                counts[(action.value, outcome.value)] += 1
                if outcome is Outcome.SKIPPED:
                    skip_reasons[(action.value, decision.detail)] += 1
                if outcome in _ACTED and action is not Action.OBSERVE:
                    acted[action.value].add(ip)

        report: Dict[str, Any] = {
            "mode": mode, "firewall": firewall, "sessions": sessions, "distinct_sources": len(seen),
            "decisions": {f"{a}/{o}": n for (a, o), n in sorted(counts.items())},
            "skipped_because": [{"action": a, "why": w, "times": n} for (a, w), n in skip_reasons.most_common(8)],
            "sources_acted_on": {a: sorted(ips) for a, ips in acted.items() if ips},
            "blocks_still_active_at_the_end": len(blocklist.entries()),
        }
        if labels:
            report["labelled_sources"] = {"attack": sum(1 for ip in seen if labels.get(ip) == "attack"),
                                          "benign": sum(1 for ip in seen if labels.get(ip) == "benign"),
                                          "unlabelled": sum(1 for ip in seen if ip not in labels)}
            report["scores"] = {a: _score(acted[a], labels, seen) for a in ("divert", "deny", "alert")}
        return report


def format_report(report: Dict[str, Any]) -> str:
    """The same report, in plain words."""
    out: List[str] = []
    out.append(f"Replayed {report['sessions']} sessions from {report['distinct_sources']} sources "
               f"(mode {report['mode']}, firewall {'on' if report['firewall'] else 'off'}).")
    out.append("")
    out.append("What the policy did:")
    for key, n in report["decisions"].items():
        out.append(f"  {n:6d}  {key}")
    if report["skipped_because"]:
        out.append("")
        out.append("Most common reasons something was skipped:")
        for item in report["skipped_because"]:
            out.append(f"  {item['times']:6d}  {item['action']}: {item['why']}")
    acted = report["sources_acted_on"]
    out.append("")
    out.append("Sources it acted on (or, in observe mode, would have):")
    names = {"divert": "sent to the honeypot", "deny": "blocked at the firewall", "alert": "alerted on"}
    if not acted:
        out.append("  none")
    for action, ips in acted.items():
        shown = ", ".join(ips[:12]) + (f", ... ({len(ips)} in all)" if len(ips) > 12 else "")
        out.append(f"  {names.get(action, action)} ({len(ips)}): {shown}")
    if "scores" in report:
        lab = report["labelled_sources"]
        out.append("")
        out.append(f"Against your labels ({lab['attack']} attack, {lab['benign']} benign, {lab['unlabelled']} unlabelled):")
        for action, s in report["scores"].items():
            if s["tp"] + s["fp"] + s["fn"] + s["tn"] == 0:
                continue
            fpr = "n/a" if s["false_positive_rate"] is None else f"{s['false_positive_rate']:.1%}"
            pre = "n/a" if s["precision"] is None else f"{s['precision']:.1%}"
            rec = "n/a" if s["recall"] is None else f"{s['recall']:.1%}"
            out.append(f"  {names.get(action, action)}: caught {s['tp']} attackers, missed {s['fn']}; "
                       f"wrongly hit {s['fp']} benign of {s['fp'] + s['tn']} (false-positive rate {fpr}); "
                       f"precision {pre}, recall {rec}")
            if s["benign_sources_hit"]:
                out.append(f"      benign sources hit: {', '.join(s['benign_sources_hit'][:10])}")
    return "\n".join(out)
