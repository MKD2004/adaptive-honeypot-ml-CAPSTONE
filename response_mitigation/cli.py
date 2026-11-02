"""
response_mitigation/cli.py

The command line for the mitigation layer. Run it as:

    python -m response_mitigation status              what is on, what is blocked
    python -m response_mitigation blocks              the active firewall blocks
    python -m response_mitigation block IP [--hours N] [--reason TEXT]
    python -m response_mitigation unblock IP
    python -m response_mitigation off                 kill switch ON: stop all automatic decisions and
                                                      remove every firewall block (within ~15 s)
    python -m response_mitigation on                  kill switch OFF: resume (unexpired blocks come back)
    python -m response_mitigation audit [--tail N] [--ip IP]
    python -m response_mitigation replay RESULTS.jsonl [--labels FILE] [--mode observe|enforce] [--firewall]

It reads the same MITIGATION_* settings as the pipeline, so run it with the same environment
(on the server: the values in /etc/honeypot/pipeline.env). It changes the block list and the
kill-switch file only; the host script does the firewall. Every change is written to the audit
log with your user name.

Exit codes: 0 done | 1 refused or failed (the reason is printed) | 2 bad command or bad settings
"""
from __future__ import annotations

import argparse
import dataclasses
import getpass
import json
import sys
import time
from typing import IO, List, Mapping, Optional

from .blocklist import iso_utc
from .config import load_config
from .engine import build_engine
from .models import Decision, Outcome
from .replay import format_report, read_labels, read_results, replay


def _actor() -> str:
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:
        return "cli:unknown"


def _say(out: IO[str], text: str = "") -> None:
    print(text, file=out)


def _left(seconds: int) -> str:
    seconds = max(0, int(seconds))
    hours, rest = divmod(seconds, 3600)
    return f"{hours} h {rest // 60:02d} min" if hours else f"{rest // 60} min"


def _result(out: IO[str], decision: Decision, done: str) -> int:
    if decision.outcome is Outcome.APPLIED:
        _say(out, f"{done}. {decision.detail}".rstrip(". ") + ".")
        return 0
    word = "FAILED" if decision.outcome is Outcome.FAILED else "Not done"
    _say(out, f"{word}: {decision.detail}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m response_mitigation", description=__doc__.split("\n\n")[0].strip(),
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("status", help="what is on and what is blocked")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("blocks", help="the active firewall blocks")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("block", help="block an address at the firewall")
    p.add_argument("ip")
    p.add_argument("--hours", type=int, help="how long (1-720; default: the configured block time)")
    p.add_argument("--reason", default="blocked from the command line")
    p = sub.add_parser("unblock", help="take an address off the block list")
    p.add_argument("ip")
    p.add_argument("--reason", default="unblocked from the command line")
    sub.add_parser("off", help="kill switch ON: stop automatic decisions and remove every firewall block")
    sub.add_parser("on", help="kill switch OFF: resume")
    p = sub.add_parser("audit", help="the most recent decisions")
    p.add_argument("--tail", type=int, default=20)
    p.add_argument("--ip", default="")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("replay", help="run recorded sessions through the policy and report what it would do")
    p.add_argument("results", help="a pipeline_results.jsonl file")
    p.add_argument("--labels", help='JSON file: {"1.2.3.4": "attack", "5.6.7.8": "benign"}')
    p.add_argument("--whitelist", help="a text file of trusted addresses, one per line")
    p.add_argument("--mode", choices=("observe", "enforce"), default="observe")
    p.add_argument("--firewall", action="store_true", help="count firewall blocks as applied (as MITIGATION_FIREWALL=1)")
    p.add_argument("--json", action="store_true")
    return ap


def main(argv: Optional[List[str]] = None, *, env: Optional[Mapping[str, str]] = None,
         out: Optional[IO[str]] = None) -> int:
    out = out or sys.stdout
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:                        # argparse prints its own message
        return int(exc.code or 0) if exc.code in (0, None) else 2
    try:
        cfg = load_config(env)
    except ValueError as exc:
        _say(out, f"There is a problem with the settings: {exc}")
        return 2
    cfg = dataclasses.replace(cfg, alert_webhook=None)          # this tool never sends alerts

    if args.command == "replay":
        return _replay(args, cfg, out)

    engine = build_engine(blacklist_manager=None, config=cfg)
    actor = _actor()

    if args.command == "status":
        status = engine.status()
        if args.json:
            _say(out, json.dumps(status, indent=2))
            return 0
        _say(out, f"Mode: {status['mode']}" + ("   (KILL SWITCH IS ON: nothing automatic is happening)" if status["kill_switch"] else ""))
        _say(out, f"Firewall blocking by the pipeline: {'on' if status['firewall_enabled'] else 'off'}   "
                  f"(a person can always block with 'block')")
        _say(out, f"Active firewall blocks: {status['active_blocks'] if status['active_blocks'] is not None else 'unknown (block list unreadable)'}")
        _say(out, f"New automatic blocks this hour: {status['new_blocks_this_hour']} of {status['max_new_blocks_per_hour']} allowed")
        _say(out, f"Blocks last {status['block_hours']} hours by default.")
        _say(out, f"Never blocked: {', '.join(status['never_block']) or '(nothing set: add your own address to MITIGATION_NEVER_BLOCK)'}")
        _say(out, f"Chat alerts: {'on' if status['alert_webhook'] else 'off'}")
        _say(out, f"Files: block list {status['blocklist_path']}, audit log {status['audit_path']}, kill switch file {status['kill_file']}")
        return 0

    if args.command == "blocks":
        try:
            blocks = engine.active_blocks()
        except Exception as exc:
            _say(out, f"The block list cannot be read: {type(exc).__name__}: {exc}")
            return 1
        now = time.time()
        if args.json:
            _say(out, json.dumps([dataclasses.asdict(b) for b in blocks], indent=2))
            return 0
        if not blocks:
            _say(out, "No active firewall blocks.")
            return 0
        _say(out, f"{len(blocks)} active firewall block(s):")
        for b in blocks:
            _say(out, f"  {b.ip:40s} {_left(b.expires_at - now):>12s} left   {b.rule}: {b.reason}")
        return 0

    if args.command == "block":
        return _result(out, engine.firewall_block(args.ip, reason=args.reason, actor=actor, hours=args.hours),
                       f"Blocked {args.ip}")
    if args.command == "unblock":
        return _result(out, engine.firewall_unblock(args.ip, actor=actor, reason=args.reason),
                       f"Unblocked {args.ip}")
    if args.command == "off":
        return _result(out, engine.set_kill_switch(True, actor=actor), "Kill switch is ON")
    if args.command == "on":
        return _result(out, engine.set_kill_switch(False, actor=actor), "Kill switch is OFF")

    if args.command == "audit":
        rows = engine.recent_decisions(max(1, args.tail), ip=args.ip)
        if args.json:
            _say(out, json.dumps(rows, indent=2))
            return 0
        if not rows:
            _say(out, "The audit log has no matching decisions.")
            return 0
        for r in rows:
            _say(out, f"{r.get('ts', '?')}  {str(r.get('actor', '?')):14s} {str(r.get('action', '?')):8s} "
                      f"{str(r.get('outcome', '?')):11s} {str(r.get('ip', '')):40s} {r.get('rule', '')}: "
                      f"{str(r.get('detail', ''))[:90]}")
        return 0
    return 2


def _replay(args, cfg, out: IO[str]) -> int:
    try:
        records, skipped = read_results(args.results)
        labels = read_labels(args.labels) if args.labels else None
        whitelist = []
        if args.whitelist:
            with open(args.whitelist, encoding="utf-8") as fh:
                whitelist = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except (OSError, ValueError) as exc:
        _say(out, f"Cannot read the input: {exc}")
        return 2
    if not records:
        _say(out, "No usable sessions in that file (each line needs src_ip and mt3_prediction).")
        return 1
    env = {"MITIGATION_NEVER_BLOCK": ",".join(str(n) for n in cfg.never_block),
           "MITIGATION_MAX_NEW_BLOCKS_PER_HOUR": str(cfg.max_new_blocks_per_hour),
           "MITIGATION_DENY_TTL_HOURS": str(cfg.policy.deny_ttl_s // 3600),
           "MITIGATION_ALERT_MIN_PHASE": str(cfg.policy.alert_min_phase),
           "MITIGATION_DENY_MIN_PHASE": str(cfg.policy.deny_min_phase),
           "MITIGATION_DENY_REPEAT_SESSIONS": str(cfg.policy.deny_repeat_sessions)}
    report = replay(records, mode=args.mode, firewall=args.firewall, labels=labels, whitelist=whitelist, env=env)
    report["lines_skipped"] = skipped
    if args.json:
        _say(out, json.dumps(report, indent=2))
    else:
        _say(out, format_report(report))
        if skipped:
            _say(out, f"\n({skipped} line(s) in the file could not be used and were skipped.)")
    return 0
