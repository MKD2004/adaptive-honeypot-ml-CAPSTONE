"""
ml_analytics/mt3_pipeline/acceptance_heralding.py

The gate a retrained MT3 must pass before `heralding` may be added to
CONFIG.MT3_TRUSTED_SOURCES.

Six scenarios, taken from the failure recorded in HONEYPOT_AUDIT.md PART 7. The
current checkpoint scores 0/6 and is *confidently* wrong on all of them -- a bare
connect with no authentication attempt comes back DISC_NETSTAT_SCAN at confidence
0.998, which clears MT3_AUTO_BLACKLIST_CONF and would blacklist a user for
opening a TCP connection.

Run:
    python -m ml_analytics.mt3_pipeline.acceptance_heralding \
        --ckpt ml_analytics/artifacts/mt3_full_d256/best.pt

Exit code 0 = every criterion met. Non-zero = do not trust this model on
Heralding. The criteria are deliberately modest; they are a safety floor, not a
quality bar:

  1. AGREEMENT. >= 80% of scenarios match the rule label. The rule labeller is a
     heuristic, so this measures agreement, NOT accuracy -- report it in those
     words (MULTI_HONEYPOT.md 7.6).
  2. NO CONFIDENT NONSENSE. On a bare connect (no auth attempt at all) the model
     must not return a phase >= 1 verdict above MT3_AUTO_BLACKLIST_CONF. This is
     the one that actually protects users; a model can fail (1) and still be
     safe, but failing (2) means it blacklists innocents.
  3. PHASE SANITY. No scenario may be assigned a phase above 1. Everything
     Heralding can observe is reconnaissance or initial access -- it has no
     shell, so Execution and beyond are unreachable by construction.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]

AGREEMENT_FLOOR = 0.80
MAX_PLAUSIBLE_PHASE = 1

# (name, protocol, port, auth attempts) -- the PART 7 set, plus the ssh variant.
SCENARIOS: List[Tuple[str, str, int, List[Tuple[str, str]]]] = [
    ("bare connect", "http", 80, []),
    ("user enum", "http", 80, [("admin", ""), ("root", ""), ("test", "")]),
    ("cred stuffing", "http", 80, [("alice", "P@ss"), ("bob", "P@ss"),
                                   ("carol", "P@ss"), ("dave", "P@ss")]),
    ("factory defaults", "http", 80, [("admin", "admin")]),
    ("http brute force", "http", 80, [("admin", "hunter2"), ("admin", "letmein"),
                                      ("admin", "qwerty")]),
    ("ftp brute force", "ftp", 21, [("anon", "x1y2"), ("anon", "z3w4")]),
]


def _session(protocol: str, port: int, attempts: List[Tuple[str, str]]) -> Dict:
    return {
        "timestamp": "2026-11-04 10:00:00.123456", "duration": 12,
        "session_id": f"acc-{protocol}-{len(attempts)}",
        "source_ip": "198.51.100.7", "source_port": 51515,
        "destination_ip": "10.0.0.2", "destination_port": port,
        "protocol": protocol, "num_auth_attempts": len(attempts),
        "auth_attempts": [{"timestamp": f"2026-11-04 10:00:{i + 1:02d}.000000",
                           "username": u, "password": p}
                          for i, (u, p) in enumerate(attempts)],
        "session_ended": True, "auxiliary_data": {}, "sensor": "acceptance",
    }


def run(ckpt: Path, verbose: bool = True) -> Dict:
    import numpy as np
    import tempfile

    import traffic_gateway.config as cfg
    tmp = Path(tempfile.mkdtemp())
    cfg.CONFIG.DATA_DIR = tmp / "d"
    cfg.CONFIG.LOG_DIR = tmp / "l"
    cfg.CONFIG.DATA_DIR.mkdir(parents=True, exist_ok=True)
    cfg.CONFIG.LOG_DIR.mkdir(parents=True, exist_ok=True)
    blacklist_conf = float(cfg.CONFIG.MT3_AUTO_BLACKLIST_CONF)

    from traffic_gateway.ext_paths import ensure_paths
    from traffic_gateway.feature_bridge import (MT3Inference, ThreatIntelCache,
                                                extract_features, group_d_mode)
    ensure_paths()
    from src.parsers import heralding_parser as hp  # type: ignore

    ti = ThreatIntelCache()
    ti.prefetch()

    class _ZeroSemantic:          # Group D is zero-filled for heralding (Phase 1b)
        available = True
        def encode(self, text):
            return np.zeros(30, dtype=np.float32)

    mt3 = MT3Inference(ckpt_path=ckpt)
    mt3.load()

    results = []
    for name, proto, port, attempts in SCENARIOS:
        rec = hp.build_record([_session(proto, port, attempts)])
        assert group_d_mode(rec) == "zero-filled"
        pred = mt3.predict(extract_features(rec, ti, _ZeroSemantic()))
        results.append({
            "scenario": name,
            "rule_label": rec["micro_state"],
            "mt3": pred["micro_state"],
            "confidence": float(pred["confidence"]),
            "phase": int(pred["phase"]),
            "agrees": pred["micro_state"] == rec["micro_state"],
            "n_auth": len(attempts),
        })

    agree = sum(r["agrees"] for r in results) / len(results)

    bare = next(r for r in results if r["n_auth"] == 0)
    confident_nonsense = bare["phase"] >= 1 and bare["confidence"] >= blacklist_conf

    over_phase = [r for r in results if r["phase"] > MAX_PLAUSIBLE_PHASE]

    criteria = {
        "agreement": {"value": round(agree, 4), "floor": AGREEMENT_FLOOR,
                      "pass": agree >= AGREEMENT_FLOOR},
        "no_confident_nonsense": {
            "value": f"bare connect -> {bare['mt3']} p={bare['confidence']:.3f} "
                     f"phase {bare['phase']}",
            "threshold": blacklist_conf, "pass": not confident_nonsense},
        "phase_sanity": {"value": f"{len(over_phase)} scenario(s) above phase "
                                  f"{MAX_PLAUSIBLE_PHASE}",
                         "pass": not over_phase},
    }
    ok = all(c["pass"] for c in criteria.values())

    if verbose:
        print(f"\ncheckpoint: {ckpt}")
        print(f"{'scenario':<20}{'rule label':<22}{'MT3':<22}{'conf':>7}{'phase':>7}  ok")
        print("-" * 88)
        for r in results:
            print(f"{r['scenario']:<20}{r['rule_label']:<22}{r['mt3']:<22}"
                  f"{r['confidence']:>7.3f}{r['phase']:>7}  {'=' if r['agrees'] else 'x'}")
        print(f"\n{'criterion':<26}{'result':<58}verdict")
        print("-" * 92)
        for name, c in criteria.items():
            print(f"{name:<26}{str(c['value']):<58}{'PASS' if c['pass'] else 'FAIL'}")
        print(f"\noverall: {'PASS -- safe to add heralding to MT3_TRUSTED_SOURCES' if ok else 'FAIL -- do NOT trust this model on heralding'}\n")

    return {"ckpt": str(ckpt), "scenarios": results, "criteria": criteria, "pass": ok}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--ckpt", default="ml_analytics/artifacts/mt3_full_d256/best.pt")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args(argv)

    out = run(Path(args.ckpt))
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"wrote {args.json_out}")
    return 0 if out["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
