#!/usr/bin/env python3
"""
deploy/sandbox/tools/record_pipeline_writes.py

Run the real post-session pipeline on a COPY of the code, over a made-up Cowrie log, and record
every file it writes.

Why this exists. honeypot-pipeline.service runs with a read-only filesystem except a short list of
folders (ReadWritePaths). If the pipeline ever starts writing somewhere new, the service fails on the
server and nothing says why. tests/test_sandbox_writes.py runs this and compares the result with the
unit file, so that mistake is caught here instead.

What is real: the Cowrie log parser, all 128-feature extractors, the configurator (bait files and
active_config.json), the mitigation engine (including the firewall executor), the gateway blacklist and
the pipeline's own bookkeeping.
What is a stand-in: the trained MT3 model (always answers "phase 5, 93 %", so the repeat-offender
rule fires on the third session from one address) and the threat-intel download. No network is used.
Group D (DistilBERT) is zero-filled because semantic_pca.pkl is not in the copy; its HF cache folder is
therefore not exercised.

By hand:   python deploy/sandbox/tools/record_pipeline_writes.py [--keep]
Needs numpy, pandas, requests and joblib (the project venv has them).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]

# Only the code the pipeline imports. Not the data, the models, the notebooks or the tests.
CODE_DIRS = ["traffic_gateway", "response_mitigation", "adaptive_honeypot", "ml_analytics", "cve_intelligence",
             "honeypot_dataset/src", "honeypot_dataset/configs"]
_ALWAYS_SKIP = {"__pycache__", "tests", "notebooks"}
_SKIP_UNDER = {"traffic_gateway": {"data", "logs"}, "ml_analytics": {"artifacts", "data"}}
_SKIP_SUFFIX = (".pyc", ".pt", ".npy", ".npz", ".pkl")

SOURCE_IP = "45.33.32.156"        # three sessions: the repeat-offender rule fires on the third
OTHER_IP = "172.217.14.206"       # a public address that starts with 172 (the old text check got this wrong)


def copy_code(repo_root: Path, dest: Path) -> None:
    def ignore(directory: str, names: List[str]):
        top = Path(directory).resolve().relative_to(repo_root.resolve()).parts[:1]
        skip = set(_ALWAYS_SKIP) | (_SKIP_UNDER.get(top[0], set()) if top else set())
        return {n for n in names if n in skip or n.endswith(_SKIP_SUFFIX)}

    for rel in CODE_DIRS:
        shutil.copytree(repo_root / rel, dest / rel, ignore=ignore)

    # Start the honeypot from its day-zero posture, not from whatever state this
    # machine happens to be in. active_config.json lives inside adaptive_honeypot/
    # and so gets copied with the code, which made this recording -- and the test
    # built on it -- depend on live repo state: the configurator only writes its
    # change log when something MATERIAL changes, so if the copied config already
    # matched what the stub predicts, app/logs was never written and
    # test_the_allowed_folders_are_used_not_just_listed failed. Seen for real: the
    # repo sat at phase 6 "high" while the stub predicts phase 5, which maps to
    # "high" as well, so nothing changed and the folder looked like a stale
    # allowance. Removing it makes the run hermetic.
    stale = dest / "adaptive_honeypot" / "active_config.json"
    if stale.exists():
        stale.unlink()


def write_cowrie_log(path: Path) -> None:
    """Four sessions in Cowrie's JSON format: brute force, discovery, then a cron job."""
    def stamp(base: float, offset: float) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(base + offset)) + ".000000Z"

    def session(n: int, ip: str) -> List[Dict[str, Any]]:
        sid, t = f"{n:012x}", 1_800_000_000 + n * 100
        ev = lambda offset, **kw: dict(session=sid, timestamp=stamp(t, offset), **kw)      # noqa: E731
        return [
            ev(0, eventid="cowrie.session.connect", src_ip=ip, src_port=40000 + n, dst_ip="10.0.0.5",
               dst_port=2222, protocol="ssh", sensor="sandbox-cowrie-1"),
            ev(1, eventid="cowrie.client.version", version="SSH-2.0-libssh2_1.9"),
            ev(2, eventid="cowrie.login.failed", username="root", password="123456"),
            ev(3, eventid="cowrie.login.failed", username="root", password="admin"),
            ev(4, eventid="cowrie.login.success", username="root", password="toor"),
            ev(6, eventid="cowrie.command.input", input="uname -a"),
            ev(8, eventid="cowrie.command.input", input="cat /etc/passwd"),
            ev(10, eventid="cowrie.command.input", input="(crontab -l; echo '* * * * * /tmp/x') | crontab -"),
            ev(12, eventid="cowrie.session.closed", duration=12.0),
        ]

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for n in range(3):
            for event in session(n, SOURCE_IP):
                handle.write(json.dumps(event) + "\n")
        for event in session(9, OTHER_IP):
            handle.write(json.dumps(event) + "\n")


# Runs in a child process so the audit hook sees everything from the first import on.
_DRIVER = textwrap.dedent('''
    import json, os, sys, warnings
    warnings.simplefilter("ignore")
    writes = []

    def hook(event, args):
        try:
            if event == "open":
                path, mode, flags = args
                if isinstance(path, (str, os.PathLike)):
                    wrote = any(c in (mode or "") for c in "wax+") or (
                        isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND))
                    if wrote:
                        writes.append(["open", os.path.abspath(os.fspath(path))])
            elif event in ("os.mkdir", "os.rename", "os.remove", "os.rmdir", "os.truncate"):
                for a in args:
                    if isinstance(a, (str, os.PathLike)):
                        writes.append([event, os.path.abspath(os.fspath(a))])
        except Exception:
            pass

    sys.addaudithook(hook)
    sys.path.insert(0, os.environ["REC_APP"])
    from pathlib import Path
    from traffic_gateway import post_session_pipeline as psp

    class StubMT3:
        meta = {"stub": True}
        def load(self): return None
        def predict(self, x_raw):
            return {"micro_state": "PERSIST_CRON", "phase": 5, "phase_name": "Persistence",
                    "confidence": 0.93, "top3": []}

    psp.MT3Inference = StubMT3
    psp.ThreatIntelCache.prefetch = lambda self: {"kev_count": 0}

    pipe = psp.PostSessionPipeline(Path(os.environ["REC_LOGS"]), Path(os.environ["REC_RESULTS"]), from_start=True)
    pipe.startup()
    results = pipe.scan_once()
    summary = [{"session": r["session_id"], "ip": r["src_ip"],
                "decisions": [[m["action"], m["outcome"]] for m in r["mitigation"]]} for r in results]
    json.dump({"writes": writes, "sessions": summary}, open(os.environ["REC_OUT"], "w"))
''')


def record(*, work_dir: Path, env: Mapping[str, str], results_path: Path, cowrie_log_dir: Path,
           repo_root: Path = REPO_ROOT) -> Dict[str, Any]:
    """Copy the code under work_dir/app, write the made-up log, run the pipeline, and return
    {"app": Path, "writes": [(kind, absolute path)], "sessions": [...]}."""
    app = work_dir / "app"
    copy_code(repo_root, app)
    write_cowrie_log(cowrie_log_dir / "cowrie.json")
    out = work_dir / "writes.json"
    child_env = dict(os.environ)
    child_env.update(env)
    child_env.update(REC_APP=str(app), REC_LOGS=str(cowrie_log_dir), REC_RESULTS=str(results_path),
                     REC_OUT=str(out), PYTHONDONTWRITEBYTECODE="1", HF_HUB_OFFLINE="1")
    done = subprocess.run([sys.executable, "-c", _DRIVER], cwd=str(app), env=child_env,
                          capture_output=True, text=True, timeout=600)
    if done.returncode != 0 or not out.exists():
        raise RuntimeError(f"the pipeline run failed (exit {done.returncode}):\n{done.stderr[-2000:]}")
    data = json.loads(out.read_text(encoding="utf-8"))
    return {"app": app, "writes": [(k, p) for k, p in data["writes"]], "sessions": data["sessions"]}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Record the files the pipeline writes.")
    ap.add_argument("--keep", action="store_true", help="keep the temporary folder and print where it is")
    args = ap.parse_args(argv)

    work = Path(tempfile.mkdtemp(prefix="rec-writes-"))
    try:
        state = work / "state"
        env = {"GATEWAY_DATA_DIR": str(state / "gateway" / "data"), "GATEWAY_LOG_DIR": str(state / "gateway" / "logs"),
               "MITIGATION_MODE": "enforce", "MITIGATION_FIREWALL": "1",
               "MITIGATION_BLOCKLIST_PATH": str(state / "guard" / "blocklist.json"),
               "MITIGATION_AUDIT_PATH": str(state / "mitigation" / "mitigation_audit.jsonl"),
               "MITIGATION_KILL_FILE": str(state / "guard" / "MITIGATION_DISABLED")}
        result = record(work_dir=work, env=env, results_path=state / "pipeline" / "pipeline_results.jsonl",
                        cowrie_log_dir=work / "app" / "honeypot_dataset" / "cowrie" / "logs")
        print(f"{len(result['sessions'])} sessions processed")
        for s in result["sessions"]:
            print(f"  {s['session']} {s['ip']:16s} {s['decisions']}")
        folders = sorted({str(Path(p).parent.relative_to(work)) if Path(p).is_relative_to(work) else p
                          for _, p in result["writes"]})
        print("folders written to:")
        for folder in folders:
            print("  ", folder)
    finally:
        if args.keep:
            print("kept:", work)
        else:
            shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
