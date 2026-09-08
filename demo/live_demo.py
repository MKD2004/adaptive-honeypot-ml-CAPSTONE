"""
demo/live_demo.py

One command that brings up the whole two-laptop demo: the real SSH server, the
SSH honeypot, the traffic gateway with classifier routing enabled, and the API
plus MT3 watcher. Prints the exact command your friends type and the firewall
rule that lets them reach you. Ctrl-C stops everything.
"""
from __future__ import annotations

import argparse
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable

COWRIE_DIR = REPO_ROOT / "honeypot_dataset" / "cowrie"
COWRIE_CONTAINER = "cowrie-honeypot"

COMPONENTS = [
    # (label, argv, the port it must end up listening on)
    ("REAL",     [PY, "demo/real_server.py"],                              8000),
    ("HONEYPOT", [PY, "demo/ssh_honeypot.py"],                             8081),
    ("GATEWAY",  [PY, "-m", "traffic_gateway.inspection_gateway"],         8080),
    ("PIPELINE", [PY, "-m", "traffic_gateway.run_pipeline", "--poll", "3"], 5000),
]


# ── Cowrie (the real honeypot, in Docker) ────────────────────────────────────
def docker_bin() -> Optional[str]:
    """Docker is not always on PATH on Windows even when it is installed."""
    import shutil

    found = shutil.which("docker")
    if found:
        return found
    # Docker Desktop installs either machine-wide or per-user; check both.
    for fallback in (
        Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"),
        Path.home() / r"AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe",
    ):
        if fallback.exists():
            return str(fallback)
    return None


def docker_ready(docker: Optional[str]) -> bool:
    if not docker:
        return False
    try:
        return subprocess.run([docker, "info", "--format", "{{.ServerVersion}}"],
                              capture_output=True, timeout=25).returncode == 0
    except Exception:
        return False


def cowrie_up(docker: str) -> bool:
    """Start (or reuse) the Cowrie container. Returns True once :8081 answers."""
    running = subprocess.run(
        [docker, "ps", "--filter", f"name={COWRIE_CONTAINER}",
         "--filter", "status=running", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=30)
    if COWRIE_CONTAINER in running.stdout:
        # If cowrie.json was deleted while the container held it open, Cowrie
        # keeps writing to the unlinked handle and the host file never comes
        # back -- the MT3 watcher would then see nothing at all. Restarting
        # makes it reopen the path. This happens every time someone clears the
        # logs between rehearsals without stopping the container.
        if not (COWRIE_DIR / "logs" / "cowrie.json").exists():
            print("  [COWRIE  ] log file missing -- restarting so Cowrie reopens it",
                  flush=True)
            subprocess.run([docker, "restart", COWRIE_CONTAINER],
                           capture_output=True, timeout=120)
        else:
            print("  [COWRIE  ] already running")
    else:
        print(f"  [COWRIE  ] docker compose up -d ...", flush=True)
        proc = subprocess.run([docker, "compose", "up", "-d"], cwd=str(COWRIE_DIR),
                              capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            print("  [COWRIE  ] failed to start:")
            for line in (proc.stderr or proc.stdout).strip().splitlines()[-6:]:
                print(f"  [COWRIE  ]   {line}")
            return False
    return wait_for_port(8081, timeout=90)


def cowrie_version(docker: str) -> str:
    try:
        out = subprocess.run([docker, "logs", COWRIE_CONTAINER],
                             capture_output=True, text=True, timeout=25)
        for line in (out.stdout + out.stderr).splitlines():
            if "Cowrie Version" in line:
                return line.split("Cowrie Version", 1)[1].strip()
    except Exception:
        pass
    return "unknown"


def lan_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.4) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def wait_for_port(port: int, timeout: float = 90.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if port_open(port):
            return True
        time.sleep(0.4)
    return False


def pump(tag: str, proc: subprocess.Popen, quiet: bool) -> None:
    """Prefix every child line with its component tag."""
    for raw in iter(proc.stdout.readline, ""):
        line = raw.rstrip()
        if not line:
            continue
        if quiet and tag == "PIPELINE" and "INFO" in line and "session" not in line:
            continue
        print(f"  [{tag:8s}] {line}", flush=True)


def preflight() -> List[str]:
    """Ports that are already taken and would break the launch."""
    busy = []
    for label, _argv, port in COMPONENTS:
        if port_open(port):
            busy.append(f"{port} ({label})")
    return busy


def firewall_rule_present() -> bool:
    if os.name != "nt":
        return True
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "if (Get-NetFirewallRule -DisplayName 'Adaptive Honeypot Gateway' "
             "-ErrorAction SilentlyContinue) { 'yes' } else { 'no' }"],
            capture_output=True, text=True, timeout=25)
        return "yes" in out.stdout.lower()
    except Exception:
        return False


def banner(ip: str, fw: bool, port: int = 5000, honeypot: str = "python") -> None:
    print()
    print("  " + "=" * 68)
    print("  LIVE TWO-LAPTOP DEMO IS UP")
    print("  " + "=" * 68)
    print()
    print(f"  HONEYPOT: {honeypot}")
    print()
    print("  YOUR DASHBOARD (keep this on screen):")
    print(f"      http://localhost:{port}/live")
    print()
    print("  WHAT YOUR FRIENDS TYPE ON THEIR LAPTOPS:")
    print(f"      ssh root@{ip} -p 8080")
    print("      (any password works -- the honeypot records it)")
    print()
    print("  TO MAKE ONE OF THEM LOOK MALICIOUS, they run a burst:")
    print(f"      for ($i=1; $i -le 40; $i++) {{ Test-NetConnection {ip} -Port 8080 "
          "-InformationLevel Quiet }")
    print("      ...or you click BLOCK next to their IP on the dashboard.")
    print()
    if not fw:
        print("  !! FIREWALL: no inbound rule found -- their connections WILL be dropped.")
        print("     Run this ONCE in an ADMIN PowerShell:")
        print('       New-NetFirewallRule -DisplayName "Adaptive Honeypot Gateway" '
              '-Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow')
        print()
    print("  Ctrl-C stops every component.")
    print("  " + "=" * 68 + "\n", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Launch the full two-laptop live demo")
    ap.add_argument("--port", type=int, default=5000, help="dashboard/API port")
    ap.add_argument("--no-pipeline", action="store_true",
                    help="skip the MT3 watcher + API (gateway routing only)")
    ap.add_argument("--zero-trust", action="store_true",
                    help="disable classifier routing: everything unknown goes to the honeypot")
    ap.add_argument("--quiet", action="store_true", help="suppress routine pipeline logs")
    ap.add_argument("--honeypot", choices=("auto", "cowrie", "python"), default="auto",
                    help="auto (default): real Cowrie in Docker when available, "
                         "else the built-in python emulator")
    args = ap.parse_args()

    # -- pick the honeypot --------------------------------------------------
    docker = docker_bin()
    use_cowrie = args.honeypot == "cowrie" or (
        args.honeypot == "auto" and docker_ready(docker))
    if args.honeypot == "cowrie" and not docker_ready(docker):
        print()
        print("  ERROR: --honeypot cowrie, but Docker is not reachable.")
        print("  Start Docker Desktop, or use --honeypot python.")
        print()
        return 1

    global COMPONENTS
    if use_cowrie:
        # Cowrie owns :8081; the python emulator must not also claim it.
        COMPONENTS = [c for c in COMPONENTS if c[0] != "HONEYPOT"]

    busy = preflight()
    if busy:
        print("\n  ERROR: these ports are already in use: " + ", ".join(busy))
        print("  Stop the old processes first, e.g.:")
        print("    Get-NetTCPConnection -LocalPort 8080,8081,8000,5000 -State Listen |"
              " Select-Object OwningProcess")
        print("    Stop-Process -Id <PID>\n")
        return 1

    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env["TRANSFORMERS_VERBOSITY"] = "error"
    if not args.zero_trust:
        env["GATEWAY_CLASSIFIER_ROUTING"] = "1"

    components = [c for c in COMPONENTS
                  if not (args.no_pipeline and c[0] == "PIPELINE")]

    procs: List[Tuple[str, subprocess.Popen]] = []
    print("\n  starting components ...\n", flush=True)
    try:
        if use_cowrie:
            if not cowrie_up(docker):
                print("\n  Cowrie did not come up on :8081."
                      " Retry, or run with --honeypot python.\n")
                return 1
            print(f"  [COWRIE  ] listening on :8081  (Cowrie {cowrie_version(docker)},"
                  f" real honeypot, container {COWRIE_CONTAINER})", flush=True)

        for label, argv, port in components:
            cmd = list(argv)
            if label == "PIPELINE":
                cmd += ["--port", str(args.port)]
            proc = subprocess.Popen(
                cmd, cwd=str(REPO_ROOT), env=env, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1,
                encoding="utf-8", errors="replace",
            )
            procs.append((label, proc))
            threading.Thread(target=pump, args=(label, proc, args.quiet),
                             daemon=True).start()

            want = args.port if label == "PIPELINE" else port
            if wait_for_port(want, timeout=120 if label == "PIPELINE" else 25):
                print(f"  [{label:8s}] listening on :{want}", flush=True)
            else:
                print(f"  [{label:8s}] WARNING: port {want} never opened", flush=True)
                if proc.poll() is not None:
                    print(f"  [{label:8s}] process exited with {proc.returncode}")
                    raise SystemExit(1)

        banner(lan_ip(), firewall_rule_present(), args.port,
               f"real Cowrie {cowrie_version(docker)} in Docker (adaptive honeyfs)"
               if use_cowrie else "built-in python emulator (demo/ssh_honeypot.py)")

        while True:
            for label, proc in procs:
                if proc.poll() is not None:
                    print(f"\n  [{label}] exited unexpectedly (code {proc.returncode})")
                    raise KeyboardInterrupt
            time.sleep(1.0)

    except KeyboardInterrupt:
        print("\n  stopping ...")
    finally:
        for label, proc in reversed(procs):
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=6)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
        print("  all components stopped.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
