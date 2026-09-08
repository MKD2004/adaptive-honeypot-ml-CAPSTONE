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

COMPONENTS = [
    # (label, colour-ish tag, argv, the port it must end up listening on)
    ("REAL",     [PY, "demo/real_server.py"],                              8000),
    ("HONEYPOT", [PY, "demo/ssh_honeypot.py"],                             8081),
    ("GATEWAY",  [PY, "-m", "traffic_gateway.inspection_gateway"],         8080),
    ("PIPELINE", [PY, "-m", "traffic_gateway.run_pipeline", "--poll", "3"], 5000),
]


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


def banner(ip: str, fw: bool, port: int = 5000) -> None:
    print()
    print("  " + "=" * 68)
    print("  LIVE TWO-LAPTOP DEMO IS UP")
    print("  " + "=" * 68)
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
    args = ap.parse_args()

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

        banner(lan_ip(), firewall_rule_present(), args.port)

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
