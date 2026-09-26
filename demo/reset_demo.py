"""
demo/reset_demo.py

Puts the demo back to a clean slate for a fresh recording: stops any running
stack, clears the dashboard feed, blacklist/whitelist, honeypot config and
captured Cowrie sessions, and (if Docker is up) restarts Cowrie so it reopens
its log file. Run this, then start live_demo.py.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COWRIE_DIR = REPO_ROOT / "honeypot_dataset" / "cowrie"

# cowrie.json is handled separately: it must be deleted while the container is
# DOWN, or Cowrie keeps writing to the stale handle and the fresh file stays
# empty (the login events never appear). See restart_cowrie().
CLEAR_FILES = [
    REPO_ROOT / "logs" / "pipeline_results.jsonl",
    REPO_ROOT / "logs" / "honeypot_config_changes.jsonl",
    REPO_ROOT / "logs" / "real_server_access.jsonl",
    REPO_ROOT / "traffic_gateway" / "data" / "blacklist.json",
    REPO_ROOT / "traffic_gateway" / "data" / "whitelist.json",
    REPO_ROOT / "traffic_gateway" / "data" / "ip_records.json",
    REPO_ROOT / "traffic_gateway" / "data" / "sessions.jsonl",
]
COWRIE_LOG = COWRIE_DIR / "logs" / "cowrie.json"


def _docker() -> str | None:
    found = shutil.which("docker")
    if found:
        return found
    for c in (Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"),
              Path.home() / r"AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe"):
        if c.exists():
            return str(c)
    return None


def stop_stack() -> None:
    """Kill any running gateway/pipeline/server python processes."""
    print("  stopping any running demo processes ...")
    if os.name == "nt":
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process -Filter \"Name like 'python%'\" | "
             "Where-Object { $_.CommandLine -match "
             "'live_demo|run_pipeline|inspection_gateway|real_server|ssh_honeypot|traffic_gateway.api' } | "
             "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"],
            capture_output=True, timeout=40)
    else:
        subprocess.run(["pkill", "-f", "live_demo|run_pipeline|inspection_gateway"],
                       capture_output=True)
    time.sleep(3)


def clear_state() -> None:
    print("  clearing dashboard feed, blacklist/whitelist, honeypot config ...")
    for f in CLEAR_FILES:
        try:
            f.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            print(f"    (could not remove {f.name}: {exc})")
    # reset the honeypot posture + honeyfs to low
    sys.path.insert(0, str(REPO_ROOT))
    try:
        from adaptive_honeypot.configurator import configurator
        c = configurator.reset()
        print(f"    honeypot reset -> {c['interaction_level']} interaction")
    except Exception as exc:
        print(f"    (configurator reset skipped: {exc})")


def restart_cowrie() -> None:
    docker = _docker()
    if not docker:
        print("  Docker not found -- skipping Cowrie (live_demo will use the python emulator)")
        return
    try:
        up = subprocess.run([docker, "info", "--format", "{{.ServerVersion}}"],
                            capture_output=True, timeout=25)
        if up.returncode != 0:
            print("  Docker installed but not running -- start Docker Desktop, or "
                  "live_demo falls back to the python emulator")
            return
    except Exception:
        print("  Docker not reachable -- skipping Cowrie")
        return
    # down -> delete the log -> up. Deleting while the container is DOWN is what
    # forces Cowrie to reopen a genuinely fresh cowrie.json; deleting it while
    # the container holds it open leaves Cowrie writing to a stale handle and the
    # mounted file stays empty, so no captured session ever reaches the pipeline.
    print("  restarting Cowrie on a fresh log (down -> clear -> up) ...")
    subprocess.run([docker, "compose", "down"], cwd=str(COWRIE_DIR),
                   capture_output=True, timeout=180)
    try:
        COWRIE_LOG.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"    (could not remove cowrie.json: {exc})")
    subprocess.run([docker, "compose", "up", "-d"], cwd=str(COWRIE_DIR),
                   capture_output=True, timeout=180)
    time.sleep(7)
    ps = subprocess.run([docker, "ps", "--filter", "name=cowrie-honeypot",
                         "--format", "{{.Status}}"],
                        capture_output=True, text=True, timeout=25)
    print(f"    cowrie: {ps.stdout.strip() or 'not running'}")


def main() -> int:
    print("\n  " + "=" * 56)
    print("  RESET DEMO TO A CLEAN STATE")
    print("  " + "=" * 56)
    stop_stack()
    clear_state()
    restart_cowrie()
    print("  " + "-" * 56)
    print("  clean. now run:")
    print("     .\\honeypot_dataset\\venv\\Scripts\\python.exe demo\\live_demo.py")
    print("  " + "=" * 56 + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
