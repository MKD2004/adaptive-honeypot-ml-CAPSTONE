"""
demo/brute_force.py

Simulates an SSH brute-force from this laptop against the gateway: opens many
short connections, each trying several passwords, so the honeypot records
multiple failed logins per session (MT3 -> ACCESS_BRUTE_SSH). The connection
volume also trips the gateway's rate limiter partway through, so the same run
shows capture + classification AND the rate-limit block.
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

# The exact passwords Cowrie's userdb denies. Every one is a recorded
# cowrie.login.failed, and the session never opens a shell -- so it reads as a
# pure brute force (many login attempts, no commands), which MT3 classifies as
# ACCESS_BRUTE_SSH with strong confidence.
PASSWORDS = [
    "123456", "password", "admin", "12345", "qwerty",
    "letmein", "1234", "root123", "toor", "P@ssw0rd",
    "admin123", "root@123", "welcome", "changeme", "passw0rd",
    "administrator", "superman", "master", "qwerty123", "abc123",
]


def one_session(host: str, port: int, user: str, attempts: int,
                idx: int, verbose: bool) -> bool:
    """One SSH connection that tries several passwords. Returns True if it
    reached the honeypot at all (i.e. was not rejected by the rate limiter)."""
    transport = None
    try:
        sock = socket.create_connection((host, port), timeout=6)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=8)
    except Exception as exc:
        # Rate-limited connections are refused before the SSH banner.
        if verbose:
            print(f"  [{idx:02d}] REJECTED by gateway ({type(exc).__name__}) "
                  f"-- rate limiter is now blocking this IP")
        if transport:
            transport.close()
        return False

    tried = 0
    for pw in PASSWORDS[:attempts]:
        tried += 1
        try:
            transport.auth_password(user, pw)
        except paramiko.AuthenticationException:
            continue          # denied -> a recorded failed login, keep spraying
        except Exception:
            break
        else:
            break             # accepted -> shell handed over
    if verbose:
        print(f"  [{idx:02d}] connected, sprayed {tried} passwords as {user!r}")
    transport.close()
    return True


def flood(host: str, port: int, count: int, verbose: bool) -> int:
    """Rapid bare-TCP connections to trip the sliding-window rate limiter.

    A password-spray session takes a second or two (many auth round-trips), so
    on its own it spreads past the 60s window and never accumulates the 20
    connections that trip the limiter. This fires quick connect/close cycles so
    the window fills fast -- that is what produces the RATE_LIMITED / blocked
    events for the demo.
    """
    rejected = 0
    for i in range(count):
        try:
            s = socket.create_connection((host, port), timeout=3)
            s.close()
        except Exception:
            rejected += 1
        time.sleep(0.05)
    if verbose:
        print(f"  flood: {count} rapid connections sent, {rejected} refused outright")
    return rejected


def main() -> int:
    ap = argparse.ArgumentParser(description="SSH brute-force simulation through the gateway")
    ap.add_argument("host", nargs="?", default="127.0.0.1",
                    help="gateway IP (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--user", default="root")
    ap.add_argument("--connections", type=int, default=6,
                    help="brute-force sessions to capture (each sprays the full "
                         "password list)")
    ap.add_argument("--attempts", type=int, default=20,
                    help="password guesses per connection (all fail -> a clean "
                         "brute-force session)")
    ap.add_argument("--preburst", type=int, default=12,
                    help="rapid connections BEFORE the spray, to raise the "
                         "behaviour signal so the spray reaches the honeypot "
                         "(0 to skip)")
    ap.add_argument("--flood", type=int, default=15,
                    help="rapid follow-up connections to trip the rate limiter "
                         "(0 to skip)")
    ap.add_argument("--delay", type=float, default=0.3,
                    help="seconds between brute-force sessions")
    args = ap.parse_args()

    print("\n  " + "=" * 60)
    print(f"  SSH BRUTE FORCE  ->  {args.host}:{args.port}   (user={args.user!r})")
    print("  " + "=" * 60)

    # Phase 0. A brand-new IP's first connection scores BENIGN (no history, no
    # signals), so the gateway would route it to the REAL server -- and the
    # password spray would never reach the honeypot. A quick pre-burst raises
    # this IP's connections-per-minute past the classifier's threshold, so it is
    # judged SUSPICIOUS and the spray sessions that follow are proxied to the
    # honeypot, where they are captured.
    if args.preburst:
        print(f"  phase 0: {args.preburst} rapid connections "
              f"(raise the behaviour signal -> SUSPICIOUS)")
        flood(args.host, args.port, args.preburst, verbose=True)

    print(f"  phase 1: {args.connections} sessions x {args.attempts} passwords "
          f"(captured by the honeypot + classified by MT3)")
    landed = 0
    for i in range(1, args.connections + 1):
        landed += one_session(args.host, args.port, args.user, args.attempts, i, verbose=True)
        time.sleep(args.delay)

    if args.flood:
        print(f"  phase 2: {args.flood} rapid connections (trip the rate limiter)")
        flood(args.host, args.port, args.flood, verbose=True)

    print("  " + "-" * 60)
    print(f"  {landed} brute-force sessions reached the honeypot.")
    print("  -> watch the dashboard: sessions classified ACCESS_BRUTE_SSH by MT3,")
    print("     the IP auto-blacklisted, and the rate limiter kicking in.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
