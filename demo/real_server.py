"""
demo/real_server.py

The REAL server -- the production service the gateway protects. Only IPs the
gateway trusts (whitelisted) are ever proxied here. Unlike the honeypot it
enforces real credentials, refuses unknown users, and writes an ordinary access
log rather than attacker forensics. Listens on 127.0.0.1:8000 (CONFIG.REAL_BACKEND).
"""
from __future__ import annotations

import argparse
import json
import logging
import socket
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import paramiko

REPO_ROOT = Path(__file__).resolve().parent.parent
ACCESS_LOG = REPO_ROOT / "logs" / "real_server_access.jsonl"
HOST_KEY_PATH = REPO_ROOT / "demo" / "real_server_host_key"

log = logging.getLogger("real_server")

BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
HOSTNAME = "prod-svr01"

# The real service has real credentials. Anyone without them is refused --
# that is the difference the panel should see: the honeypot lets everyone in.
VALID_USERS: Dict[str, str] = {
    "deploy": "deploy123",
    "admin": "admin123",
}

MOTD = f"""
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com

  System load:  0.04              Processes:             142
  Usage of /:   36.2% of 31.8GB   Users logged in:       1
  Memory usage: 27%               IPv4 address for eth0: 10.0.4.11

  ** THIS IS THE REAL PRODUCTION SERVER **
  You reached it because the traffic gateway classified your IP as BENIGN
  and routed you to the real backend instead of the honeypot.

"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class AccessLog:
    def __init__(self, path: Path = ACCESS_LOG) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, **fields) -> None:
        rec = {"ts": _utcnow(), "server": "real", "hostname": HOSTNAME, **fields}
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
                fh.flush()


class _Server(paramiko.ServerInterface):
    """Real credential check -- wrong password is refused, unlike the honeypot."""

    def __init__(self, session: str, src_ip: str, access: AccessLog) -> None:
        self.session = session
        self.src_ip = src_ip
        self.access = access
        self.username: Optional[str] = None
        self.authenticated = False
        self.event = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return (paramiko.OPEN_SUCCEEDED if kind == "session"
                else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def check_auth_password(self, username: str, password: str) -> int:
        ok = VALID_USERS.get(username) == password
        self.access.write(event="auth", session=self.session, src_ip=self.src_ip,
                          username=username, result="success" if ok else "failure")
        log.info("  auth %-7s %s", "OK" if ok else "REFUSED", username)
        if ok:
            self.username = username
            self.authenticated = True
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        self.exec_command = command.decode("utf-8", "replace")
        self.event.set()
        return True


def real_response(cmd: str, user: str) -> Optional[str]:
    """A small, honest command set -- this is a real service, not a trap."""
    c = cmd.strip()
    low = c.lower()
    if not low:
        return ""
    if low in ("exit", "logout"):
        return None
    if low == "whoami":
        return user
    if low.startswith("hostname"):
        return HOSTNAME
    if low.startswith("uname"):
        return "Linux prod-svr01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
    if low == "id":
        return f"uid=1000({user}) gid=1000({user}) groups=1000({user}),27(sudo)"
    if low.startswith("pwd"):
        return f"/home/{user}"
    if low.startswith("ls"):
        return "app  deploy.log  releases"
    if low.startswith("uptime") or low.startswith("w"):
        return " 09:14:22 up 87 days,  4:11,  1 user,  load average: 0.04, 0.03, 0.01"
    if low.startswith("df"):
        return ("Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/root        32G   11G   20G  36% /")
    if low.startswith("cat") or low.startswith("sudo"):
        return f"{c.split()[0]}: permission denied (this is the real server -- audited)"
    return f"-bash: {c.split()[0]}: command not found"


def handle_client(client: socket.socket, addr, host_key, access: AccessLog) -> None:
    src_ip, src_port = addr[0], addr[1]
    session = uuid.uuid4().hex[:12]
    log.info("connect %s:%s  session=%s", src_ip, src_port, session)
    access.write(event="connect", session=session, src_ip=src_ip, src_port=src_port)

    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.local_version = BANNER
        transport.add_server_key(host_key)
        server = _Server(session, src_ip, access)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as exc:
            log.debug("  negotiation failed: %s", exc)
            return

        chan = transport.accept(20)
        if chan is None:
            return
        server.event.wait(10)
        if not server.authenticated:
            return

        user = server.username or "deploy"

        exec_cmd = getattr(server, "exec_command", None)
        if exec_cmd:
            access.write(event="command", session=session, src_ip=src_ip,
                         username=user, command=exec_cmd)
            out = real_response(exec_cmd, user)
            if out:
                chan.send(out.replace("\n", "\r\n") + "\r\n")
            chan.send_exit_status(0)
            return

        chan.send(MOTD.replace("\n", "\r\n"))
        prompt = f"{user}@{HOSTNAME}:~$ "
        chan.send(prompt)

        buf = ""
        while True:
            try:
                data = chan.recv(1024)
            except Exception:
                break
            if not data:
                break
            for ch in data.decode("utf-8", "replace"):
                if ch in ("\r", "\n"):
                    chan.send("\r\n")
                    cmd, buf = buf.strip(), ""
                    if cmd:
                        access.write(event="command", session=session, src_ip=src_ip,
                                     username=user, command=cmd)
                        log.info("  cmd: %s", cmd)
                        out = real_response(cmd, user)
                        if out is None:
                            chan.send("logout\r\n")
                            return
                        if out:
                            chan.send(out.replace("\n", "\r\n") + "\r\n")
                    chan.send(prompt)
                elif ch in ("\x7f", "\b"):
                    if buf:
                        buf = buf[:-1]
                        chan.send("\b \b")
                elif ch == "\x04":
                    chan.send("logout\r\n")
                    return
                else:
                    buf += ch
                    chan.send(ch)
    except Exception as exc:
        log.warning("  session error: %s", exc)
    finally:
        access.write(event="close", session=session, src_ip=src_ip)
        log.info("closed  %s  session=%s", src_ip, session)
        try:
            if transport:
                transport.close()
            client.close()
        except Exception:
            pass


def load_host_key(path: Path = HOST_KEY_PATH) -> paramiko.RSAKey:
    if path.exists():
        return paramiko.RSAKey(filename=str(path))
    key = paramiko.RSAKey.generate(2048)
    path.parent.mkdir(parents=True, exist_ok=True)
    key.write_private_key_file(str(path))
    return key


def main() -> int:
    ap = argparse.ArgumentParser(description="The REAL production server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000,
                    help="default 8000 = CONFIG.REAL_BACKEND")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [REAL] %(message)s",
                        datefmt="%H:%M:%S")
    # paramiko logs a full traceback whenever a peer opens and drops a
    # socket without speaking SSH -- which every port probe and every
    # port scanner does. Silence it; we log the outcome ourselves.
    for _n in ("paramiko", "paramiko.transport", "paramiko.transport.sftp"):
        logging.getLogger(_n).setLevel(logging.CRITICAL)

    access = AccessLog()
    host_key = load_host_key()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(32)

    print()
    print("  " + "=" * 60)
    print("  REAL SERVER (production backend)")
    print(f"    listening  {args.host}:{args.port}")
    print(f"    hostname   {HOSTNAME}")
    print(f"    valid creds: {', '.join(f'{u}/{p}' for u, p in VALID_USERS.items())}")
    print(f"    access log {access.path}")
    print("    only WHITELISTED / BENIGN ips are routed here by the gateway")
    print("  " + "=" * 60 + "\n", flush=True)

    try:
        while True:
            client, addr = sock.accept()
            threading.Thread(target=handle_client, args=(client, addr, host_key, access),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\n  real server stopped.")
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
