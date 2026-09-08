"""
demo/ssh_honeypot.py

Fake SSH server (the honeypot). Accepts any password, serves a convincing fake
shell, and records every credential and command as Cowrie-format JSON events --
so the existing post_session_pipeline picks the session up and MT3 classifies it
with no changes. Listens on 127.0.0.1:8081, matching CONFIG.HONEYPOT_TARGETS.
"""
from __future__ import annotations

import argparse
import json
import logging
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import paramiko

REPO_ROOT = Path(__file__).resolve().parent.parent
COWRIE_LOG_DIR = REPO_ROOT / "honeypot_dataset" / "cowrie" / "logs"
HOST_KEY_PATH = REPO_ROOT / "demo" / "honeypot_host_key"
ACTIVE_CONFIG = REPO_ROOT / "adaptive_honeypot" / "active_config.json"

log = logging.getLogger("ssh_honeypot")

BANNER = "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"   # matches cowrie.cfg
HOSTNAME = "svr04"

# ── Fake filesystem, scaled by the configurator's interaction level ──────────
# The configurator writes active_config.json; the honeypot reads it per session,
# so an escalation decided by MT3 on the last session actually changes what the
# next attacker sees. That is the "adaptive" loop, closed.
FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:106:110:MySQL Server,,,:/nonexistent:/bin/false
deploy:x:1000:1000:deploy,,,:/home/deploy:/bin/bash"""

FAKE_SHADOW = """root:$6$xyzsalt$3xAmPl3H4sHV4lu3Notreal00000000000000000000:19000:0:99999:7:::
deploy:$6$abcsalt$9zQwErTyU1oPa5SdFgHjKl00000000000000000000:19000:0:99999:7:::"""

FAKE_SSH_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxFAKEKEYFORHONEYPOTDEMOONLYNOTAREALKEY0000000000000
NOTAVALIDKEYTHISISAHONEYPOTCANARYTOKENFORCAPSTONEDEMONSTRATION0000000
-----END OPENSSH PRIVATE KEY-----"""

FAKE_ENV = """DB_HOST=10.0.4.22
DB_USER=deploy
DB_PASS=Pr0d_D3ploy_2024!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"""


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_interaction_level() -> str:
    """Read the level MT3 + the configurator last decided on."""
    try:
        with ACTIVE_CONFIG.open(encoding="utf-8") as fh:
            return str(json.load(fh).get("interaction_level", "low"))
    except Exception:
        return "low"


class CowrieWriter:
    """Appends Cowrie-format JSON events, one per line."""

    def __init__(self, log_dir: Path = COWRIE_LOG_DIR) -> None:
        self.path = Path(log_dir) / "cowrie.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def emit(self, eventid: str, session: str, src_ip: str, **fields) -> None:
        record = {
            "eventid": eventid,
            "session": session,
            "src_ip": src_ip,
            "timestamp": _utcnow_iso(),
            "sensor": HOSTNAME,
            **fields,
        }
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
                fh.flush()


class _Server(paramiko.ServerInterface):
    """Accepts every password and records the attempts."""

    def __init__(self, session: str, src_ip: str, writer: CowrieWriter,
                 accept_after: int = 1) -> None:
        self.session = session
        self.src_ip = src_ip
        self.writer = writer
        self.accept_after = accept_after   # fail this many times, then let them in
        self.attempts = 0
        self.credentials: List[Dict[str, str]] = []
        self.event = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        self.attempts += 1
        self.credentials.append({"username": username, "password": password})
        # Let them in eventually -- a honeypot that never opens collects nothing.
        success = self.attempts >= self.accept_after
        self.writer.emit(
            "cowrie.login.success" if success else "cowrie.login.failed",
            self.session, self.src_ip, username=username, password=password,
        )
        log.info("  auth %-8s %s:%s", "OK" if success else "FAIL", username, password)
        return paramiko.AUTH_SUCCESSFUL if success else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key) -> int:
        # Force password auth so we capture credentials.
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
        """Non-interactive: `ssh host "id; uname -a"`."""
        self.exec_command = command.decode("utf-8", "replace")
        self.event.set()
        return True


def fake_response(cmd: str, level: str, cwd: str = "/root") -> str:
    """Plausible output for a command, richer at higher interaction levels."""
    c = cmd.strip()
    low = c.lower()

    def rich(text: str, minimum: str = "low") -> str:
        order = {"low": 0, "medium": 1, "high": 2, "maximum": 3}
        return text if order[level] >= order[minimum] else "Permission denied"

    if low in ("", ":"):
        return ""
    if low.startswith("uname"):
        return "Linux svr04 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 x86_64 GNU/Linux"
    if low in ("id", "whoami") or low.startswith("id "):
        return "uid=0(root) gid=0(root) groups=0(root)" if low != "whoami" else "root"
    if low.startswith("hostname"):
        return HOSTNAME
    if low.startswith("pwd"):
        return cwd
    if low.startswith("arch"):
        return "x86_64"
    if "os-release" in low or "lsb_release" in low or "/etc/issue" in low:
        return ('PRETTY_NAME="Debian GNU/Linux 10 (buster)"\nNAME="Debian GNU/Linux"\n'
                'VERSION_ID="10"\nVERSION="10 (buster)"\nID=debian')
    if "/proc/cpuinfo" in low:
        return ("processor\t: 0\nvendor_id\t: GenuineIntel\n"
                "model name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\ncpu MHz\t\t: 2400.070")
    if low.startswith("ls"):
        base = "backup.tar.gz  deploy.sh  logs  www"
        return base + ("  .ssh  .env  credentials.txt" if level in ("high", "maximum") else "")
    if "/etc/passwd" in low:
        return FAKE_PASSWD
    if "/etc/shadow" in low:
        return rich(FAKE_SHADOW, "high")
    if "authorized_keys" in low or "id_rsa" in low or ".ssh" in low:
        return rich(FAKE_SSH_KEY, "high")
    if ".env" in low or "credentials" in low:
        return rich(FAKE_ENV, "high")
    if low.startswith("netstat") or low.startswith("ss "):
        return ("Active Internet connections (only servers)\n"
                "tcp   0  0 0.0.0.0:22      0.0.0.0:*   LISTEN  812/sshd\n"
                "tcp   0  0 127.0.0.1:3306  0.0.0.0:*   LISTEN  1104/mysqld\n"
                "tcp   0  0 10.0.4.11:8080  0.0.0.0:*   LISTEN  2291/java")
    if low.startswith("ps"):
        return ("  PID TTY          TIME CMD\n  812 ?        00:00:01 sshd\n"
                " 1104 ?        00:04:22 mysqld\n 2291 ?        00:31:08 java\n"
                " 3310 pts/0    00:00:00 bash")
    if low.startswith("ifconfig") or low.startswith("ip addr") or low.startswith("ip a"):
        return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 10.0.4.11  netmask 255.255.255.0  broadcast 10.0.4.255")
    if low.startswith("w") or low.startswith("who"):
        return " 09:14:22 up 87 days,  4:11,  1 user,  load average: 0.08, 0.03, 0.01"
    if low.startswith("df"):
        return ("Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/xvda1       32G   11G   20G  36% /")
    if low.startswith("free"):
        return ("              total        used        free\n"
                "Mem:        8167848     2214512     3901120")
    if low.startswith("sudo"):
        return rich("root is not in the sudoers file.  This incident will be reported.", "medium") \
            if level in ("low",) else "Matching Defaults entries for root on svr04:\n    env_reset\n\nUser root may run the following commands:\n    (ALL : ALL) ALL"
    if low.startswith("find"):
        return rich("/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/chsh\n/bin/mount", "medium")
    if low.startswith("crontab"):
        return "no crontab for root" if "-l" in low else ""
    if low.startswith("wget") or low.startswith("curl"):
        return rich("--2024-03-18 09:15:02--  connecting... 200 OK\nSaved (12,884 bytes)", "medium")
    if low.startswith("cat"):
        return "cat: No such file or directory"
    if low.startswith("cd"):
        return ""
    if low.startswith("rm") or low.startswith("history"):
        return ""
    if low.startswith("exit") or low.startswith("logout"):
        return None    # sentinel: close the session
    return f"-bash: {c.split()[0] if c.split() else c}: command not found"


def handle_client(client: socket.socket, addr, host_key, writer: CowrieWriter,
                  accept_after: int) -> None:
    src_ip, src_port = addr[0], addr[1]
    session = uuid.uuid4().hex[:12]
    level = _load_interaction_level()
    delay_ms = {"low": 1200, "medium": 400, "high": 120, "maximum": 80}[level]

    log.info("connect %s:%s  session=%s  interaction=%s", src_ip, src_port, session, level)
    writer.emit("cowrie.session.connect", session, src_ip,
                src_port=src_port, dst_port=8081, protocol="ssh")

    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.local_version = BANNER
        transport.add_server_key(host_key)
        server = _Server(session, src_ip, writer, accept_after=accept_after)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as exc:
            log.debug("  ssh negotiation failed: %s", exc)
            return

        writer.emit("cowrie.client.version", session, src_ip,
                    version=str(transport.remote_version))

        chan = transport.accept(20)
        if chan is None:
            log.info("  no channel opened")
            return
        server.event.wait(10)

        # Non-interactive `ssh host "cmd"`
        exec_cmd = getattr(server, "exec_command", None)
        if exec_cmd:
            for part in [p.strip() for p in exec_cmd.split(";") if p.strip()]:
                writer.emit("cowrie.command.input", session, src_ip, input=part)
                log.info("  exec: %s", part)
                out = fake_response(part, level)
                if out:
                    chan.send(out.replace("\n", "\r\n") + "\r\n")
            chan.send_exit_status(0)
            return

        # Interactive shell
        chan.send("\r\nLinux svr04 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 x86_64\r\n\r\n"
                  "The programs included with the Debian GNU/Linux system are free software;\r\n"
                  "the exact distribution terms for each program are described in the\r\n"
                  "individual files in /usr/share/doc/*/copyright.\r\n\r\n"
                  f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from 10.0.4.7\r\n")
        prompt = f"root@{HOSTNAME}:~# "
        chan.send(prompt)

        buf = ""
        while True:
            try:
                data = chan.recv(1024)
            except Exception:
                break
            if not data:
                break
            text = data.decode("utf-8", "replace")
            for ch in text:
                if ch in ("\r", "\n"):
                    chan.send("\r\n")
                    cmd = buf.strip()
                    buf = ""
                    if cmd:
                        writer.emit("cowrie.command.input", session, src_ip, input=cmd)
                        log.info("  cmd: %s", cmd)
                        time.sleep(delay_ms / 1000.0)   # the configured stall
                        out = fake_response(cmd, level)
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
                elif ch == "\x03":          # Ctrl-C
                    chan.send("^C\r\n" + prompt)
                    buf = ""
                elif ch == "\x04":          # Ctrl-D
                    chan.send("logout\r\n")
                    return
                else:
                    buf += ch
                    chan.send(ch)           # echo
    except Exception as exc:
        log.warning("  session error: %s", exc)
    finally:
        writer.emit("cowrie.session.closed", session, src_ip)
        log.info("closed  %s  session=%s", src_ip, session)
        try:
            if transport:
                transport.close()
            client.close()
        except Exception:
            pass


def load_host_key(path: Path = HOST_KEY_PATH) -> paramiko.RSAKey:
    """Persist one host key so repeat connections don't warn about a key change."""
    if path.exists():
        return paramiko.RSAKey(filename=str(path))
    key = paramiko.RSAKey.generate(2048)
    path.parent.mkdir(parents=True, exist_ok=True)
    key.write_private_key_file(str(path))
    return key


def main() -> int:
    ap = argparse.ArgumentParser(description="SSH honeypot (the FAKE server)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1: reachable only via the gateway)")
    ap.add_argument("--port", type=int, default=8081,
                    help="default 8081 = CONFIG.HONEYPOT_TARGETS")
    ap.add_argument("--log-dir", default=str(COWRIE_LOG_DIR))
    ap.add_argument("--accept-after", type=int, default=1,
                    help="number of auth attempts before login succeeds")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [HONEYPOT] %(message)s",
                        datefmt="%H:%M:%S")
    # paramiko logs a full traceback whenever a peer opens and drops a
    # socket without speaking SSH -- which every port probe and every
    # port scanner does. Silence it; we log the outcome ourselves.
    for _n in ("paramiko", "paramiko.transport", "paramiko.transport.sftp"):
        logging.getLogger(_n).setLevel(logging.CRITICAL)

    writer = CowrieWriter(Path(args.log_dir))
    host_key = load_host_key()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(64)

    print()
    print("  " + "=" * 60)
    print("  FAKE SERVER (SSH HONEYPOT)")
    print(f"    listening   {args.host}:{args.port}")
    print(f"    banner      {BANNER}")
    print(f"    cowrie log  {writer.path}")
    print(f"    interaction {_load_interaction_level()} (re-read per session)")
    print("    every credential and command is recorded for MT3")
    print("  " + "=" * 60 + "\n", flush=True)

    try:
        while True:
            client, addr = sock.accept()
            threading.Thread(target=handle_client,
                             args=(client, addr, host_key, writer, args.accept_after),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\n  honeypot stopped.")
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
