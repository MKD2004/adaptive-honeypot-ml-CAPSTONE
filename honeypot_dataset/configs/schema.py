"""
configs/schema.py  —  Central schema for HoneySynth-1M dataset
Defines 45 MITRE-mapped micro-states, 128-feature layout, kill-chain DAG.
"""
from __future__ import annotations
from typing import Dict, List, Set

# ─── 45 Micro-States ─────────────────────────────────────────────────────────
MICRO_STATES: List[Dict] = [
    # Phase 0: Reconnaissance (6)
    {"id": 0,  "label": "RECON_DNS",            "mitre": "T1590.002", "phase": 0},
    {"id": 1,  "label": "RECON_IP_SCAN",         "mitre": "T1046",     "phase": 0},
    {"id": 2,  "label": "RECON_VERSION_PROBE",   "mitre": "T1590.001", "phase": 0},
    {"id": 3,  "label": "RECON_OS_DETECT",       "mitre": "T1082",     "phase": 0},
    {"id": 4,  "label": "RECON_VULN_SCAN",       "mitre": "T1595.002", "phase": 0},
    {"id": 5,  "label": "RECON_USER_ENUM",       "mitre": "T1589.003", "phase": 0},
    # Phase 1: Initial Access (6)
    {"id": 6,  "label": "ACCESS_BRUTE_SSH",      "mitre": "T1110.001", "phase": 1},
    {"id": 7,  "label": "ACCESS_BRUTE_HTTP",     "mitre": "T1110.001", "phase": 1},
    {"id": 8,  "label": "ACCESS_CRED_STUFF",     "mitre": "T1110.004", "phase": 1},
    {"id": 9,  "label": "ACCESS_DEFAULT_CRED",   "mitre": "T1078.001", "phase": 1},
    {"id": 10, "label": "ACCESS_KEX_EXPLOIT",    "mitre": "T1190",     "phase": 1},
    {"id": 11, "label": "ACCESS_AUTH_BYPASS",    "mitre": "T1548",     "phase": 1},
    # Phase 2: Execution (6)
    {"id": 12, "label": "EXEC_SHELL_OPEN",       "mitre": "T1059.004", "phase": 2},
    {"id": 13, "label": "EXEC_PYTHON_SCRIPT",    "mitre": "T1059.006", "phase": 2},
    {"id": 14, "label": "EXEC_PERL_SCRIPT",      "mitre": "T1059",     "phase": 2},
    {"id": 15, "label": "EXEC_CURL_BASH",        "mitre": "T1059.004", "phase": 2},
    {"id": 16, "label": "EXEC_WGET_EXEC",        "mitre": "T1105",     "phase": 2},
    {"id": 17, "label": "EXEC_MEMFD_EXEC",       "mitre": "T1620",     "phase": 2},
    # Phase 3: Discovery (5)
    {"id": 18, "label": "DISC_ENV_PROBE",        "mitre": "T1082",     "phase": 3},
    {"id": 19, "label": "DISC_NETSTAT_SCAN",     "mitre": "T1049",     "phase": 3},
    {"id": 20, "label": "DISC_PROC_ENUM",        "mitre": "T1057",     "phase": 3},
    {"id": 21, "label": "DISC_SUID_HUNT",        "mitre": "T1548.001", "phase": 3},
    {"id": 22, "label": "DISC_CVE_SEARCH",       "mitre": "T1595",     "phase": 3},
    # Phase 4: Privilege Escalation (4)
    {"id": 23, "label": "PRIVESC_SUDO_ABUSE",    "mitre": "T1548.003", "phase": 4},
    {"id": 24, "label": "PRIVESC_SUID_EXPLOIT",  "mitre": "T1548.001", "phase": 4},
    {"id": 25, "label": "PRIVESC_KERNEL_XPLOIT", "mitre": "T1068",     "phase": 4},
    {"id": 26, "label": "PRIVESC_CONTAINER_ESC", "mitre": "T1611",     "phase": 4},
    # Phase 5: Persistence (5)
    {"id": 27, "label": "PERSIST_CRONTAB",       "mitre": "T1053.003", "phase": 5},
    {"id": 28, "label": "PERSIST_BASHRC",        "mitre": "T1546.004", "phase": 5},
    {"id": 29, "label": "PERSIST_SSH_KEY_ADD",   "mitre": "T1098.004", "phase": 5},
    {"id": 30, "label": "PERSIST_BACKDOOR_ADD",  "mitre": "T1505",     "phase": 5},
    {"id": 31, "label": "PERSIST_SYSTEMD_SVC",   "mitre": "T1543.002", "phase": 5},
    # Phase 6: Defense Evasion (5)
    {"id": 32, "label": "EVASION_LOG_WIPE",      "mitre": "T1070.002", "phase": 6},
    {"id": 33, "label": "EVASION_HIST_ERASE",    "mitre": "T1070.003", "phase": 6},
    {"id": 34, "label": "EVASION_CHMOD_HIDE",    "mitre": "T1564",     "phase": 6},
    {"id": 35, "label": "EVASION_CURL_OBFUS",    "mitre": "T1027",     "phase": 6},
    {"id": 36, "label": "EVASION_PROC_INJECT",   "mitre": "T1055",     "phase": 6},
    # Phase 7: Lateral Movement (3)
    {"id": 37, "label": "LATERAL_SSH_SPREAD",    "mitre": "T1021.004", "phase": 7},
    {"id": 38, "label": "LATERAL_SCAN_PIVOT",    "mitre": "T1046",     "phase": 7},
    {"id": 39, "label": "LATERAL_CRED_REUSE",    "mitre": "T1078",     "phase": 7},
    # Phase 8: Exfiltration (5)
    {"id": 40, "label": "EXFIL_SCP_DATA",        "mitre": "T1048.002", "phase": 8},
    {"id": 41, "label": "EXFIL_CURL_C2",         "mitre": "T1071.001", "phase": 8},
    {"id": 42, "label": "EXFIL_DNS_TUNNEL",      "mitre": "T1048.001", "phase": 8},
    {"id": 43, "label": "EXFIL_STAGING_TAR",     "mitre": "T1074.001", "phase": 8},
    {"id": 44, "label": "EXFIL_TUNNEL_NGROK",    "mitre": "T1572",     "phase": 8},
]

LABEL_TO_IDX: Dict[str, int]  = {s["label"]: s["id"]    for s in MICRO_STATES}
IDX_TO_LABEL: Dict[int, str]  = {s["id"]:    s["label"] for s in MICRO_STATES}
IDX_TO_PHASE: Dict[int, int]  = {s["id"]:    s["phase"] for s in MICRO_STATES}
LABEL_TO_MITRE: Dict[str,str] = {s["label"]: s["mitre"] for s in MICRO_STATES}
N_CLASSES = 45
N_PHASES  = 9

# ─── 128-Feature Layout ──────────────────────────────────────────────────────
FEATURE_GROUPS: Dict[str, Dict] = {
    "A_temporal":     {"start":  0, "end":  24, "size": 24, "arch": "LSTM"},
    "B_network":      {"start": 24, "end":  52, "size": 28, "arch": "CNN"},
    "C_payload":      {"start": 52, "end":  76, "size": 24, "arch": "CNN"},
    "D_semantic":     {"start": 76, "end": 106, "size": 30, "arch": "DistilBERT"},
    "E_threat_intel": {"start":106, "end": 120, "size": 14, "arch": "CNN+LSTM"},
    "F_tls_host":     {"start":120, "end": 128, "size":  8, "arch": "CNN"},
}
N_FEATURES   = 128
FEAT_NAMES   = [f"f_{i:03d}" for i in range(N_FEATURES)]

# ─── Dataset Split Targets ───────────────────────────────────────────────────
SPLIT_TARGETS = {
    "real_cowrie":   180_000,
    "real_transfer":  60_000,
    "tabsyn_synth":  720_000,
    "great_synth":   240_000,
}
TOTAL_SESSIONS       = 1_200_000
MIN_SAMPLES_PER_CLASS = 2_000

# ─── Kill-Chain DAG ──────────────────────────────────────────────────────────
KILL_CHAIN_DAG: Dict[str, Set[str]] = {
    "RECON_DNS":             {"RECON_IP_SCAN","RECON_VERSION_PROBE"},
    "RECON_IP_SCAN":         {"RECON_VERSION_PROBE","RECON_OS_DETECT","RECON_VULN_SCAN"},
    "RECON_VERSION_PROBE":   {"RECON_OS_DETECT","RECON_VULN_SCAN","ACCESS_BRUTE_SSH"},
    "RECON_OS_DETECT":       {"RECON_VULN_SCAN","ACCESS_BRUTE_SSH"},
    "RECON_VULN_SCAN":       {"RECON_USER_ENUM","ACCESS_BRUTE_SSH","ACCESS_KEX_EXPLOIT"},
    "RECON_USER_ENUM":       {"ACCESS_BRUTE_SSH","ACCESS_CRED_STUFF"},
    "ACCESS_BRUTE_SSH":      {"ACCESS_BRUTE_SSH","ACCESS_AUTH_BYPASS","EXEC_SHELL_OPEN"},
    "ACCESS_BRUTE_HTTP":     {"ACCESS_CRED_STUFF","EXEC_SHELL_OPEN"},
    "ACCESS_CRED_STUFF":     {"ACCESS_DEFAULT_CRED","EXEC_SHELL_OPEN"},
    "ACCESS_DEFAULT_CRED":   {"EXEC_SHELL_OPEN"},
    "ACCESS_KEX_EXPLOIT":    {"EXEC_SHELL_OPEN"},
    "ACCESS_AUTH_BYPASS":    {"EXEC_SHELL_OPEN"},
    "EXEC_SHELL_OPEN":       {"EXEC_PYTHON_SCRIPT","EXEC_CURL_BASH","EXEC_WGET_EXEC",
                              "DISC_ENV_PROBE","DISC_NETSTAT_SCAN"},
    "EXEC_PYTHON_SCRIPT":    {"DISC_ENV_PROBE","PRIVESC_SUDO_ABUSE","PERSIST_CRONTAB"},
    "EXEC_PERL_SCRIPT":      {"DISC_ENV_PROBE","PRIVESC_SUDO_ABUSE"},
    "EXEC_CURL_BASH":        {"EXEC_WGET_EXEC","DISC_ENV_PROBE"},
    "EXEC_WGET_EXEC":        {"EXEC_MEMFD_EXEC","DISC_ENV_PROBE","PRIVESC_SUDO_ABUSE"},
    "EXEC_MEMFD_EXEC":       {"DISC_ENV_PROBE","PRIVESC_KERNEL_XPLOIT"},
    "DISC_ENV_PROBE":        {"DISC_NETSTAT_SCAN","DISC_PROC_ENUM","DISC_SUID_HUNT",
                              "DISC_CVE_SEARCH","PRIVESC_SUDO_ABUSE"},
    "DISC_NETSTAT_SCAN":     {"DISC_PROC_ENUM","LATERAL_SCAN_PIVOT","PRIVESC_SUDO_ABUSE"},
    "DISC_PROC_ENUM":        {"DISC_SUID_HUNT","PRIVESC_SUDO_ABUSE"},
    "DISC_SUID_HUNT":        {"PRIVESC_SUID_EXPLOIT","PRIVESC_SUDO_ABUSE"},
    "DISC_CVE_SEARCH":       {"PRIVESC_KERNEL_XPLOIT","PRIVESC_CONTAINER_ESC"},
    "PRIVESC_SUDO_ABUSE":    {"PERSIST_CRONTAB","PERSIST_BASHRC","EVASION_LOG_WIPE"},
    "PRIVESC_SUID_EXPLOIT":  {"PERSIST_CRONTAB","PERSIST_BACKDOOR_ADD"},
    "PRIVESC_KERNEL_XPLOIT": {"PERSIST_CRONTAB","PERSIST_BACKDOOR_ADD","PERSIST_SYSTEMD_SVC"},
    "PRIVESC_CONTAINER_ESC": {"LATERAL_SSH_SPREAD","EXFIL_SCP_DATA"},
    "PERSIST_CRONTAB":       {"PERSIST_BASHRC","PERSIST_SSH_KEY_ADD","EVASION_LOG_WIPE"},
    "PERSIST_BASHRC":        {"PERSIST_SSH_KEY_ADD","EVASION_LOG_WIPE"},
    "PERSIST_SSH_KEY_ADD":   {"PERSIST_BACKDOOR_ADD","EVASION_LOG_WIPE"},
    "PERSIST_BACKDOOR_ADD":  {"PERSIST_SYSTEMD_SVC","EVASION_LOG_WIPE"},
    "PERSIST_SYSTEMD_SVC":   {"EVASION_LOG_WIPE","LATERAL_SSH_SPREAD"},
    "EVASION_LOG_WIPE":      {"EVASION_HIST_ERASE","EVASION_CHMOD_HIDE"},
    "EVASION_HIST_ERASE":    {"EVASION_CHMOD_HIDE","EVASION_CURL_OBFUS",
                              "LATERAL_SSH_SPREAD","EXFIL_SCP_DATA"},
    "EVASION_CHMOD_HIDE":    {"EVASION_CURL_OBFUS","EXFIL_SCP_DATA"},
    "EVASION_CURL_OBFUS":    {"EVASION_PROC_INJECT","EXFIL_CURL_C2"},
    "EVASION_PROC_INJECT":   {"EXFIL_CURL_C2","EXFIL_DNS_TUNNEL"},
    "LATERAL_SSH_SPREAD":    {"LATERAL_SCAN_PIVOT","LATERAL_CRED_REUSE"},
    "LATERAL_SCAN_PIVOT":    {"LATERAL_CRED_REUSE","EXFIL_SCP_DATA"},
    "LATERAL_CRED_REUSE":    {"EXFIL_SCP_DATA","EXFIL_CURL_C2"},
    "EXFIL_SCP_DATA":        {"EXFIL_STAGING_TAR","EXFIL_TUNNEL_NGROK"},
    "EXFIL_CURL_C2":         {"EXFIL_DNS_TUNNEL","EXFIL_TUNNEL_NGROK"},
    "EXFIL_DNS_TUNNEL":      {"EXFIL_STAGING_TAR","EXFIL_TUNNEL_NGROK"},
    "EXFIL_STAGING_TAR":     {"EXFIL_TUNNEL_NGROK"},
    "EXFIL_TUNNEL_NGROK":    set(),
}
