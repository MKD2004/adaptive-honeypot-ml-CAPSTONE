# SCHEMA

Shared reference — **committed**, identical on every machine (ASUS / Dell / DGX).
Change it once and push; do not fork it locally.

Quick-lookup copy of `honeypot_dataset/configs/schema.py`
so prompts/questions can reference exact labels, indices, and feature groups without
re-reading the source file every time. If this ever disagrees with `schema.py`,
`schema.py` is the source of truth — this is a snapshot.

---

## 128-Feature Layout

| Group | Indices | Size | Arch Branch | Extractor | Extracts |
|---|---|---|---|---|---|
| A_temporal | 0-23 | 24 | LSTM | `temporal.py` | IAT stats, burst detection, calendar context |
| B_network | 24-51 | 28 | CNN | `network.py` | byte/packet flows, port/protocol encoding, TCP flags |
| C_payload | 52-75 | 24 | CNN | `payload.py` | entropy, byte distributions, n-gram stats, shell tokens |
| D_semantic | 76-105 | 30 | DistilBERT | `semantic.py` | DistilBERT CLS → PCA(30) of command text |
| E_threat_intel | 106-119 | 14 | CNN+LSTM | `threat_intel.py` | CVSS, EPSS, CISA KEV, exploit counts (live API) |
| F_tls_host | 120-127 | 8 | CNN | `tls_host.py` | JA3 fingerprint, TLS version, geo risk |

`N_FEATURES = 128`. Feature names are placeholder `f_000`...`f_127` (`FEAT_NAMES`
in schema.py) — the group table above is the real semantic reference.

## 45 Micro-States (9 Kill-Chain Phases)

Real-data coverage column reflects notebook 01's output as of 2026-08-11
(737,319 real sessions, post label-mapping-bug-fix — see ERRORS.md). ✓ = at
least some real sessions exist for this class; ✗ = zero real coverage, needs
TabSyn/GReaT synthetic to reach the 2,000-sample minimum.

### Phase 0 — Reconnaissance (6)
| id | label | mitre | real data? |
|---|---|---|---|
| 0 | RECON_DNS | T1590.002 | ✗ |
| 1 | RECON_IP_SCAN | T1046 | ✓ |
| 2 | RECON_VERSION_PROBE | T1590.001 | ✗ |
| 3 | RECON_OS_DETECT | T1082 | ✗ |
| 4 | RECON_VULN_SCAN | T1595.002 | ✓ |
| 5 | RECON_USER_ENUM | T1589.003 | ✗ |

### Phase 1 — Initial Access (6)
| id | label | mitre | real data? |
|---|---|---|---|
| 6 | ACCESS_BRUTE_SSH | T1110.001 | ✓ |
| 7 | ACCESS_BRUTE_HTTP | T1110.001 | ✓ |
| 8 | ACCESS_CRED_STUFF | T1110.004 | ✗ |
| 9 | ACCESS_DEFAULT_CRED | T1078.001 | ✗ |
| 10 | ACCESS_KEX_EXPLOIT | T1190 | ✓ |
| 11 | ACCESS_AUTH_BYPASS | T1548 | ✗ |

### Phase 2 — Execution (6)
| id | label | mitre | real data? |
|---|---|---|---|
| 12 | EXEC_SHELL_OPEN | T1059.004 | ✓ |
| 13 | EXEC_PYTHON_SCRIPT | T1059.006 | ✗ |
| 14 | EXEC_PERL_SCRIPT | T1059 | ✗ |
| 15 | EXEC_CURL_BASH | T1059.004 | ✓ |
| 16 | EXEC_WGET_EXEC | T1105 | ✓ |
| 17 | EXEC_MEMFD_EXEC | T1620 | ✓ |

### Phase 3 — Discovery (5)
| id | label | mitre | real data? |
|---|---|---|---|
| 18 | DISC_ENV_PROBE | T1082 | ✓ |
| 19 | DISC_NETSTAT_SCAN | T1049 | ✓ |
| 20 | DISC_PROC_ENUM | T1057 | ✓ |
| 21 | DISC_SUID_HUNT | T1548.001 | ✓ |
| 22 | DISC_CVE_SEARCH | T1595 | ✗ |

### Phase 4 — Privilege Escalation (4)
| id | label | mitre | real data? |
|---|---|---|---|
| 23 | PRIVESC_SUDO_ABUSE | T1548.003 | ✓ |
| 24 | PRIVESC_SUID_EXPLOIT | T1548.001 | ✗ |
| 25 | PRIVESC_KERNEL_XPLOIT | T1068 | ✗ |
| 26 | PRIVESC_CONTAINER_ESC | T1611 | ✗ |

### Phase 5 — Persistence (5)
| id | label | mitre | real data? |
|---|---|---|---|
| 27 | PERSIST_CRONTAB | T1053.003 | ✓ |
| 28 | PERSIST_BASHRC | T1546.004 | ✗ |
| 29 | PERSIST_SSH_KEY_ADD | T1098.004 | ✓ |
| 30 | PERSIST_BACKDOOR_ADD | T1505 | ✓ |
| 31 | PERSIST_SYSTEMD_SVC | T1543.002 | ✗ |

### Phase 6 — Defense Evasion (5)
| id | label | mitre | real data? |
|---|---|---|---|
| 32 | EVASION_LOG_WIPE | T1070.002 | ✓ |
| 33 | EVASION_HIST_ERASE | T1070.003 | ✓ |
| 34 | EVASION_CHMOD_HIDE | T1564 | ✗ |
| 35 | EVASION_CURL_OBFUS | T1027 | ✗ |
| 36 | EVASION_PROC_INJECT | T1055 | ✗ |

### Phase 7 — Lateral Movement (3)
| id | label | mitre | real data? |
|---|---|---|---|
| 37 | LATERAL_SSH_SPREAD | T1021.004 | ✓ |
| 38 | LATERAL_SCAN_PIVOT | T1046 | ✗ |
| 39 | LATERAL_CRED_REUSE | T1078 | ✗ |

### Phase 8 — Exfiltration (5)
| id | label | mitre | real data? |
|---|---|---|---|
| 40 | EXFIL_SCP_DATA | T1048.002 | ✓ |
| 41 | EXFIL_CURL_C2 | T1071.001 | ✗ |
| 42 | EXFIL_DNS_TUNNEL | T1048.001 | ✗ |
| 43 | EXFIL_STAGING_TAR | T1074.001 | ✓ |
| 44 | EXFIL_TUNNEL_NGROK | T1572 | ✗ |

**Totals: 22/45 covered by real data, 23/45 need synthetic-only coverage.**

## Dataset Split Targets (`SPLIT_TARGETS` in schema.py)

| Source | Target count |
|---|---|
| real_cowrie | 180,000 |
| real_transfer (CIC+UNSW) | 60,000 |
| tabsyn_synth | 720,000 |
| great_synth | 240,000 |
| **Total** | **1,200,000** |

`MIN_SAMPLES_PER_CLASS = 2,000`. Current real data is 737,319 sessions total
(15,000 Cowrie + 557,646 CIC + 164,673 UNSW) — well past the 240k real target in
raw count, but concentrated in 22 classes; the 23 missing classes still need
`MIN_SAMPLES_PER_CLASS` from synthetic generation alone.

## Kill-Chain DAG

`KILL_CHAIN_DAG` in schema.py defines valid transitions (label → set of valid
next labels) used to constrain session simulation. Not reproduced here in full —
read `configs/schema.py:96-145` directly when writing simulator logic; it's the
one part of the schema dense enough that a stale copy here would be actively
misleading.
