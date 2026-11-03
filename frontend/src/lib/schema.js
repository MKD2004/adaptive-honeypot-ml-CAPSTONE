// Project schema constants — mirrors honeypot_dataset/configs/schema.py and
// SCHEMA.md. Read-only reference data, not mock data: these are the real
// 45 micro-states / 9 kill-chain phases / 128-feature layout documented in
// the repo. Do not invent additional states or phases here.

export const KILL_CHAIN_PHASES = [
  { id: 0, name: 'Reconnaissance', stateCount: 6, interaction: 'low' },
  { id: 1, name: 'Initial Access', stateCount: 6, interaction: 'low' },
  { id: 2, name: 'Execution', stateCount: 6, interaction: 'medium' },
  { id: 3, name: 'Discovery', stateCount: 5, interaction: 'medium' },
  { id: 4, name: 'Privilege Escalation', stateCount: 4, interaction: 'high' },
  { id: 5, name: 'Persistence', stateCount: 5, interaction: 'high' },
  { id: 6, name: 'Defense Evasion', stateCount: 5, interaction: 'high' },
  { id: 7, name: 'Lateral Movement', stateCount: 3, interaction: 'maximum' },
  { id: 8, name: 'Exfiltration', stateCount: 5, interaction: 'maximum' },
]

// realData = anchored by genuinely real data (CIC-IDS2017 / UNSW-NB15): 13 of 45.
// The 15k Cowrie sessions are synthetic (DECISIONS.md 2026-08-28), so the 9
// classes only they covered are NOT real-anchored, even though SCHEMA.md's
// older table marks 22 classes.
export const MICRO_STATES = [
  { id: 0, label: 'RECON_DNS', mitre: 'T1590.002', phase: 0, realData: false },
  { id: 1, label: 'RECON_IP_SCAN', mitre: 'T1046', phase: 0, realData: true },
  { id: 2, label: 'RECON_VERSION_PROBE', mitre: 'T1590.001', phase: 0, realData: false },
  { id: 3, label: 'RECON_OS_DETECT', mitre: 'T1082', phase: 0, realData: false },
  { id: 4, label: 'RECON_VULN_SCAN', mitre: 'T1595.002', phase: 0, realData: true },
  { id: 5, label: 'RECON_USER_ENUM', mitre: 'T1589.003', phase: 0, realData: false },

  { id: 6, label: 'ACCESS_BRUTE_SSH', mitre: 'T1110.001', phase: 1, realData: true },
  { id: 7, label: 'ACCESS_BRUTE_HTTP', mitre: 'T1110.001', phase: 1, realData: true },
  { id: 8, label: 'ACCESS_CRED_STUFF', mitre: 'T1110.004', phase: 1, realData: false },
  { id: 9, label: 'ACCESS_DEFAULT_CRED', mitre: 'T1078.001', phase: 1, realData: false },
  { id: 10, label: 'ACCESS_KEX_EXPLOIT', mitre: 'T1190', phase: 1, realData: true },
  { id: 11, label: 'ACCESS_AUTH_BYPASS', mitre: 'T1548', phase: 1, realData: false },

  { id: 12, label: 'EXEC_SHELL_OPEN', mitre: 'T1059.004', phase: 2, realData: true },
  { id: 13, label: 'EXEC_PYTHON_SCRIPT', mitre: 'T1059.006', phase: 2, realData: false },
  { id: 14, label: 'EXEC_PERL_SCRIPT', mitre: 'T1059', phase: 2, realData: false },
  { id: 15, label: 'EXEC_CURL_BASH', mitre: 'T1059.004', phase: 2, realData: true },
  { id: 16, label: 'EXEC_WGET_EXEC', mitre: 'T1105', phase: 2, realData: false },
  { id: 17, label: 'EXEC_MEMFD_EXEC', mitre: 'T1620', phase: 2, realData: true },

  { id: 18, label: 'DISC_ENV_PROBE', mitre: 'T1082', phase: 3, realData: true },
  { id: 19, label: 'DISC_NETSTAT_SCAN', mitre: 'T1049', phase: 3, realData: true },
  { id: 20, label: 'DISC_PROC_ENUM', mitre: 'T1057', phase: 3, realData: false },
  { id: 21, label: 'DISC_SUID_HUNT', mitre: 'T1548.001', phase: 3, realData: false },
  { id: 22, label: 'DISC_CVE_SEARCH', mitre: 'T1595', phase: 3, realData: false },

  { id: 23, label: 'PRIVESC_SUDO_ABUSE', mitre: 'T1548.003', phase: 4, realData: false },
  { id: 24, label: 'PRIVESC_SUID_EXPLOIT', mitre: 'T1548.001', phase: 4, realData: false },
  { id: 25, label: 'PRIVESC_KERNEL_XPLOIT', mitre: 'T1068', phase: 4, realData: false },
  { id: 26, label: 'PRIVESC_CONTAINER_ESC', mitre: 'T1611', phase: 4, realData: false },

  { id: 27, label: 'PERSIST_CRONTAB', mitre: 'T1053.003', phase: 5, realData: true },
  { id: 28, label: 'PERSIST_BASHRC', mitre: 'T1546.004', phase: 5, realData: false },
  { id: 29, label: 'PERSIST_SSH_KEY_ADD', mitre: 'T1098.004', phase: 5, realData: false },
  { id: 30, label: 'PERSIST_BACKDOOR_ADD', mitre: 'T1505', phase: 5, realData: true },
  { id: 31, label: 'PERSIST_SYSTEMD_SVC', mitre: 'T1543.002', phase: 5, realData: false },

  { id: 32, label: 'EVASION_LOG_WIPE', mitre: 'T1070.002', phase: 6, realData: false },
  { id: 33, label: 'EVASION_HIST_ERASE', mitre: 'T1070.003', phase: 6, realData: false },
  { id: 34, label: 'EVASION_CHMOD_HIDE', mitre: 'T1564', phase: 6, realData: false },
  { id: 35, label: 'EVASION_CURL_OBFUS', mitre: 'T1027', phase: 6, realData: false },
  { id: 36, label: 'EVASION_PROC_INJECT', mitre: 'T1055', phase: 6, realData: false },

  { id: 37, label: 'LATERAL_SSH_SPREAD', mitre: 'T1021.004', phase: 7, realData: true },
  { id: 38, label: 'LATERAL_SCAN_PIVOT', mitre: 'T1046', phase: 7, realData: false },
  { id: 39, label: 'LATERAL_CRED_REUSE', mitre: 'T1078', phase: 7, realData: false },

  { id: 40, label: 'EXFIL_SCP_DATA', mitre: 'T1048.002', phase: 8, realData: false },
  { id: 41, label: 'EXFIL_CURL_C2', mitre: 'T1071.001', phase: 8, realData: false },
  { id: 42, label: 'EXFIL_DNS_TUNNEL', mitre: 'T1048.001', phase: 8, realData: false },
  { id: 43, label: 'EXFIL_STAGING_TAR', mitre: 'T1074.001', phase: 8, realData: false },
  { id: 44, label: 'EXFIL_TUNNEL_NGROK', mitre: 'T1572', phase: 8, realData: false },
]

export const FEATURE_GROUPS = [
  { key: 'A_temporal', range: '0-23', size: 24, branch: 'LSTM', desc: 'IAT stats, burst detection, calendar context' },
  { key: 'B_network', range: '24-51', size: 28, branch: 'CNN', desc: 'Byte/packet flows, port/protocol encoding, TCP flags' },
  { key: 'C_payload', range: '52-75', size: 24, branch: 'CNN', desc: 'Entropy, byte distributions, n-gram stats, shell tokens' },
  { key: 'D_semantic', range: '76-105', size: 30, branch: 'DistilBERT', desc: 'DistilBERT CLS → PCA(30) of command text' },
  { key: 'E_threat_intel', range: '106-119', size: 14, branch: 'CNN+LSTM', desc: 'CVSS, EPSS, CISA KEV, exploit counts (live API)' },
  { key: 'F_tls_host', range: '120-127', size: 8, branch: 'CNN', desc: 'JA3 fingerprint, TLS version, geo risk' },
]

// Fixed qualitative palette, one color per kill-chain phase (index-aligned
// with KILL_CHAIN_PHASES). Deliberately NOT theme-tokenized — chart
// categorical palettes conventionally stay constant across themes so a
// phase keeps the same color everywhere it's charted. Single source of
// truth: ThreatDistributionDonut and the Stage 6 analytics/MITRE charts all
// import this instead of redefining it.
export const PHASE_COLORS = [
  '#3b82f6', '#6366f1', '#8b5cf6', '#a855f7', '#ec4899',
  '#f97316', '#eab308', '#ef4444', '#22c55e',
]

export const N_FEATURES = 128
export const N_MICRO_STATES = 45
export const N_PHASES = 9

// Documented model comparison — README.md "Model Results" / STATUS.md session 3.
// macro-F1 over the 21 classes present in test_real. Do not editorialize which
// model is "better" — the headline finding is a statistical tie on test_real.
export const MODEL_RESULTS = [
  {
    model: 'Linear probe',
    params: 5805,
    valMacroF1: 0.9376,
    testRealClean: 0.7551,
    testSynth: 0.9373,
  },
  {
    model: 'CNN-LSTM baseline',
    params: 189581,
    valMacroF1: 0.9621,
    testRealClean: 0.7976,
    testSynth: 0.9610,
  },
  {
    model: 'MT3 (d=256, 4 layers)',
    params: 3759510,
    valMacroF1: 0.9599,
    testRealClean: 0.8187,
    testSynth: 0.9589,
  },
]

export const MODEL_RESULTS_NOTE =
  'On test_real the two neural models statistically tie (McNemar p = 0.617, clean subset). ' +
  'MT3’s Transformer fusion does not outperform concatenation + MLP at 20x the parameters. ' +
  'The CNN-LSTM wins test_synth significantly (p = 0.00064). Numbers above are the "clean" ' +
  'column — 29.74% of test_real rows are byte-identical to training rows and are excluded.'

export const DATASET_SUMMARY = {
  name: 'HoneySynth-960k',
  frozenDate: '2026-08-27',
  train: 756000,
  val: 84000,
  testReal: 60000,
  testSynth: 60000,
  testRealClasses: 21,
  totalClasses: 45,
  realAnchoredClasses: 13,
  note:
    'Real network-intrusion data (CIC-IDS2017 + UNSW-NB15) anchors 13 of 45 kill-chain classes; ' +
    'the remaining classes are synthetic honeypot sessions + TabSyn, generated to cover the full ' +
    '45-class MITRE taxonomy. There is no real honeypot data in the project.',
}

// Mirrors adaptive_honeypot/configurator.py INTERACTION_PROFILES / PHASE_TO_LEVEL.
export const INTERACTION_LEVELS = [
  {
    key: 'low',
    label: 'Low',
    phases: [0, 1],
    purpose: "Waste the attacker's time; collect source IP and tool fingerprint.",
    filesystem: 'minimal',
    delayMs: 1200,
    bait: 'none',
  },
  {
    key: 'medium',
    label: 'Medium',
    phases: [2, 3],
    purpose: 'Let the attacker reveal their tooling and techniques.',
    filesystem: 'rich',
    delayMs: 400,
    bait: 'fake credentials visible, downloads captured',
  },
  {
    key: 'high',
    label: 'High',
    phases: [4, 5, 6],
    purpose: 'Capture the full toolkit and any C2 infrastructure.',
    filesystem: 'full',
    delayMs: 120,
    bait: 'fake /etc/shadow + stealable SSH key planted in honeyfs',
  },
  {
    key: 'maximum',
    label: 'Maximum',
    phases: [7, 8],
    purpose: 'Attacker believes they succeeded; maximum intelligence collection.',
    filesystem: 'full',
    delayMs: 80,
    bait: 'everything above + external alert armed',
  },
]

export const LEVEL_LABEL = Object.fromEntries(INTERACTION_LEVELS.map((l) => [l.key, l.label]))

export function phaseName(id) {
  return KILL_CHAIN_PHASES[id]?.name ?? `Phase ${id}`
}

export function microStateLabel(id) {
  return MICRO_STATES.find((m) => m.id === id)?.label ?? `STATE_${id}`
}

const BY_LABEL = Object.fromEntries(MICRO_STATES.map((m) => [m.label, m]))

export function microStateByLabel(label) {
  return BY_LABEL[label] ?? null
}
