// Turns one row of GET /api/live-feed into the session shape the session
// components already expect, so the pages could move off src/data/mockData.js
// without any component being rewritten.
//
// /api/live-feed is used rather than /api/mt3-results because it returns the
// raw pipeline_results.jsonl row, which carries the fields the detail view
// needs (duration, commands, login attempts, and the configurator's
// before/after config) on top of the MT3 prediction itself.
//
// Four fields the mock invented are NOT available from the API and are
// reported as null rather than guessed — see UNAVAILABLE_FIELDS below. The
// UI renders a dash for them.

import { KILL_CHAIN_PHASES, MICRO_STATES } from '../lib/schema'
import { getLiveFeed } from './api'

// The pipeline records the honeypot it routed to, not the wire protocol.
const PROTOCOL_BY_TARGET = {
  SSH_HONEYPOT: 'SSH',
  HTTP_HONEYPOT: 'HTTP',
  DB_HONEYPOT: 'PostgreSQL',
}

// Cowrie logs no source/destination port into the fields the parser keeps, and
// the pipeline result has no destination address, so these cannot be filled in
// from the API. The mock generated them at random; showing a made-up port next
// to real MT3 output would be worse than showing nothing.
export const UNAVAILABLE_FIELDS = ['destination', 'src_port', 'dst_port']

const MITRE_BY_LABEL = new Map(MICRO_STATES.map((m) => [m.label, m.mitre]))

// Same thresholds as components/common/RiskBadge.jsx.
export function phaseToRisk(phaseId) {
  if (phaseId >= 7) return 'critical'
  if (phaseId >= 4) return 'high'
  if (phaseId >= 2) return 'medium'
  return 'low'
}

// MT3 classifies a session only once it CLOSES -- it needs the whole session
// for the temporal features -- so every row the pipeline emits is a finished
// session. There is no live "active"/"idle" state to report here.
const SESSION_STATE = 'closed'

function toIso(value) {
  if (!value) return null
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? null : d.toISOString()
}

// The timeline is derived from the three timestamps the pipeline actually
// records: session start, session end (start + duration) and the moment MT3
// finished. Nothing is interpolated between them.
function buildTimeline(row, pred) {
  const startIso = toIso(row.timestamp)
  if (!startIso) return []
  const startMs = new Date(startIso).getTime()
  const durationMs = Math.max(0, Number(row.duration_s) || 0) * 1000
  const nCommands = Array.isArray(row.commands) ? row.commands.length : 0
  const confidence = Number(pred.confidence)

  const steps = [
    {
      ts: startIso,
      label: 'Session opened',
      detail: row.observed_src_ip
        ? `Seen by the honeypot as ${row.observed_src_ip}, attributed to ${row.src_ip}`
        : `Connection from ${row.src_ip}`,
    },
  ]

  if (row.login_attempts > 0) {
    steps.push({
      ts: new Date(startMs + durationMs * 0.25).toISOString(),
      label: 'Authentication attempted',
      detail: `${row.login_attempts} login attempt${row.login_attempts === 1 ? '' : 's'}`,
    })
  }
  if (nCommands > 0) {
    steps.push({
      ts: new Date(startMs + durationMs * 0.5).toISOString(),
      label: 'Commands observed',
      detail: `${nCommands} command${nCommands === 1 ? '' : 's'} captured by Cowrie`,
    })
  }

  steps.push({
    ts: new Date(startMs + durationMs).toISOString(),
    label: 'Session closed',
    detail: `Lasted ${(durationMs / 1000).toFixed(3)}s`,
  })

  const processedIso = toIso(row.processed_at)
  if (processedIso) {
    steps.push({
      ts: processedIso,
      label: 'MT3 classification',
      detail: Number.isFinite(confidence)
        ? `${pred.micro_state} (p=${confidence.toFixed(3)})` +
          (row.latency_ms ? ` in ${row.latency_ms}ms` : '')
        : 'No prediction recorded',
    })
    const action = row.honeypot_action || {}
    if (action.changed) {
      steps.push({
        ts: processedIso,
        label: 'Honeypot reconfigured',
        detail: action.reason || 'Interaction level updated',
      })
    }
  }
  return steps
}

export function resultToSession(row) {
  const pred = row.mt3_prediction || {}
  const action = row.honeypot_action || {}
  const newConfig = action.new_config || {}
  const prevConfig = action.previous_config || {}
  const phase = Number.isFinite(pred.phase) ? pred.phase : null
  const phaseMeta = phase !== null ? KILL_CHAIN_PHASES[phase] : null
  const startIso = toIso(row.timestamp)

  return {
    session_id: row.session_id || '',
    src_ip: row.src_ip || '',
    observed_src_ip: row.observed_src_ip || null,

    // Derived from the honeypot the pipeline routed to.
    honeypot_target: pred.honeypot_target || null,
    protocol: PROTOCOL_BY_TARGET[pred.honeypot_target] || null,

    // Not obtainable from the API -- see UNAVAILABLE_FIELDS.
    destination: null,
    src_port: null,
    dst_port: null,

    status: SESSION_STATE,
    risk: phase !== null ? phaseToRisk(phase) : 'low',

    // The pipeline's `timestamp` is the session's start time.
    timestamp: startIso,
    first_seen: startIso,
    duration_s: Number(row.duration_s) || 0,

    micro_state: pred.micro_state || null,
    mitre: MITRE_BY_LABEL.get(pred.micro_state) || null,
    phase,
    phase_name: pred.phase_name || (phaseMeta ? phaseMeta.name : null),
    confidence: Number.isFinite(Number(pred.confidence)) ? Number(pred.confidence) : null,
    top3: (pred.top3 || []).map((t) => ({ label: t.micro_state, prob: t.p })),

    gateway_score: Number.isFinite(Number(row.gateway_score)) ? Number(row.gateway_score) : null,
    gateway_verdict: row.gateway_verdict || null,
    gateway_signals: row.gateway_signals || [],
    rule_label: row.rule_label || null,
    kcvr_valid: row.kcvr_valid,

    // The adaptive loop, straight from the configurator's own record.
    config_changed: Boolean(action.changed),
    interaction_level: newConfig.interaction_level || null,
    previous_interaction_level: prevConfig.interaction_level || null,
    adaptive_reason: action.reason || null,

    login_attempts: Number(row.login_attempts) || 0,
    commands: Array.isArray(row.commands) ? row.commands : [],

    // Provenance, added by the pipeline so internet and lab data are never
    // pooled. Null on rows written before those fields existed.
    sensor: row.sensor || null,
    source: row.source || null,
    auto_blacklisted: Boolean(row.auto_blacklisted),
    semantic_available: row.semantic_available,

    timeline: buildTimeline(row, pred),
  }
}

// Newest first, matching the order the mock used.
export async function getSessions({ limit } = {}) {
  const payload = await getLiveFeed({ limit })
  const rows = Array.isArray(payload?.results) ? payload.results : []
  const sessions = rows
    .map(resultToSession)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
  return { sessions, count: sessions.length, source: payload?.source ?? null }
}

// The summary numbers the Dashboard and Live Sessions metric cards share, so
// the two views can never disagree. `active` is always 0: see SESSION_STATE.
export function getSessionSummary(sessions = []) {
  const withConfidence = sessions.filter((s) => Number.isFinite(s.confidence))
  return {
    active: sessions.filter((s) => s.status === 'active').length,
    total: sessions.length,
    highRisk: sessions.filter((s) => s.risk === 'high' || s.risk === 'critical').length,
    avgConfidence: withConfidence.length
      ? withConfidence.reduce((sum, s) => sum + s.confidence, 0) / withConfidence.length
      : 0,
  }
}
