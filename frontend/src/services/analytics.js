// Per-micro-state analytics computed from the sessions MT3 has actually
// classified, in the same shape src/data/mockAnalytics.js exported, so the
// Threat Analytics page kept its components and its filter logic.
//
// Two deliberate differences from the simulated version it replaced:
//
//  1. All 45 micro-states are always present, most of them with count 0.
//     That is the honest picture on this project — `test_real` only ever had
//     21 of the 45 classes, and one machine's sessions will touch far fewer.
//  2. The confidence histogram buckets EVERY SESSION's own confidence. The
//     mock bucketed each state's *average* confidence and then added up the
//     state's whole count, which put e.g. 50 sessions into one bucket on the
//     strength of a single mean. Real sessions are counted individually.

import { MICRO_STATES, KILL_CHAIN_PHASES } from '../lib/schema'

export const HIGH_CONFIDENCE_THRESHOLD = 0.75

export const CONFIDENCE_BUCKET_DEFS = [
  { label: '50-60%', min: 0.5, max: 0.6 },
  { label: '60-70%', min: 0.6, max: 0.7 },
  { label: '70-80%', min: 0.7, max: 0.8 },
  { label: '80-90%', min: 0.8, max: 0.9 },
  { label: '90-100%', min: 0.9, max: 1.001 },
]

function mean(values) {
  return values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0
}

// One row per micro-state in the schema, whether or not it was ever observed.
export function microStateAnalytics(sessions = []) {
  const byLabel = new Map()
  sessions.forEach((s) => {
    if (!s.micro_state) return
    if (!byLabel.has(s.micro_state)) byLabel.set(s.micro_state, [])
    if (Number.isFinite(s.confidence)) byLabel.get(s.micro_state).push(s.confidence)
  })

  return MICRO_STATES.map((state) => {
    const confidences = byLabel.get(state.label) ?? []
    return {
      ...state,
      count: confidences.length,
      avgConfidence: Math.round(mean(confidences) * 1000) / 1000,
      highConfidenceCount: confidences.filter((c) => c >= HIGH_CONFIDENCE_THRESHOLD).length,
    }
  })
}

export function phaseAnalytics(states = []) {
  return KILL_CHAIN_PHASES.map((phase) => {
    const forPhase = states.filter((s) => s.phase === phase.id)
    const count = forPhase.reduce((sum, s) => sum + s.count, 0)
    const avgConfidence = count
      ? Math.round(
          (forPhase.reduce((sum, s) => sum + s.avgConfidence * s.count, 0) / count) * 1000,
        ) / 1000
      : 0
    return { ...phase, count, avgConfidence, states: forPhase }
  })
}

// Buckets individual session confidences, not per-state averages.
export function confidenceBuckets(sessions = []) {
  const values = sessions.map((s) => s.confidence).filter((c) => Number.isFinite(c))
  return CONFIDENCE_BUCKET_DEFS.map((bucket) => ({
    ...bucket,
    count: values.filter((c) => c >= bucket.min && c < bucket.max).length,
  }))
}

export function analyticsTotals(sessions = []) {
  const confidences = sessions.map((s) => s.confidence).filter((c) => Number.isFinite(c))
  return {
    total: sessions.length,
    highConfidenceTotal: confidences.filter((c) => c >= HIGH_CONFIDENCE_THRESHOLD).length,
    avgConfidence: mean(confidences),
    statesObserved: new Set(sessions.map((s) => s.micro_state).filter(Boolean)).size,
  }
}
