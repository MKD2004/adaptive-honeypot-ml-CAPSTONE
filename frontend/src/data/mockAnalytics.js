// SIMULATED analytics data for the Threat Analytics page (/analytics).
//
// This is intentionally a separate dataset from mockLiveSessions
// (src/data/mockData.js) — 24 live sessions are too sparse to chart a
// meaningful distribution across 45 micro-states or a confidence histogram.
// Every number below is produced by a fixed, deterministic formula keyed off
// each micro-state's id (never Math.random()), so the page shows identical
// numbers on every load, filter change, and theme toggle. Nothing here
// implies the model actually ran — see the "Simulated Data" badge on the
// page itself.
//
// MITRE Analysis (/mitre), by contrast, deliberately counts straight from
// mockLiveSessions — see MitreAnalysisPage.jsx — because that page is meant
// to reflect "the mock dataset" literally, not a simulated larger sample.

import { MICRO_STATES, KILL_CHAIN_PHASES } from '../lib/schema'

export const HIGH_CONFIDENCE_THRESHOLD = 0.75

function deterministicCount(state) {
  // Real-data-anchored states get a larger simulated sample, matching the
  // project's own documented pattern (real classes have deeper coverage).
  const base = state.realData ? 45 : 18
  const spread = (state.id * 37) % 23 // 0-22, deterministic
  return base + spread
}

function deterministicConfidence(state) {
  // Deterministic per-state variation around a realistic band (matches the
  // 0.55-0.99 range already used by mockData.js), higher for real-anchored
  // states — mirroring the project's documented real-vs-synthetic gap.
  const base = state.realData ? 0.82 : 0.71
  const jitter = (((state.id * 13) % 21) - 10) / 100 // -0.10 .. +0.10
  return Math.max(0.5, Math.min(0.99, base + jitter))
}

export const MICRO_STATE_ANALYTICS = MICRO_STATES.map((state) => {
  const count = deterministicCount(state)
  const avgConfidence = Math.round(deterministicConfidence(state) * 1000) / 1000
  const highConfidenceCount = Math.round(
    count * (avgConfidence >= HIGH_CONFIDENCE_THRESHOLD ? 0.8 : 0.4),
  )
  return { ...state, count, avgConfidence, highConfidenceCount }
})

export const TOTAL_ANALYZED_SESSIONS = MICRO_STATE_ANALYTICS.reduce((sum, s) => sum + s.count, 0)

export const HIGH_CONFIDENCE_TOTAL = MICRO_STATE_ANALYTICS.reduce(
  (sum, s) => sum + s.highConfidenceCount,
  0,
)

export const OVERALL_AVG_CONFIDENCE =
  MICRO_STATE_ANALYTICS.reduce((sum, s) => sum + s.avgConfidence * s.count, 0) /
  TOTAL_ANALYZED_SESSIONS

export const PHASE_ANALYTICS = KILL_CHAIN_PHASES.map((phase) => {
  const states = MICRO_STATE_ANALYTICS.filter((s) => s.phase === phase.id)
  const count = states.reduce((sum, s) => sum + s.count, 0)
  const avgConfidence = count
    ? Math.round(
        (states.reduce((sum, s) => sum + s.avgConfidence * s.count, 0) / count) * 1000,
      ) / 1000
    : 0
  return { ...phase, count, avgConfidence, states }
})

export const CONFIDENCE_BUCKET_DEFS = [
  { label: '50-60%', min: 0.5, max: 0.6 },
  { label: '60-70%', min: 0.6, max: 0.7 },
  { label: '70-80%', min: 0.7, max: 0.8 },
  { label: '80-90%', min: 0.8, max: 0.9 },
  { label: '90-100%', min: 0.9, max: 1.001 },
]

export const CONFIDENCE_BUCKETS = CONFIDENCE_BUCKET_DEFS.map((bucket) => ({
  ...bucket,
  count: MICRO_STATE_ANALYTICS.filter(
    (s) => s.avgConfidence >= bucket.min && s.avgConfidence < bucket.max,
  ).reduce((sum, s) => sum + s.count, 0),
}))
