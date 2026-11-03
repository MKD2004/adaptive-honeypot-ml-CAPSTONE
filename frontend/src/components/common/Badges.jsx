import { cn } from '../../lib/cn'
import { PHASE_COLORS, LEVEL_LABEL, phaseName } from '../../lib/schema'

const pill = 'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium'

// Kill-chain phase, colored with the same palette every chart uses.
export function PhaseBadge({ phase, showName = true }) {
  if (phase === null || phase === undefined) return <span className="text-text-muted">—</span>
  return (
    <span className={cn(pill, 'border-base-border text-text-secondary')}>
      <span className="h-2 w-2 rounded-full" style={{ background: PHASE_COLORS[phase] }} />
      {showName ? `${phase} · ${phaseName(phase)}` : phase}
    </span>
  )
}

// traffic_classifier.py's pre-filter verdict (NOT an MT3 output).
const VERDICT_CLS = {
  MALICIOUS: 'border-risk-critical/30 bg-risk-critical/10 text-risk-critical',
  SUSPICIOUS: 'border-risk-medium/30 bg-risk-medium/10 text-risk-medium',
  BENIGN: 'border-risk-low/30 bg-risk-low/10 text-risk-low',
  REJECTED: 'border-risk-info/30 bg-risk-info/10 text-risk-info',
}

export function VerdictBadge({ verdict }) {
  const v = verdict || '—'
  return <span className={cn(pill, VERDICT_CLS[v] ?? 'border-base-border text-text-muted')}>{v}</span>
}

// Where the gateway sent the connection.
const DEST_CLS = {
  'REAL SERVER': 'text-risk-low',
  HONEYPOT: 'text-risk-critical',
  REJECTED: 'text-risk-info',
}

export function DestinationLabel({ destination }) {
  return <span className={cn('text-xs font-semibold', DEST_CLS[destination] ?? 'text-text-muted')}>{destination || '—'}</span>
}

// The adaptive honeypot's interaction level.
const LEVEL_CLS = {
  low: 'border-risk-info/30 bg-risk-info/10 text-risk-info',
  medium: 'border-risk-medium/30 bg-risk-medium/10 text-risk-medium',
  high: 'border-risk-high/30 bg-risk-high/10 text-risk-high',
  maximum: 'border-risk-critical/30 bg-risk-critical/10 text-risk-critical',
}

export function LevelBadge({ level, suffix = ' interaction' }) {
  if (!level) return <span className="text-text-muted">—</span>
  return (
    <span className={cn(pill, LEVEL_CLS[level] ?? 'border-base-border text-text-muted')}>
      {(LEVEL_LABEL[level] ?? level) + suffix}
    </span>
  )
}

export function ListTags({ blacklisted, whitelisted }) {
  return (
    <>
      {blacklisted && (
        <span className="ml-1.5 rounded border border-risk-critical/30 px-1 text-[10px] font-semibold text-risk-critical">BL</span>
      )}
      {whitelisted && (
        <span className="ml-1.5 rounded border border-risk-low/30 px-1 text-[10px] font-semibold text-risk-low">WL</span>
      )}
    </>
  )
}

// MT3 confidence as a bar + number.
export function ConfidenceBar({ value }) {
  if (typeof value !== 'number') return <span className="text-text-muted">—</span>
  const tone = value >= 0.8 ? 'bg-risk-low' : value >= 0.5 ? 'bg-risk-medium' : 'bg-risk-high'
  return (
    <span className="inline-flex items-center gap-2">
      <span className="h-1.5 w-14 overflow-hidden rounded-full bg-base-raised">
        <span className={cn('block h-full', tone)} style={{ width: `${Math.round(value * 100)}%` }} />
      </span>
      <span className="tabular-nums text-xs text-text-secondary">{(value * 100).toFixed(1)}%</span>
    </span>
  )
}
