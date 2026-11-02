import { cn } from '../../lib/cn'

const STYLES = {
  running: 'bg-risk-low/10 text-risk-low border-risk-low/30',
  online: 'bg-risk-low/10 text-risk-low border-risk-low/30',
  active: 'bg-risk-low/10 text-risk-low border-risk-low/30',
  idle: 'bg-text-muted/10 text-text-secondary border-base-border',
  degraded: 'bg-risk-medium/10 text-risk-medium border-risk-medium/30',
  offline: 'bg-risk-high/10 text-risk-high border-risk-high/30',
  stopped: 'bg-risk-high/10 text-risk-high border-risk-high/30',
  // Honest "this is demo data, not a live reading" indicator — used instead
  // of a green "online"/"running" badge anywhere the backend isn't wired up.
  mock: 'bg-risk-info/10 text-risk-info border-risk-info/30',
  unknown: 'bg-text-muted/10 text-text-muted border-base-border',
  not_implemented: 'bg-text-muted/10 text-text-muted border-base-border border-dashed',
}

const DOT = {
  running: 'bg-risk-low',
  online: 'bg-risk-low',
  active: 'bg-risk-low',
  idle: 'bg-text-muted',
  degraded: 'bg-risk-medium',
  offline: 'bg-risk-high',
  stopped: 'bg-risk-high',
  mock: 'bg-risk-info',
  unknown: 'bg-text-muted',
  not_implemented: 'bg-text-muted',
}

export default function StatusBadge({ status = 'unknown', label }) {
  const key = STYLES[status] ? status : 'unknown'
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium',
        STYLES[key],
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', DOT[key])} />
      {label ?? status.replace(/_/g, ' ')}
    </span>
  )
}
