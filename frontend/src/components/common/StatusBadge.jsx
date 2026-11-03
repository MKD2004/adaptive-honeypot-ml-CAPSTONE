import { cn } from '../../lib/cn'

const STYLES = {
  running: 'bg-risk-low/10 text-risk-low border-risk-low/30',
  online: 'bg-risk-low/10 text-risk-low border-risk-low/30',
  degraded: 'bg-risk-medium/10 text-risk-medium border-risk-medium/30',
  offline: 'bg-risk-high/10 text-risk-high border-risk-high/30',
  info: 'bg-risk-info/10 text-risk-info border-risk-info/30',
  unknown: 'bg-text-muted/10 text-text-muted border-base-border',
}

const DOT = {
  running: 'bg-risk-low',
  online: 'bg-risk-low',
  degraded: 'bg-risk-medium',
  offline: 'bg-risk-high',
  info: 'bg-risk-info',
  unknown: 'bg-text-muted',
}

export default function StatusBadge({ status = 'unknown', label, pulse }) {
  const key = STYLES[status] ? status : 'unknown'
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-1 text-xs font-medium',
        STYLES[key],
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', DOT[key], pulse && 'animate-pulse')} />
      {label ?? status.replace(/_/g, ' ')}
    </span>
  )
}
