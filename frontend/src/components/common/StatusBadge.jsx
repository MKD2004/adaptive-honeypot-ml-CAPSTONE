import { cn } from '../../lib/cn'

// Borderless tinted pills, matching the Pulse console's badges.
const STYLES = {
  running: 'bg-success/10 text-success',
  online: 'bg-success/10 text-success',
  active: 'bg-success/10 text-success',
  closed: 'bg-muted text-muted-foreground',
  idle: 'bg-muted text-muted-foreground',
  degraded: 'bg-warning/15 text-warning',
  offline: 'bg-destructive/10 text-destructive',
  stopped: 'bg-destructive/10 text-destructive',
  // Honest "this is demo data, not a live reading" indicator — used instead
  // of a green "online"/"running" badge anywhere the backend isn't wired up.
  mock: 'bg-info/10 text-info',
  unknown: 'bg-muted text-muted-foreground',
  not_implemented: 'bg-muted text-muted-foreground',
}

const DOT = {
  running: 'bg-success',
  online: 'bg-success',
  active: 'bg-success',
  closed: 'bg-muted-foreground',
  idle: 'bg-muted-foreground',
  degraded: 'bg-warning',
  offline: 'bg-destructive',
  stopped: 'bg-destructive',
  mock: 'bg-info',
  unknown: 'bg-muted-foreground',
  not_implemented: 'bg-muted-foreground',
}

export default function StatusBadge({ status = 'unknown', label }) {
  const key = STYLES[status] ? status : 'unknown'
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium',
        STYLES[key],
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', DOT[key])} />
      {label ?? status.replace(/_/g, ' ')}
    </span>
  )
}
