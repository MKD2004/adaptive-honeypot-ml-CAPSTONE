import { cn } from '../../lib/cn'

export default function MetricCard({ icon: Icon, label, value, sublabel, accent = 'default' }) {
  const accentCls = {
    default: 'text-accent',
    low: 'text-risk-low',
    medium: 'text-risk-medium',
    high: 'text-risk-high',
    critical: 'text-risk-critical',
  }[accent]

  return (
    <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-text-muted">{label}</span>
        {Icon && <Icon className={cn('h-4 w-4', accentCls)} strokeWidth={1.75} />}
      </div>
      <div className="mt-2 text-2xl font-semibold tabular-nums text-text-primary">{value}</div>
      {sublabel && <div className="mt-1 text-xs text-text-secondary">{sublabel}</div>}
    </div>
  )
}
