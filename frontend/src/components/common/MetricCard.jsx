import { cn } from '../../lib/cn'
import Panel from './Panel'

// The Pulse console's metric card: a tinted rounded-xl icon tile top-left, an
// optional note top-right, then the value and its label. The icon tile's tint
// is what carries the severity, so the number itself stays foreground-coloured
// and the four cards in a row read as one object.
const TONE = {
  default: { fg: 'text-chart-1', bg: 'bg-chart-1/10' },
  info: { fg: 'text-info', bg: 'bg-info/10' },
  low: { fg: 'text-success', bg: 'bg-success/10' },
  medium: { fg: 'text-chart-4', bg: 'bg-chart-4/15' },
  high: { fg: 'text-destructive', bg: 'bg-destructive/10' },
  critical: { fg: 'text-destructive', bg: 'bg-destructive/15' },
}

export default function MetricCard({ icon: Icon, label, value, sublabel, accent = 'default', note }) {
  const tone = TONE[accent] ?? TONE.default

  return (
    <Panel padding="p-5">
      <div className="mb-3 flex items-start justify-between">
        {Icon && (
          <div className={cn('rounded-xl p-2.5', tone.bg)}>
            <Icon className={cn('h-5 w-5', tone.fg)} strokeWidth={1.75} />
          </div>
        )}
        {note && <span className="text-xs font-medium text-muted-foreground">{note}</span>}
      </div>
      <p className="mb-1 text-2xl font-semibold tabular-nums text-foreground">{value}</p>
      <p className="text-sm text-muted-foreground">{label}</p>
      {sublabel && <p className="mt-1 text-xs text-muted-foreground/80">{sublabel}</p>}
    </Panel>
  )
}
