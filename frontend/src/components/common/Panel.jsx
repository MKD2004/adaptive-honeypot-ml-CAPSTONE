import { cn } from '../../lib/cn'

// Every surface in the Pulse console is this: a white card, rounded-2xl, a
// hairline border and the layered shadow (defined once as --shadow-card in
// index.css, where that design sets it inline on each card).
export default function Panel({ className, padding = 'p-6', children, hover = false }) {
  return (
    <div
      className={cn(
        'rounded-2xl border border-border bg-card shadow-card',
        hover && 'card-hover',
        padding,
        className,
      )}
    >
      {children}
    </div>
  )
}

// Matching section heading: title + optional subtitle on the left, legend or
// action on the right.
export function PanelHeader({ title, subtitle, right, className }) {
  return (
    <div className={cn('mb-6 flex items-start justify-between gap-4', className)}>
      <div className="min-w-0">
        <h3 className="text-base font-semibold text-foreground">{title}</h3>
        {subtitle && <p className="text-sm text-muted-foreground">{subtitle}</p>}
      </div>
      {right && <div className="flex shrink-0 items-center gap-4 text-sm">{right}</div>}
    </div>
  )
}

// The small round-dot legend the design uses above its charts.
export function LegendDot({ color, label }) {
  return (
    <div className="flex items-center gap-2">
      <div className={cn('h-3 w-3 rounded-full', color)} />
      <span className="text-muted-foreground">{label}</span>
    </div>
  )
}
