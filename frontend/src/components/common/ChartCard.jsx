export default function ChartCard({ title, subtitle, actions, children, height = 260 }) {
  return (
    <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
      <div className="mb-3 flex items-start justify-between">
        <div>
          <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
          {subtitle && <p className="mt-0.5 text-xs text-text-muted">{subtitle}</p>}
        </div>
        {actions}
      </div>
      <div style={{ height }}>{children}</div>
    </div>
  )
}
