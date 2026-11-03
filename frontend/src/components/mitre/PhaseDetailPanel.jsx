export default function PhaseDetailPanel({ phase }) {
  return (
    <div className="rounded-2xl border border-border bg-card p-6 shadow-card">
      <div className="mb-3 flex items-baseline justify-between">
        <h3 className="text-base font-semibold text-foreground">
          Phase {phase.id} &middot; {phase.name}
        </h3>
        <span className="text-xs text-muted-foreground">
          {phase.count} session{phase.count === 1 ? '' : 's'} in the mock dataset
        </span>
      </div>

      {phase.states.length === 0 ? (
        <p className="text-xs text-muted-foreground">No micro-states defined for this phase.</p>
      ) : (
        <ul className="divide-y divide-border/60">
          {phase.states.map((s) => (
            <li key={s.id} className="flex items-center justify-between gap-3 py-2 text-sm">
              <div>
                <span className="font-mono text-xs text-chart-1">{s.label}</span>
                <span className="ml-2 font-mono text-[11px] text-muted-foreground">{s.mitre}</span>
              </div>
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span className="tabular-nums text-foreground/80">{s.count}</span>
                <span className="tabular-nums">
                  {phase.count ? `${((s.count / phase.count) * 100).toFixed(0)}%` : '0%'}
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
