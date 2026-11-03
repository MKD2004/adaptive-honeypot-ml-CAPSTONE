export default function PhaseDetailPanel({ phase }) {
  return (
    <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
      <div className="mb-3 flex items-baseline justify-between">
        <h3 className="text-sm font-semibold text-text-primary">
          Phase {phase.id} &middot; {phase.name}
        </h3>
        <span className="text-xs text-text-muted">
          {phase.count} classified session{phase.count === 1 ? '' : 's'}
        </span>
      </div>

      {phase.states.length === 0 ? (
        <p className="text-xs text-text-muted">No micro-states defined for this phase.</p>
      ) : (
        <ul className="divide-y divide-base-borderMuted">
          {phase.states.map((s) => (
            <li key={s.id} className="flex items-center justify-between gap-3 py-2 text-sm">
              <div>
                <span className="font-mono text-xs text-accent">{s.label}</span>
                <span className="ml-2 font-mono text-[11px] text-text-muted">{s.mitre}</span>
              </div>
              <div className="flex items-center gap-3 text-xs text-text-muted">
                <span className="tabular-nums text-text-secondary">{s.count}</span>
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
