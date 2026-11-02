import { Search } from 'lucide-react'
import EmptyState from '../common/EmptyState'
import { phaseName } from '../../lib/schema'

const selectCls =
  'rounded-md border border-base-border bg-base-raised px-2.5 py-1.5 text-sm text-text-primary ' +
  'focus:border-accent focus:outline-none'

// Search + phase filter across all 45 micro-states, with counts derived
// from the real mockLiveSessions array (see MitreAnalysisPage.jsx). `phase`
// is shared with KillChainOverview/PhaseDetailPanel so selecting a phase
// there also filters this table.
export default function MicroStateExplorer({ states, total, search, onSearchChange, phase, onPhaseChange, phases }) {
  return (
    <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-text-primary">Micro-State Explorer</h3>
        <span className="text-xs text-text-muted">{states.length} of 45</span>
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-3">
        <div className="relative min-w-[220px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-muted" />
          <input
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search micro-state or MITRE ID…"
            className="w-full rounded-md border border-base-border bg-base-raised py-1.5 pl-8 pr-3 text-sm text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
          />
        </div>
        <select value={phase} onChange={(e) => onPhaseChange(e.target.value)} className={selectCls} aria-label="Filter by phase">
          <option value="all">All phases</option>
          {phases.map((p) => (
            <option key={p.id} value={String(p.id)}>{p.name}</option>
          ))}
        </select>
      </div>

      {states.length === 0 ? (
        <EmptyState
          title="No micro-states match these filters"
          description="Try a different search term or clear the phase filter."
        />
      ) : (
        <div className="overflow-x-auto scrollbar-thin">
          <table className="w-full min-w-[640px] border-collapse text-sm">
            <thead>
              <tr className="border-b border-base-border text-left text-xs uppercase tracking-wide text-text-muted">
                <th className="py-2 pr-4 font-medium">Micro-State</th>
                <th className="py-2 pr-4 font-medium">MITRE</th>
                <th className="py-2 pr-4 font-medium">Phase</th>
                <th className="py-2 pr-4 font-medium">Sessions</th>
                <th className="py-2 pr-4 font-medium">% of dataset</th>
              </tr>
            </thead>
            <tbody>
              {states.map((s) => (
                <tr key={s.id} className="border-b border-base-borderMuted">
                  <td className="py-2.5 pr-4 font-mono text-xs text-accent">{s.label}</td>
                  <td className="py-2.5 pr-4 font-mono text-xs text-text-muted">{s.mitre}</td>
                  <td className="py-2.5 pr-4 text-text-secondary">{phaseName(s.phase)}</td>
                  <td className="py-2.5 pr-4 tabular-nums text-text-primary">{s.count}</td>
                  <td className="py-2.5 pr-4 tabular-nums text-text-muted">
                    {total ? `${((s.count / total) * 100).toFixed(1)}%` : '0%'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
