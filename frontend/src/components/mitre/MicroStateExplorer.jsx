import { Search } from 'lucide-react'
import EmptyState from '../common/EmptyState'
import GlideSelect from '../common/GlideSelect'
import { phaseName } from '../../lib/schema'

// Search + phase filter across all 45 micro-states, with counts derived from
// the sessions MT3 has classified (see MitreAnalysisPage.jsx). `phase` is
// shared with KillChainOverview/PhaseDetailPanel so selecting a phase there
// also filters this table.
export default function MicroStateExplorer({ states, total, search, onSearchChange, phase, onPhaseChange, phases }) {
  return (
    <div className="rounded-2xl border border-border bg-card p-6 shadow-card">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-base font-semibold text-foreground">Micro-State Explorer</h3>
        <span className="text-xs text-muted-foreground">{states.length} of 45</span>
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-3">
        <div className="relative min-w-[220px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search micro-state or MITRE ID…"
            className="w-full rounded-md border border-border bg-muted/50 py-1.5 pl-8 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-chart-1 focus:outline-none"
          />
        </div>
        <GlideSelect
          options={[
            { value: 'all', label: 'All phases' },
            ...phases.map((p) => ({ value: String(p.id), label: p.name, tag: `P${p.id}` })),
          ]}
          value={phase}
          onChange={onPhaseChange}
          ariaLabel="Filter by phase"
          menuWidth={220}
          align="right"
        />
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
              <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                <th className="py-2 pr-4 font-medium">Micro-State</th>
                <th className="py-2 pr-4 font-medium">MITRE</th>
                <th className="py-2 pr-4 font-medium">Phase</th>
                <th className="py-2 pr-4 font-medium">Sessions</th>
                <th className="py-2 pr-4 font-medium">% of dataset</th>
              </tr>
            </thead>
            <tbody>
              {states.map((s) => (
                <tr key={s.id} className="border-b border-border/60">
                  <td className="py-2.5 pr-4 font-mono text-xs text-chart-1">{s.label}</td>
                  <td className="py-2.5 pr-4 font-mono text-xs text-muted-foreground">{s.mitre}</td>
                  <td className="py-2.5 pr-4 text-foreground/80">{phaseName(s.phase)}</td>
                  <td className="py-2.5 pr-4 tabular-nums text-foreground">{s.count}</td>
                  <td className="py-2.5 pr-4 tabular-nums text-muted-foreground">
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
