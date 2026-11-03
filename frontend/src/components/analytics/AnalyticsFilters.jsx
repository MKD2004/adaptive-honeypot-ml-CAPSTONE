import { Search, RotateCcw } from 'lucide-react'
import GlideSelect from '../common/GlideSelect'

// Frontend-only filter controls for the Threat Analytics page. Filters the
// already-fetched analytics in memory — no backend call of its own.
export default function AnalyticsFilters({
  search, onSearchChange,
  phase, onPhaseChange,
  confidenceBucket, onConfidenceBucketChange,
  phases,
  confidenceBuckets,
  onReset,
  isFiltered,
}) {
  return (
    <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-border bg-card p-3">
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
        ariaLabel="Filter by kill-chain phase"
        menuWidth={220}
      />

      <GlideSelect
        options={[
          { value: 'all', label: 'All confidence' },
          ...confidenceBuckets.map((b) => ({ value: b.label, label: `${b.label} confidence` })),
        ]}
        value={confidenceBucket}
        onChange={onConfidenceBucketChange}
        ariaLabel="Filter by confidence range"
        menuWidth={200}
        align="right"
      />

      {isFiltered && (
        <button
          onClick={onReset}
          className="flex items-center gap-1.5 rounded-md border border-border bg-muted/50 px-3 py-1.5 text-xs font-medium text-foreground/80 transition-colors hover:text-foreground"
        >
          <RotateCcw className="h-3.5 w-3.5" strokeWidth={1.75} />
          Reset Filters
        </button>
      )}
    </div>
  )
}
