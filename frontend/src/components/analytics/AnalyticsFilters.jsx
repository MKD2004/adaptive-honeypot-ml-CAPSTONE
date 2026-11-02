import { Search, RotateCcw } from 'lucide-react'

const selectCls =
  'rounded-md border border-base-border bg-base-raised px-2.5 py-1.5 text-sm text-text-primary ' +
  'focus:border-accent focus:outline-none'

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
    <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-base-border bg-base-surface p-3">
      <div className="relative min-w-[220px] flex-1">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-muted" />
        <input
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search micro-state or MITRE ID…"
          className="w-full rounded-md border border-base-border bg-base-raised py-1.5 pl-8 pr-3 text-sm text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
        />
      </div>

      <select value={phase} onChange={(e) => onPhaseChange(e.target.value)} className={selectCls} aria-label="Filter by kill-chain phase">
        <option value="all">All phases</option>
        {phases.map((p) => (
          <option key={p.id} value={String(p.id)}>{p.name}</option>
        ))}
      </select>

      <select
        value={confidenceBucket}
        onChange={(e) => onConfidenceBucketChange(e.target.value)}
        className={selectCls}
        aria-label="Filter by confidence range"
      >
        <option value="all">All confidence levels</option>
        {confidenceBuckets.map((b) => (
          <option key={b.label} value={b.label}>{b.label} confidence</option>
        ))}
      </select>

      {isFiltered && (
        <button
          onClick={onReset}
          className="flex items-center gap-1.5 rounded-md border border-base-border bg-base-raised px-3 py-1.5 text-xs font-medium text-text-secondary transition-colors hover:text-text-primary"
        >
          <RotateCcw className="h-3.5 w-3.5" strokeWidth={1.75} />
          Reset Filters
        </button>
      )}
    </div>
  )
}
