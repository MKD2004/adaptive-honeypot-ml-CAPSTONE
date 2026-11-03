import { Search, RotateCcw } from 'lucide-react'
import GlideSelect from '../common/GlideSelect'

const RISK_LEVELS = ['low', 'medium', 'high', 'critical']
const STATUSES = ['active', 'idle', 'closed']

export const SORT_OPTIONS = [
  { value: 'timestamp_desc', label: 'Most Recent' },
  { value: 'risk_desc', label: 'Highest Risk' },
  { value: 'confidence_desc', label: 'Highest Confidence' },
  { value: 'session_id_asc', label: 'Session ID (A–Z)' },
]

function cap(s) {
  return s.charAt(0).toUpperCase() + s.slice(1)
}

// Option lists for the GlideSelect dropdowns. "all" is always first so the
// unfiltered state is the top row and the highlight pill starts there.
const RISK_OPTIONS = [
  { value: 'all', label: 'All risk' },
  ...RISK_LEVELS.map((r) => ({ value: r, label: cap(r) })),
]

const STATUS_OPTIONS = [
  { value: 'all', label: 'All status' },
  ...STATUSES.map((s) => ({ value: s, label: cap(s) })),
]

// Frontend-only search/filter/sort controls for the Live Sessions table.
// Operates entirely on the mock session array passed in by the page — no
// backend call. Search matches Session ID, Source IP, micro-state, and
// protocol so "available session fields" beyond just ID/IP are searchable.
export default function SessionFilters({
  query, onQueryChange,
  risk, onRiskChange,
  phase, onPhaseChange,
  status, onStatusChange,
  sortBy, onSortByChange,
  phases,
  onClear,
  isFiltered,
}) {
  return (
    <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-border bg-card p-3">
      <div className="relative min-w-[220px] flex-1">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <input
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          placeholder="Search by Session ID, IP, or micro-state…"
          className="w-full rounded-md border border-border bg-muted/50 py-1.5 pl-8 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-chart-1 focus:outline-none"
        />
      </div>

      <GlideSelect
        options={RISK_OPTIONS}
        value={risk}
        onChange={onRiskChange}
        ariaLabel="Filter by risk"
        menuWidth={150}
      />

      <GlideSelect
        options={[
          { value: 'all', label: 'All phases' },
          ...phases.map((p) => ({ value: String(p.id), label: p.name, tag: `P${p.id}` })),
        ]}
        value={phase}
        onChange={onPhaseChange}
        ariaLabel="Filter by phase"
        menuWidth={220}
      />

      <GlideSelect
        options={STATUS_OPTIONS}
        value={status}
        onChange={onStatusChange}
        ariaLabel="Filter by status"
        menuWidth={150}
      />

      <GlideSelect
        options={SORT_OPTIONS}
        value={sortBy}
        onChange={onSortByChange}
        ariaLabel="Sort sessions"
        menuWidth={210}
        align="right"
      />

      {isFiltered && (
        <button
          onClick={onClear}
          className="flex items-center gap-1.5 rounded-md border border-border bg-muted/50 px-3 py-1.5 text-xs font-medium text-foreground/80 transition-colors hover:text-foreground"
        >
          <RotateCcw className="h-3.5 w-3.5" strokeWidth={1.75} />
          Clear Filters
        </button>
      )}
    </div>
  )
}
