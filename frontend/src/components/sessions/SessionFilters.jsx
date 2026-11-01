import { Search, RotateCcw } from 'lucide-react'

const RISK_LEVELS = ['low', 'medium', 'high', 'critical']
const STATUSES = ['active', 'idle', 'closed']

export const SORT_OPTIONS = [
  { value: 'timestamp_desc', label: 'Most Recent' },
  { value: 'risk_desc', label: 'Highest Risk' },
  { value: 'confidence_desc', label: 'Highest Confidence' },
  { value: 'session_id_asc', label: 'Session ID (A–Z)' },
]

const selectCls =
  'rounded-md border border-base-border bg-base-raised px-2.5 py-1.5 text-sm text-text-primary ' +
  'focus:border-accent focus:outline-none'

function cap(s) {
  return s.charAt(0).toUpperCase() + s.slice(1)
}

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
    <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-base-border bg-base-surface p-3">
      <div className="relative min-w-[220px] flex-1">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-muted" />
        <input
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          placeholder="Search by Session ID, IP, or micro-state…"
          className="w-full rounded-md border border-base-border bg-base-raised py-1.5 pl-8 pr-3 text-sm text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
        />
      </div>

      <select value={risk} onChange={(e) => onRiskChange(e.target.value)} className={selectCls} aria-label="Filter by risk">
        <option value="all">All risk</option>
        {RISK_LEVELS.map((r) => (
          <option key={r} value={r}>{cap(r)}</option>
        ))}
      </select>

      <select value={phase} onChange={(e) => onPhaseChange(e.target.value)} className={selectCls} aria-label="Filter by phase">
        <option value="all">All phases</option>
        {phases.map((p) => (
          <option key={p.id} value={String(p.id)}>{p.name}</option>
        ))}
      </select>

      <select value={status} onChange={(e) => onStatusChange(e.target.value)} className={selectCls} aria-label="Filter by status">
        <option value="all">All status</option>
        {STATUSES.map((s) => (
          <option key={s} value={s}>{cap(s)}</option>
        ))}
      </select>

      <select value={sortBy} onChange={(e) => onSortByChange(e.target.value)} className={selectCls} aria-label="Sort sessions">
        {SORT_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>Sort: {o.label}</option>
        ))}
      </select>

      {isFiltered && (
        <button
          onClick={onClear}
          className="flex items-center gap-1.5 rounded-md border border-base-border bg-base-raised px-3 py-1.5 text-xs font-medium text-text-secondary transition-colors hover:text-text-primary"
        >
          <RotateCcw className="h-3.5 w-3.5" strokeWidth={1.75} />
          Clear Filters
        </button>
      )}
    </div>
  )
}
