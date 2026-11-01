import { Search, RotateCcw } from 'lucide-react'

export const SEVERITY_LEVELS = ['Critical', 'High', 'Medium']

export const SORT_OPTIONS = [
  { value: 'cvss_desc', label: 'CVSS Score (High → Low)' },
  { value: 'published_desc', label: 'Published (Newest)' },
  { value: 'published_asc', label: 'Published (Oldest)' },
  { value: 'cve_id_asc', label: 'CVE ID (A–Z)' },
]

const selectCls =
  'rounded-md border border-base-border bg-base-raised px-2.5 py-1.5 text-sm text-text-primary ' +
  'focus:border-accent focus:outline-none'

// Frontend-only search/filter/sort controls for the CVE Intelligence page.
// Operates entirely on the static sample array in data/mockCves.js.
export default function CveFilters({
  query, onQueryChange,
  severity, onSeverityChange,
  kevOnly, onKevOnlyChange,
  sortBy, onSortByChange,
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
          placeholder="Search CVE ID, description, or KEV name…"
          className="w-full rounded-md border border-base-border bg-base-raised py-1.5 pl-8 pr-3 text-sm text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
        />
      </div>

      <select value={severity} onChange={(e) => onSeverityChange(e.target.value)} className={selectCls} aria-label="Filter by severity">
        <option value="all">All severity</option>
        {SEVERITY_LEVELS.map((s) => (
          <option key={s} value={s}>{s}</option>
        ))}
      </select>

      <label className="flex items-center gap-2 rounded-md border border-base-border bg-base-raised px-2.5 py-1.5 text-sm text-text-secondary">
        <input
          type="checkbox"
          checked={kevOnly}
          onChange={(e) => onKevOnlyChange(e.target.checked)}
          className="h-3.5 w-3.5 accent-accent"
        />
        Known Exploited (CISA KEV) only
      </label>

      <select value={sortBy} onChange={(e) => onSortByChange(e.target.value)} className={selectCls} aria-label="Sort CVEs">
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
