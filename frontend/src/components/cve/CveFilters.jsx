import { Search, RotateCcw } from 'lucide-react'
import GlideSelect from '../common/GlideSelect'

export const SEVERITY_LEVELS = ['Critical', 'High', 'Medium']

export const SORT_OPTIONS = [
  { value: 'cvss_desc', label: 'CVSS Score (High → Low)' },
  { value: 'published_desc', label: 'Published (Newest)' },
  { value: 'published_asc', label: 'Published (Oldest)' },
  { value: 'cve_id_asc', label: 'CVE ID (A–Z)' },
]

const SEVERITY_OPTIONS = [
  { value: 'all', label: 'All severity' },
  ...SEVERITY_LEVELS.map((s) => ({ value: s, label: s })),
]

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
    <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-border bg-card p-3">
      <div className="relative min-w-[220px] flex-1">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <input
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          placeholder="Search CVE ID, description, or KEV name…"
          className="w-full rounded-md border border-border bg-muted/50 py-1.5 pl-8 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-chart-1 focus:outline-none"
        />
      </div>

      <GlideSelect
        options={SEVERITY_OPTIONS}
        value={severity}
        onChange={onSeverityChange}
        ariaLabel="Filter by severity"
        menuWidth={160}
      />

      <label className="flex items-center gap-2 rounded-md border border-border bg-muted/50 px-2.5 py-1.5 text-sm text-foreground/80">
        <input
          type="checkbox"
          checked={kevOnly}
          onChange={(e) => onKevOnlyChange(e.target.checked)}
          className="h-3.5 w-3.5 accent-chart-1"
        />
        Known Exploited (CISA KEV) only
      </label>

      <GlideSelect
        options={SORT_OPTIONS}
        value={sortBy}
        onChange={onSortByChange}
        ariaLabel="Sort CVEs"
        menuWidth={230}
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
