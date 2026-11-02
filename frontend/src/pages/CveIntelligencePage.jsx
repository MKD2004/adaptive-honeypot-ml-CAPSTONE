import { useMemo, useState } from 'react'
import { Database, ShieldAlert, AlertTriangle, Clock } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import MetricCard from '../components/common/MetricCard'
import StatusBadge from '../components/common/StatusBadge'
import EmptyState from '../components/common/EmptyState'
import CveFilters from '../components/cve/CveFilters'
import CveTable from '../components/cve/CveTable'
import {
  mockCves,
  CVE_DATA_SNAPSHOT_NOTE,
  TOTAL_CVES,
  CRITICAL_CVE_COUNT,
  HIGH_CVE_COUNT,
  RECENT_CVE_COUNT,
  RECENT_WINDOW_LABEL,
} from '../data/mockCves'

const DEFAULT_SORT = 'cvss_desc'

function sortCves(cves, sortBy) {
  const sorted = [...cves]
  switch (sortBy) {
    case 'published_desc':
      return sorted.sort((a, b) => new Date(b.published) - new Date(a.published))
    case 'published_asc':
      return sorted.sort((a, b) => new Date(a.published) - new Date(b.published))
    case 'cve_id_asc':
      return sorted.sort((a, b) => a.cve_id.localeCompare(b.cve_id))
    case 'cvss_desc':
    default:
      return sorted.sort((a, b) => b.cvss_score - a.cvss_score)
  }
}

export default function CveIntelligencePage() {
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [kevOnly, setKevOnly] = useState(false)
  const [sortBy, setSortBy] = useState(DEFAULT_SORT)

  const isFiltered = query.trim() !== '' || severity !== 'all' || kevOnly || sortBy !== DEFAULT_SORT

  const clearFilters = () => {
    setQuery('')
    setSeverity('all')
    setKevOnly(false)
    setSortBy(DEFAULT_SORT)
  }

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    const matches = mockCves.filter((c) => {
      if (
        q &&
        !(
          c.cve_id.toLowerCase().includes(q) ||
          c.description.toLowerCase().includes(q) ||
          c.kev_name.toLowerCase().includes(q)
        )
      )
        return false
      if (severity !== 'all' && c.severity !== severity) return false
      if (kevOnly && !c.is_kev) return false
      return true
    })
    return sortCves(matches, sortBy)
  }, [query, severity, kevOnly, sortBy])

  return (
    <div>
      <PageHeader
        title="CVE Intelligence"
        subtitle="Sample vulnerability dataset — NVD / CISA KEV records copied from cve_intelligence/'s own pipeline output"
        actions={<StatusBadge status="mock" label="Sample Data" />}
      />

      <p className="mb-6 text-xs text-text-muted">{CVE_DATA_SNAPSHOT_NOTE}</p>

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <MetricCard icon={Database} label="Total CVE Records" value={TOTAL_CVES} sublabel="sample dataset" />
        <MetricCard
          icon={ShieldAlert}
          label="Critical Severity"
          value={CRITICAL_CVE_COUNT}
          sublabel={`of ${TOTAL_CVES} in sample`}
          accent="critical"
        />
        <MetricCard
          icon={AlertTriangle}
          label="High Severity"
          value={HIGH_CVE_COUNT}
          sublabel={`of ${TOTAL_CVES} in sample`}
          accent="high"
        />
        <MetricCard
          icon={Clock}
          label="Recently Updated"
          value={RECENT_CVE_COUNT}
          sublabel={RECENT_WINDOW_LABEL}
        />
      </div>

      <CveFilters
        query={query}
        onQueryChange={setQuery}
        severity={severity}
        onSeverityChange={setSeverity}
        kevOnly={kevOnly}
        onKevOnlyChange={setKevOnly}
        sortBy={sortBy}
        onSortByChange={setSortBy}
        onClear={clearFilters}
        isFiltered={isFiltered}
      />

      <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-text-primary">CVE Records</h3>
          <span className="text-xs text-text-muted">{filtered.length} of {TOTAL_CVES}</span>
        </div>
        {filtered.length === 0 ? (
          <EmptyState
            title="No CVE records match these filters"
            description="Clear the search box or reset the filters above to see the full sample dataset."
          />
        ) : (
          <CveTable cves={filtered} />
        )}
      </div>
    </div>
  )
}
