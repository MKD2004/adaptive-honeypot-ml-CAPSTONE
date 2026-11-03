import { useMemo, useState } from 'react'
import { Radio, Activity, ShieldAlert, Gauge } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import MetricCard from '../components/common/MetricCard'
import StatusBadge from '../components/common/StatusBadge'
import EmptyState from '../components/common/EmptyState'
import DataSection from '../components/common/DataSection'
import SessionFilters from '../components/sessions/SessionFilters'
import SessionTable from '../components/sessions/SessionTable'
import { useApiResource, API_STATUS } from '../hooks/useApiResource'
import { getSessions, getSessionSummary } from '../services/sessions'
import { KILL_CHAIN_PHASES } from '../lib/schema'

const RISK_RANK = { critical: 3, high: 2, medium: 1, low: 0 }

function sortSessions(sessions, sortBy) {
  const sorted = [...sessions]
  switch (sortBy) {
    case 'risk_desc':
      return sorted.sort((a, b) => (RISK_RANK[b.risk] ?? -1) - (RISK_RANK[a.risk] ?? -1))
    case 'confidence_desc':
      return sorted.sort((a, b) => (b.confidence ?? -1) - (a.confidence ?? -1))
    case 'session_id_asc':
      return sorted.sort((a, b) => a.session_id.localeCompare(b.session_id))
    case 'timestamp_desc':
    default:
      return sorted.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
  }
}

const DEFAULT_SORT = 'timestamp_desc'

// Every session here is a CLOSED session: MT3 classifies only on
// cowrie.session.closed, because it needs the whole session for the temporal
// features. So the "Active Sessions" card reads 0 by design, and the status
// filter only ever has "closed" to match.
export default function LiveSessionsPage() {
  const [query, setQuery] = useState('')
  const [risk, setRisk] = useState('all')
  const [phase, setPhase] = useState('all')
  const [status, setStatus] = useState('all')
  const [sortBy, setSortBy] = useState(DEFAULT_SORT)

  const resource = useApiResource(getSessions, {
    deps: [],
    isEmpty: (data) => !data?.sessions?.length,
  })
  const sessions = resource.data?.sessions ?? []

  const isFiltered =
    query.trim() !== '' || risk !== 'all' || phase !== 'all' || status !== 'all' || sortBy !== DEFAULT_SORT

  const clearFilters = () => {
    setQuery('')
    setRisk('all')
    setPhase('all')
    setStatus('all')
    setSortBy(DEFAULT_SORT)
  }

  // Same helper the Dashboard uses, so the two pages' summary cards can
  // never disagree about what the session set contains.
  const summary = useMemo(() => getSessionSummary(sessions), [sessions])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    const matches = sessions.filter((s) => {
      if (
        q &&
        !(
          s.session_id.toLowerCase().includes(q) ||
          s.src_ip.includes(q) ||
          (s.micro_state ?? '').toLowerCase().includes(q) ||
          (s.protocol ?? '').toLowerCase().includes(q)
        )
      )
        return false
      if (risk !== 'all' && s.risk !== risk) return false
      if (phase !== 'all' && String(s.phase) !== phase) return false
      if (status !== 'all' && s.status !== status) return false
      return true
    })
    return sortSessions(matches, sortBy)
  }, [sessions, query, risk, phase, status, sortBy])

  const headerBadge =
    resource.status === API_STATUS.UNREACHABLE ? (
      <StatusBadge status="offline" label="Gateway Unreachable" />
    ) : (
      <StatusBadge status="running" label="Live: GET /api/live-feed" />
    )

  return (
    <div>
      <PageHeader
        title="Live Sessions"
        subtitle="Attacker sessions classified by MT3, newest first. A session is classified once it closes."
        actions={headerBadge}
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <MetricCard
          icon={Radio}
          label="Active Sessions"
          value={summary.active}
          sublabel="MT3 classifies on close"
        />
        <MetricCard icon={Activity} label="Sessions Classified" value={summary.total} sublabel="in this window" />
        <MetricCard
          icon={ShieldAlert}
          label="High Risk"
          value={summary.highRisk}
          sublabel="phase 4+ classifications"
          accent="high"
        />
        <MetricCard
          icon={Gauge}
          label="Avg. Confidence"
          value={`${(summary.avgConfidence * 100).toFixed(1)}%`}
          sublabel="MT3, d=256"
        />
      </div>

      <SessionFilters
        query={query}
        onQueryChange={setQuery}
        risk={risk}
        onRiskChange={setRisk}
        phase={phase}
        onPhaseChange={setPhase}
        status={status}
        onStatusChange={setStatus}
        sortBy={sortBy}
        onSortByChange={setSortBy}
        phases={KILL_CHAIN_PHASES}
        onClear={clearFilters}
        isFiltered={isFiltered}
      />

      <div className="rounded-2xl border border-border bg-card p-6 shadow-card">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-base font-semibold text-foreground">Sessions</h3>
          <span className="text-xs text-muted-foreground">
            {filtered.length} of {sessions.length}
          </span>
        </div>
        <DataSection
          resource={resource}
          loadingLabel="Loading sessions…"
          emptyTitle="No sessions classified yet"
          emptyDescription="logs/pipeline_results.jsonl is empty — run the pipeline with python -m traffic_gateway.run_pipeline and send a session to the honeypot."
        >
          {filtered.length === 0 ? (
            <EmptyState
              title="No sessions match these filters"
              description="Clear the search box or reset the filters above to see every classified session."
            />
          ) : (
            <SessionTable sessions={filtered} variant="full" />
          )}
        </DataSection>
      </div>
    </div>
  )
}
