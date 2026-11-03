import { useMemo, useState } from 'react'
import { Layers, ShieldCheck, TrendingUp, Gauge } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import MetricCard from '../components/common/MetricCard'
import ChartCard from '../components/common/ChartCard'
import StatusBadge from '../components/common/StatusBadge'
import EmptyState from '../components/common/EmptyState'
import AnalyticsFilters from '../components/analytics/AnalyticsFilters'
import PhaseAnalyticsChart from '../components/analytics/PhaseAnalyticsChart'
import ConfidenceHistogram from '../components/analytics/ConfidenceHistogram'
import MicroStateAnalyticsTable from '../components/analytics/MicroStateAnalyticsTable'
import FeatureGroupOverview from '../components/analytics/FeatureGroupOverview'
import DataSection from '../components/common/DataSection'
import { useApiResource, API_STATUS } from '../hooks/useApiResource'
import { getSessions } from '../services/sessions'
import {
  microStateAnalytics,
  analyticsTotals,
  confidenceBuckets as bucketSessions,
  HIGH_CONFIDENCE_THRESHOLD,
  CONFIDENCE_BUCKET_DEFS,
} from '../services/analytics'
import { KILL_CHAIN_PHASES } from '../lib/schema'

// Per-micro-state analytics over the sessions MT3 has actually classified.
// All 45 states always appear, most at zero: that is the honest picture, not
// a gap to be filled in with simulated counts.
export default function ThreatAnalyticsPage() {
  const [search, setSearch] = useState('')
  const [phase, setPhase] = useState('all')
  const [confidenceBucket, setConfidenceBucket] = useState('all')

  const resource = useApiResource(getSessions, {
    deps: [],
    isEmpty: (data) => !data?.sessions?.length,
  })
  const sessions = resource.data?.sessions ?? []
  const allStates = useMemo(() => microStateAnalytics(sessions), [sessions])
  const totals = useMemo(() => analyticsTotals(sessions), [sessions])

  const isFiltered = search.trim() !== '' || phase !== 'all' || confidenceBucket !== 'all'

  const resetFilters = () => {
    setSearch('')
    setPhase('all')
    setConfidenceBucket('all')
  }

  const filteredStates = useMemo(() => {
    const q = search.trim().toLowerCase()
    const bucket = CONFIDENCE_BUCKET_DEFS.find((b) => b.label === confidenceBucket)
    return allStates.filter((s) => {
      if (phase !== 'all' && String(s.phase) !== phase) return false
      if (bucket && !(s.avgConfidence >= bucket.min && s.avgConfidence < bucket.max)) return false
      if (q && !(s.label.toLowerCase().includes(q) || s.mitre.toLowerCase().includes(q))) return false
      return true
    })
  }, [allStates, search, phase, confidenceBucket])

  const filteredTotal = filteredStates.reduce((sum, s) => sum + s.count, 0)
  const filteredHighConfidence = filteredStates.reduce((sum, s) => sum + s.highConfidenceCount, 0)
  const filteredAvgConfidence = filteredTotal
    ? filteredStates.reduce((sum, s) => sum + s.avgConfidence * s.count, 0) / filteredTotal
    : 0

  const phaseChartData = useMemo(
    () =>
      KILL_CHAIN_PHASES.map((p) => {
        const states = filteredStates.filter((s) => s.phase === p.id)
        const count = states.reduce((sum, s) => sum + s.count, 0)
        const avgConfidence = count
          ? states.reduce((sum, s) => sum + s.avgConfidence * s.count, 0) / count
          : 0
        return { ...p, count, avgConfidence }
      }),
    [filteredStates],
  )

  const mostActivePhase = phaseChartData.reduce(
    (best, p) => (p.count > (best?.count ?? -1) ? p : best),
    null,
  )

  // Buckets each session's own confidence, not per-state averages, so the
  // histogram counts observations rather than inferring them from a mean.
  const histogramBuckets = useMemo(() => {
    const shown = new Set(filteredStates.map((s) => s.label))
    return bucketSessions(sessions.filter((s) => shown.has(s.micro_state)))
  }, [sessions, filteredStates])

  return (
    <div>
      <PageHeader
        title="Threat Analytics"
        subtitle="Per-micro-state prediction analytics over classified sessions — 45 micro-states, 128 features"
        actions={
          resource.status === API_STATUS.UNREACHABLE ? (
            <StatusBadge status="offline" label="Gateway Unreachable" />
          ) : (
            <StatusBadge status="running" label="Live: GET /api/live-feed" />
          )
        }
      />

      <DataSection
        resource={resource}
        loadingLabel="Loading analytics…"
        emptyTitle="No sessions classified yet"
        emptyDescription="logs/pipeline_results.jsonl is empty — run the pipeline and send a session to the honeypot to populate these charts."
      >

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <MetricCard
          icon={Layers}
          label="Sessions Classified"
          value={isFiltered ? filteredTotal : totals.total}
          sublabel={isFiltered ? `of ${totals.total} classified` : `${totals.statesObserved} of 45 states observed`}
        />
        <MetricCard
          icon={ShieldCheck}
          label="High-Confidence Predictions"
          value={isFiltered ? filteredHighConfidence : totals.highConfidenceTotal}
          sublabel={`≥${(HIGH_CONFIDENCE_THRESHOLD * 100).toFixed(0)}% confidence`}
        />
        <MetricCard
          icon={TrendingUp}
          label="Most Active Phase"
          value={mostActivePhase?.count ? mostActivePhase.name : '—'}
          sublabel={
            mostActivePhase?.count && filteredTotal
              ? `${((mostActivePhase.count / filteredTotal) * 100).toFixed(0)}% of shown sessions`
              : 'no data in filter'
          }
        />
        <MetricCard
          icon={Gauge}
          label="Average Model Confidence"
          value={`${((isFiltered ? filteredAvgConfidence : totals.avgConfidence) * 100).toFixed(1)}%`}
          sublabel="softmax probability, not verified accuracy"
        />
      </div>

      <AnalyticsFilters
        search={search}
        onSearchChange={setSearch}
        phase={phase}
        onPhaseChange={setPhase}
        confidenceBucket={confidenceBucket}
        onConfidenceBucketChange={setConfidenceBucket}
        phases={KILL_CHAIN_PHASES}
        confidenceBuckets={CONFIDENCE_BUCKET_DEFS}
        onReset={resetFilters}
        isFiltered={isFiltered}
      />

      <div className="mb-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <ChartCard
          title="Threat Distribution by Kill-Chain Phase"
          subtitle="Classified session counts per phase — click a bar to filter"
        >
          <PhaseAnalyticsChart data={phaseChartData} selectedPhase={phase} onSelectPhase={setPhase} />
        </ChartCard>
        <ChartCard
          title="Confidence Distribution"
          subtitle="MT3 confidence per session — not a measure of correctness"
        >
          <ConfidenceHistogram buckets={histogramBuckets} />
        </ChartCard>
      </div>

      <div className="mb-6 rounded-2xl border border-border bg-card p-6 shadow-card">
        <h3 className="mb-4 text-base font-semibold text-foreground">Micro-State Analysis</h3>
        {filteredStates.length === 0 ? (
          <EmptyState
            title="No micro-states match these filters"
            description="Clear the search box or reset the filters above."
          />
        ) : (
          <MicroStateAnalyticsTable rows={filteredStates} total={filteredTotal} />
        )}
      </div>

      </DataSection>

      <div className="rounded-2xl border border-border bg-card p-6 shadow-card">
        <h3 className="mb-4 text-base font-semibold text-foreground">Feature Group Overview</h3>
        <FeatureGroupOverview />
      </div>
    </div>
  )
}
