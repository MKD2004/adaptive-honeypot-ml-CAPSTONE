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
import { KILL_CHAIN_PHASES } from '../lib/schema'
import {
  MICRO_STATE_ANALYTICS,
  TOTAL_ANALYZED_SESSIONS,
  HIGH_CONFIDENCE_TOTAL,
  HIGH_CONFIDENCE_THRESHOLD,
  OVERALL_AVG_CONFIDENCE,
  CONFIDENCE_BUCKET_DEFS,
} from '../data/mockAnalytics'

export default function ThreatAnalyticsPage() {
  const [search, setSearch] = useState('')
  const [phase, setPhase] = useState('all')
  const [confidenceBucket, setConfidenceBucket] = useState('all')

  const isFiltered = search.trim() !== '' || phase !== 'all' || confidenceBucket !== 'all'

  const resetFilters = () => {
    setSearch('')
    setPhase('all')
    setConfidenceBucket('all')
  }

  const filteredStates = useMemo(() => {
    const q = search.trim().toLowerCase()
    const bucket = CONFIDENCE_BUCKET_DEFS.find((b) => b.label === confidenceBucket)
    return MICRO_STATE_ANALYTICS.filter((s) => {
      if (phase !== 'all' && String(s.phase) !== phase) return false
      if (bucket && !(s.avgConfidence >= bucket.min && s.avgConfidence < bucket.max)) return false
      if (q && !(s.label.toLowerCase().includes(q) || s.mitre.toLowerCase().includes(q))) return false
      return true
    })
  }, [search, phase, confidenceBucket])

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

  const confidenceBuckets = useMemo(
    () =>
      CONFIDENCE_BUCKET_DEFS.map((b) => ({
        ...b,
        count: filteredStates
          .filter((s) => s.avgConfidence >= b.min && s.avgConfidence < b.max)
          .reduce((sum, s) => sum + s.count, 0),
      })),
    [filteredStates],
  )

  return (
    <div>
      <PageHeader
        title="Threat Analytics"
        subtitle="Simulated per-micro-state prediction analytics — 45 micro-states, 128 features, model comparison"
        actions={<StatusBadge status="mock" label="Simulated Data" />}
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <MetricCard
          icon={Layers}
          label="Total Analyzed Sessions"
          value={isFiltered ? filteredTotal : TOTAL_ANALYZED_SESSIONS}
          sublabel={isFiltered ? `of ${TOTAL_ANALYZED_SESSIONS} simulated` : 'simulated, deterministic'}
        />
        <MetricCard
          icon={ShieldCheck}
          label="High-Confidence Predictions"
          value={isFiltered ? filteredHighConfidence : HIGH_CONFIDENCE_TOTAL}
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
          value={`${((isFiltered ? filteredAvgConfidence : OVERALL_AVG_CONFIDENCE) * 100).toFixed(1)}%`}
          sublabel="simulated probability, not verified accuracy"
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
          subtitle="Simulated session counts per phase — click a bar to filter"
        >
          <PhaseAnalyticsChart data={phaseChartData} selectedPhase={phase} onSelectPhase={setPhase} />
        </ChartCard>
        <ChartCard
          title="Confidence Distribution"
          subtitle="Simulated model probability buckets — not a measure of correctness"
        >
          <ConfidenceHistogram buckets={confidenceBuckets} />
        </ChartCard>
      </div>

      <div className="mb-6 rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
        <h3 className="mb-3 text-sm font-semibold text-text-primary">Micro-State Analysis</h3>
        {filteredStates.length === 0 ? (
          <EmptyState
            title="No micro-states match these filters"
            description="Clear the search box or reset the filters above."
          />
        ) : (
          <MicroStateAnalyticsTable rows={filteredStates} total={filteredTotal} />
        )}
      </div>

      <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
        <h3 className="mb-3 text-sm font-semibold text-text-primary">Feature Group Overview</h3>
        <FeatureGroupOverview />
      </div>
    </div>
  )
}
