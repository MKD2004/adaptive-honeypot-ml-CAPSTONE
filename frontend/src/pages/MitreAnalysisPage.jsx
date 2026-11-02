import { useMemo, useState } from 'react'
import PageHeader from '../components/common/PageHeader'
import StatusBadge from '../components/common/StatusBadge'
import KillChainOverview from '../components/mitre/KillChainOverview'
import PhaseDetailPanel from '../components/mitre/PhaseDetailPanel'
import MicroStateExplorer from '../components/mitre/MicroStateExplorer'
import TaxonomyExplanation from '../components/mitre/TaxonomyExplanation'
import DataSection from '../components/common/DataSection'
import { useApiResource, API_STATUS } from '../hooks/useApiResource'
import { getSessions } from '../services/sessions'
import { KILL_CHAIN_PHASES, MICRO_STATES } from '../lib/schema'

// Counts straight from the sessions MT3 has actually classified
// (GET /api/live-feed). Most of the 45 micro-states will show 0: that is real
// information — this machine's sessions never reached them — not a bug. The
// 45 rows always render so the taxonomy stays visible even at zero coverage.
export default function MitreAnalysisPage() {
  const [selectedPhase, setSelectedPhase] = useState('all')
  const [search, setSearch] = useState('')

  const resource = useApiResource(getSessions, {
    deps: [],
    isEmpty: (data) => !data?.sessions?.length,
  })
  const sessions = resource.data?.sessions ?? []

  const phaseCounts = useMemo(() => {
    const counts = new Array(KILL_CHAIN_PHASES.length).fill(0)
    sessions.forEach((s) => {
      if (counts[s.phase] !== undefined) counts[s.phase] += 1
    })
    return counts
  }, [sessions])

  const microStateCounts = useMemo(() => {
    const counts = {}
    sessions.forEach((s) => {
      if (s.micro_state) counts[s.micro_state] = (counts[s.micro_state] || 0) + 1
    })
    return counts
  }, [sessions])

  const statesWithCounts = useMemo(
    () => MICRO_STATES.map((s) => ({ ...s, count: microStateCounts[s.label] || 0 })),
    [microStateCounts],
  )

  const phasesWithCounts = useMemo(
    () =>
      KILL_CHAIN_PHASES.map((p) => ({
        ...p,
        count: phaseCounts[p.id],
        states: statesWithCounts.filter((s) => s.phase === p.id),
      })),
    [phaseCounts, statesWithCounts],
  )

  const filteredStates = useMemo(() => {
    const q = search.trim().toLowerCase()
    return statesWithCounts.filter((s) => {
      if (selectedPhase !== 'all' && String(s.phase) !== selectedPhase) return false
      if (q && !(s.label.toLowerCase().includes(q) || s.mitre.toLowerCase().includes(q))) return false
      return true
    })
  }, [statesWithCounts, selectedPhase, search])

  const selectedPhaseData =
    selectedPhase !== 'all' ? phasesWithCounts.find((p) => String(p.id) === selectedPhase) : null

  return (
    <div>
      <PageHeader
        title="MITRE Analysis"
        subtitle="Kill-chain phases and micro-state coverage, counted from the sessions MT3 has classified"
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
        loadingLabel="Loading classifications…"
        emptyTitle="No sessions classified yet"
        emptyDescription="logs/pipeline_results.jsonl is empty — the taxonomy below is the full 45-state schema, with no observations to count against it yet."
      >
      <div className="mb-6">
        <KillChainOverview
          phases={phasesWithCounts}
          selectedPhase={selectedPhase}
          onSelectPhase={setSelectedPhase}
        />
      </div>

      {selectedPhaseData && (
        <div className="mb-6">
          <PhaseDetailPanel phase={selectedPhaseData} />
        </div>
      )}

      <div className="mb-6">
        <MicroStateExplorer
          states={filteredStates}
          total={sessions.length}
          search={search}
          onSearchChange={setSearch}
          phase={selectedPhase}
          onPhaseChange={setSelectedPhase}
          phases={KILL_CHAIN_PHASES}
        />
      </div>

      </DataSection>

      <TaxonomyExplanation />
    </div>
  )
}
