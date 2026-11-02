import { useMemo, useState } from 'react'
import PageHeader from '../components/common/PageHeader'
import StatusBadge from '../components/common/StatusBadge'
import KillChainOverview from '../components/mitre/KillChainOverview'
import PhaseDetailPanel from '../components/mitre/PhaseDetailPanel'
import MicroStateExplorer from '../components/mitre/MicroStateExplorer'
import TaxonomyExplanation from '../components/mitre/TaxonomyExplanation'
import { KILL_CHAIN_PHASES, MICRO_STATES } from '../lib/schema'
import { mockLiveSessions } from '../data/mockData'

// Deliberately counts straight from mockLiveSessions (the actual 24-session
// mock array in data/mockData.js), not the larger simulated dataset used by
// Threat Analytics — this page is meant to reflect "the mock dataset"
// literally. Most of the 45 micro-states will show 0 here; that's real
// information (this session batch never touched them), not a bug.
export default function MitreAnalysisPage() {
  const [selectedPhase, setSelectedPhase] = useState('all')
  const [search, setSearch] = useState('')

  const phaseCounts = useMemo(() => {
    const counts = new Array(KILL_CHAIN_PHASES.length).fill(0)
    mockLiveSessions.forEach((s) => {
      if (counts[s.phase] !== undefined) counts[s.phase] += 1
    })
    return counts
  }, [])

  const microStateCounts = useMemo(() => {
    const counts = {}
    mockLiveSessions.forEach((s) => {
      counts[s.micro_state] = (counts[s.micro_state] || 0) + 1
    })
    return counts
  }, [])

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
        subtitle="Kill-chain phases and micro-state coverage, counted from the mock session dataset"
        actions={<StatusBadge status="mock" label="Mock Data" />}
      />

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
          total={mockLiveSessions.length}
          search={search}
          onSearchChange={setSearch}
          phase={selectedPhase}
          onPhaseChange={setSelectedPhase}
          phases={KILL_CHAIN_PHASES}
        />
      </div>

      <TaxonomyExplanation />
    </div>
  )
}
