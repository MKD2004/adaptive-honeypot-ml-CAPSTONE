import { useMemo, useState } from 'react'
import PageHeader from '../components/common/PageHeader'
import StatusBadge from '../components/common/StatusBadge'
import KillChainOverview from '../components/mitre/KillChainOverview'
import PhaseDetailPanel from '../components/mitre/PhaseDetailPanel'
import MicroStateExplorer from '../components/mitre/MicroStateExplorer'
import TaxonomyExplanation from '../components/mitre/TaxonomyExplanation'
import { useApiResource, API_STATUS } from '../hooks/useApiResource'
import { getLiveFeed } from '../services/api'
import { KILL_CHAIN_PHASES, MICRO_STATES } from '../lib/schema'

const WINDOW = 1000

// The 45-state / 9-phase taxonomy (lib/schema.js mirrors configs/schema.py)
// overlaid with how often MT3 has predicted each state. The taxonomy itself
// renders even when the API is offline; only the counts need the backend.
export default function MitreTaxonomyPage() {
  const [selectedPhase, setSelectedPhase] = useState('all')
  const [search, setSearch] = useState('')
  const feed = useApiResource(() => getLiveFeed({ limit: WINDOW }), { intervalMs: 10000 })

  const records = useMemo(() => feed.data?.results ?? [], [feed.data])
  const counts = useMemo(() => {
    const c = {}
    records.forEach((r) => {
      const label = r.mt3_prediction?.micro_state
      if (label) c[label] = (c[label] || 0) + 1
    })
    return c
  }, [records])

  const states = useMemo(() => MICRO_STATES.map((s) => ({ ...s, count: counts[s.label] || 0 })), [counts])
  const phases = useMemo(
    () =>
      KILL_CHAIN_PHASES.map((p) => {
        const ps = states.filter((s) => s.phase === p.id)
        return { ...p, states: ps, count: ps.reduce((a, s) => a + s.count, 0) }
      }),
    [states],
  )

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return states.filter((s) => {
      if (selectedPhase !== 'all' && String(s.phase) !== selectedPhase) return false
      return !q || s.label.toLowerCase().includes(q) || s.mitre.toLowerCase().includes(q)
    })
  }, [states, selectedPhase, search])

  const selected = selectedPhase !== 'all' ? phases.find((p) => String(p.id) === selectedPhase) : null
  const offline = feed.status === API_STATUS.UNREACHABLE || feed.status === API_STATUS.ERROR

  return (
    <div>
      <PageHeader
        title="MITRE Taxonomy"
        subtitle={`45 micro-states across 9 kill-chain phases, with how often MT3 predicted each (latest ${WINDOW.toLocaleString()} sessions)`}
        actions={offline && <StatusBadge status="offline" label="API offline: counts unavailable" />}
      />

      <div className="mb-6">
        <KillChainOverview phases={phases} selectedPhase={selectedPhase} onSelectPhase={setSelectedPhase} />
      </div>

      {selected && (
        <div className="mb-6">
          <PhaseDetailPanel phase={selected} />
        </div>
      )}

      <div className="mb-6">
        <MicroStateExplorer
          states={filtered}
          total={records.length}
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
