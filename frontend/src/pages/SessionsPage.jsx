import { useMemo, useState } from 'react'
import { Search, RotateCcw } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import Panel from '../components/common/Panel'
import Resource from '../components/common/Resource'
import EmptyState from '../components/common/EmptyState'
import SessionTable from '../components/sessions/SessionTable'
import { useApiResource } from '../hooks/useApiResource'
import { getLiveFeed } from '../services/api'
import { KILL_CHAIN_PHASES } from '../lib/schema'

const FEED_LIMIT = 500

const SORTS = {
  newest: (a, b) => String(b.timestamp).localeCompare(String(a.timestamp)),
  conf_desc: (a, b) => (b.mt3_prediction?.confidence ?? 0) - (a.mt3_prediction?.confidence ?? 0),
  conf_asc: (a, b) => (a.mt3_prediction?.confidence ?? 0) - (b.mt3_prediction?.confidence ?? 0),
  phase_desc: (a, b) => (b.mt3_prediction?.phase ?? -1) - (a.mt3_prediction?.phase ?? -1),
}

const selectCls =
  'rounded-md border border-base-border bg-base-raised px-2.5 py-1.5 text-sm text-text-primary focus:border-accent focus:outline-none'

function filterRecords(records, { query, phase, onlyChanged, sort }) {
  const q = query.trim().toLowerCase()
  return records
    .filter((r) => {
      const m = r.mt3_prediction || {}
      if (phase !== 'all' && String(m.phase) !== phase) return false
      if (onlyChanged && !r.honeypot_action?.changed) return false
      if (!q) return true
      return [r.session_id, r.src_ip, m.micro_state, r.rule_label, ...(r.commands || [])]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(q))
    })
    .sort(SORTS[sort])
}

export default function SessionsPage() {
  const [query, setQuery] = useState('')
  const [phase, setPhase] = useState('all')
  const [onlyChanged, setOnlyChanged] = useState(false)
  const [sort, setSort] = useState('newest')

  const feed = useApiResource(() => getLiveFeed({ limit: FEED_LIMIT }), {
    intervalMs: 5000,
    isEmpty: (d) => !d?.results?.length,
  })

  const records = feed.data?.results
  const filtered = useMemo(
    () => (records ? filterRecords(records, { query, phase, onlyChanged, sort }) : []),
    [records, query, phase, onlyChanged, sort],
  )
  const isFiltered = query || phase !== 'all' || onlyChanged || sort !== 'newest'

  return (
    <div>
      <PageHeader
        title="Classified Sessions"
        subtitle="Every Cowrie session MT3 has classified: micro-state, phase, confidence, and what the honeypot did about it"
      />

      <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-base-border bg-base-surface p-3">
        <div className="relative min-w-[240px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-muted" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search IP, session ID, micro-state or command…"
            className="w-full rounded-md border border-base-border bg-base-raised py-1.5 pl-8 pr-3 text-sm text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
          />
        </div>
        <select value={phase} onChange={(e) => setPhase(e.target.value)} className={selectCls} aria-label="Filter by phase">
          <option value="all">All phases</option>
          {KILL_CHAIN_PHASES.map((p) => (
            <option key={p.id} value={String(p.id)}>
              {p.id} · {p.name}
            </option>
          ))}
        </select>
        <select value={sort} onChange={(e) => setSort(e.target.value)} className={selectCls} aria-label="Sort">
          <option value="newest">Sort: newest</option>
          <option value="phase_desc">Sort: deepest phase</option>
          <option value="conf_desc">Sort: highest confidence</option>
          <option value="conf_asc">Sort: lowest confidence</option>
        </select>
        <label className="flex items-center gap-2 text-sm text-text-secondary">
          <input type="checkbox" checked={onlyChanged} onChange={(e) => setOnlyChanged(e.target.checked)} />
          Changed the honeypot
        </label>
        {isFiltered && (
          <button
            type="button"
            onClick={() => {
              setQuery('')
              setPhase('all')
              setOnlyChanged(false)
              setSort('newest')
            }}
            className="flex items-center gap-1.5 rounded-md border border-base-border bg-base-raised px-3 py-1.5 text-xs font-medium text-text-secondary hover:text-text-primary"
          >
            <RotateCcw className="h-3.5 w-3.5" /> Clear
          </button>
        )}
      </div>

      <Panel
        title="Sessions"
        subtitle={`GET /api/live-feed (latest ${FEED_LIMIT}) · refreshes every 5 s`}
        actions={records && <span className="text-xs text-text-muted">{filtered.length} of {records.length}</span>}
      >
        <Resource
          resource={feed}
          emptyTitle="No sessions classified yet"
          emptyDescription="logs/pipeline_results.jsonl is empty. Run demo/simulate_attack.py --reset-config, or attack through the gateway with the pipeline running."
        >
          {() =>
            filtered.length ? (
              <SessionTable records={filtered} />
            ) : (
              <EmptyState title="No sessions match these filters" description="Clear the search or filters above." />
            )
          }
        </Resource>
      </Panel>
    </div>
  )
}
