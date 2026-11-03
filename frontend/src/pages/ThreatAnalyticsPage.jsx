import { useMemo, useState } from 'react'
import { Layers, Gauge, AlertTriangle, GitCompare, Workflow, ShieldHalf } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import MetricCard from '../components/common/MetricCard'
import Panel from '../components/common/Panel'
import Resource from '../components/common/Resource'
import EmptyState from '../components/common/EmptyState'
import { PhaseBadge } from '../components/common/Badges'
import PhaseAnalyticsChart from '../components/analytics/PhaseAnalyticsChart'
import ConfidenceHistogram from '../components/analytics/ConfidenceHistogram'
import { useApiResource, hasData } from '../hooks/useApiResource'
import { getLiveFeed, getStats } from '../services/api'
import { KILL_CHAIN_PHASES, microStateByLabel, phaseName } from '../lib/schema'
import { num, pct } from '../lib/format'

const WINDOW = 1000
const LOW_CONF = 0.5
const BUCKETS = [
  { label: '<50%', min: 0, max: 0.5 },
  { label: '50–70%', min: 0.5, max: 0.7 },
  { label: '70–90%', min: 0.7, max: 0.9 },
  { label: '≥90%', min: 0.9, max: 1.01 },
]

const rate = (n, d) => (d ? n / d : null)

// Everything below is computed from real pipeline records — nothing is
// simulated. "Agreement" compares MT3 with the parser's rule-based label,
// which is a heuristic, so it is reported as agreement, not accuracy.
function analyse(records) {
  const states = {}
  let confSum = 0
  let low = 0
  let ruleN = 0
  let ruleAgree = 0
  let kcvrN = 0
  let kcvrOk = 0
  let changed = 0

  for (const r of records) {
    const m = r.mt3_prediction || {}
    const c = typeof m.confidence === 'number' ? m.confidence : 0
    confSum += c
    if (c < LOW_CONF) low += 1
    if (r.rule_label) {
      ruleN += 1
      if (r.rule_label === m.micro_state) ruleAgree += 1
    }
    if (r.kcvr_valid === true || r.kcvr_valid === false) {
      kcvrN += 1
      if (r.kcvr_valid) kcvrOk += 1
    }
    if (r.honeypot_action?.changed) changed += 1

    if (!m.micro_state) continue
    const s = (states[m.micro_state] ??= { label: m.micro_state, phase: m.phase, count: 0, conf: 0, ruleN: 0, ruleAgree: 0 })
    s.count += 1
    s.conf += c
    if (r.rule_label) {
      s.ruleN += 1
      if (r.rule_label === m.micro_state) s.ruleAgree += 1
    }
  }

  const stateRows = Object.values(states)
    .map((s) => ({ ...s, avgConf: s.conf / s.count, agreement: rate(s.ruleAgree, s.ruleN), meta: microStateByLabel(s.label) }))
    .sort((a, b) => b.count - a.count)

  const phases = KILL_CHAIN_PHASES.map((p) => {
    const rows = stateRows.filter((s) => s.phase === p.id)
    const count = rows.reduce((a, s) => a + s.count, 0)
    return { ...p, count, avgConfidence: count ? rows.reduce((a, s) => a + s.conf, 0) / count : 0 }
  })

  const buckets = BUCKETS.map((b) => ({
    ...b,
    count: records.filter((r) => {
      const c = r.mt3_prediction?.confidence ?? 0
      return c >= b.min && c < b.max
    }).length,
  }))

  return {
    n: records.length,
    meanConf: rate(confSum, records.length),
    lowShare: rate(low, records.length),
    agreement: rate(ruleAgree, ruleN),
    kcvr: rate(kcvrOk, kcvrN),
    kcvrN,
    changed,
    stateRows,
    phases,
    buckets,
  }
}

function MicroStateTable({ rows }) {
  return (
    <div className="overflow-x-auto scrollbar-thin">
      <table className="w-full min-w-[720px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-base-border text-left text-xs uppercase tracking-wide text-text-muted">
            <th className="py-2 pr-4 font-medium">Micro-state</th>
            <th className="py-2 pr-4 font-medium">MITRE</th>
            <th className="py-2 pr-4 font-medium">Phase</th>
            <th className="py-2 pr-4 text-right font-medium">Sessions</th>
            <th className="py-2 pr-4 text-right font-medium">Avg confidence</th>
            <th className="py-2 pr-4 text-right font-medium">Agrees w/ rule label</th>
            <th className="py-2 pr-4 font-medium">Training data</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((s) => (
            <tr key={s.label} className="border-b border-base-borderMuted">
              <td className="py-2 pr-4 font-mono text-xs text-accent">{s.label}</td>
              <td className="py-2 pr-4 font-mono text-xs text-text-muted">{s.meta?.mitre ?? '—'}</td>
              <td className="py-2 pr-4"><PhaseBadge phase={s.phase} /></td>
              <td className="py-2 pr-4 text-right tabular-nums">{num(s.count)}</td>
              <td className="py-2 pr-4 text-right tabular-nums text-text-secondary">{pct(s.avgConf)}</td>
              <td className="py-2 pr-4 text-right tabular-nums text-text-secondary">{pct(s.agreement)}</td>
              <td className="py-2 pr-4 text-xs">
                {s.meta?.realData ? (
                  <span className="text-risk-low">real-anchored</span>
                ) : (
                  <span className="text-text-muted">synthetic only</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function ThreatAnalyticsPage() {
  const [phase, setPhase] = useState('all')
  const feed = useApiResource(() => getLiveFeed({ limit: WINDOW }), {
    intervalMs: 10000,
    isEmpty: (d) => !d?.results?.length,
  })
  const stats = useApiResource(getStats, { intervalMs: 10000 })

  const a = useMemo(() => (feed.data?.results ? analyse(feed.data.results) : null), [feed.data])
  const rows = a ? a.stateRows.filter((s) => phase === 'all' || String(s.phase) === phase) : []
  const targets = stats.data?.honeypot_targets || {}
  const windowNote =
    hasData(stats) && stats.data.total_sessions > WINDOW
      ? `latest ${num(WINDOW)} of ${num(stats.data.total_sessions)} sessions`
      : 'all classified sessions'

  return (
    <div>
      <PageHeader
        title="Threat Analytics"
        subtitle={`What MT3 has seen, computed live from the pipeline results (${windowNote})`}
      />

      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <MetricCard icon={Layers} label="Sessions analysed" value={a ? num(a.n) : '—'} sublabel={windowNote} />
        <MetricCard icon={Gauge} label="Mean confidence" value={a ? pct(a.meanConf) : '—'} sublabel="top-1 probability" />
        <MetricCard icon={AlertTriangle} label="Low confidence" value={a ? pct(a.lowShare) : '—'} sublabel={`< ${LOW_CONF * 100}%: model unsure`} accent="medium" />
        <MetricCard icon={GitCompare} label="Rule-label agreement" value={a ? pct(a.agreement) : '—'} sublabel="MT3 vs parser heuristic" />
        <MetricCard icon={Workflow} label="Kill-chain valid" value={a ? pct(a.kcvr) : '—'} sublabel={a ? `KILL_CHAIN_DAG, n=${num(a.kcvrN)}` : ''} />
        <MetricCard icon={ShieldHalf} label="Triggered adaptation" value={a ? num(a.changed) : '—'} sublabel="sessions that changed config" accent="high" />
      </div>

      <Resource
        resource={feed}
        emptyTitle="No sessions classified yet"
        emptyDescription="Analytics fill in once MT3 has classified sessions. Run demo/simulate_attack.py --reset-config or attack through the gateway."
      >
        {() => (
          <>
            <div className="mb-6 grid grid-cols-1 gap-4 xl:grid-cols-2">
              <Panel title="Sessions by Kill-Chain Phase" subtitle="Click a bar to filter the micro-state table">
                <div style={{ height: 260 }}>
                  <PhaseAnalyticsChart data={a.phases} selectedPhase={phase} onSelectPhase={(p) => setPhase(p === phase ? 'all' : p)} />
                </div>
              </Panel>
              <Panel title="Confidence Distribution" subtitle="Model probability, not a measure of correctness">
                <div style={{ height: 260 }}>
                  <ConfidenceHistogram buckets={a.buckets} />
                </div>
              </Panel>
            </div>

            <div className="mb-6 grid grid-cols-1 gap-4 xl:grid-cols-3">
              <Panel
                className="xl:col-span-2"
                title="Micro-States Observed"
                subtitle={phase === 'all' ? `${a.stateRows.length} of 45 states seen` : `Phase ${phase}: ${phaseName(Number(phase))}`}
                actions={
                  phase !== 'all' && (
                    <button type="button" onClick={() => setPhase('all')} className="text-xs font-medium text-accent hover:underline">
                      Show all phases
                    </button>
                  )
                }
              >
                {rows.length ? (
                  <MicroStateTable rows={rows} />
                ) : (
                  <EmptyState title="No sessions in this phase" description="Pick another bar or show all phases." />
                )}
              </Panel>

              <Panel title="Honeypot Targets" subtitle="Which emulator each session was routed to (all sessions)">
                {Object.keys(targets).length ? (
                  <ul className="space-y-2 text-sm">
                    {Object.entries(targets).map(([t, n]) => (
                      <li key={t} className="flex items-center justify-between">
                        <span className="font-mono text-xs text-text-secondary">{t}</span>
                        <span className="tabular-nums">{num(n)}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-text-muted">—</p>
                )}
                <p className="mt-4 border-t border-base-borderMuted pt-3 text-[11px] text-text-muted">
                  "Synthetic only" states have no real-data anchor in training (only CIC-IDS2017 / UNSW-NB15
                  are real, covering 13 of 45 states), so lower confidence there is expected.
                </p>
              </Panel>
            </div>
          </>
        )}
      </Resource>
    </div>
  )
}
