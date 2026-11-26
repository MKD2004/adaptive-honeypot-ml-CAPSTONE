function formatTs(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleTimeString('en-US', { hour12: false })
}

// divert = send this source to the honeypot, alert = notify only,
// observe = record the decision and take no action. Colour carries the
// severity so a reviewer can read the column without the legend.
const ACTION_STYLE = {
  divert: 'bg-red-500/10 text-red-600 dark:text-red-400',
  alert: 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
  observe: 'bg-sky-500/10 text-sky-600 dark:text-sky-400',
}

const OUTCOME_STYLE = {
  applied: 'text-emerald-600 dark:text-emerald-400',
  skipped: 'text-muted-foreground',
  failed: 'text-red-600 dark:text-red-400',
  vetoed: 'text-amber-600 dark:text-amber-400',
}

function Pill({ value, styles }) {
  const cls = styles[String(value)] ?? 'bg-muted text-muted-foreground'
  return (
    <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${cls}`}>
      {value || '—'}
    </span>
  )
}

// Renders GET /api/mitigation's `decisions[]` — response_mitigation's audit
// log. This is the DECISION, not the outcome: /api/blacklist already showed
// which IPs ended up blocked, but not which rule fired, what the reason was,
// or whether the action was actually carried out.
//
// `confidence` and `micro_state` here ARE MT3's, unlike RoutingDecisionsTable
// where the score is the gateway's pre-filter heuristic. `phase -1` means
// BENIGN, which has no kill-chain phase.
export default function MitigationDecisionsTable({ decisions }) {
  return (
    <div className="overflow-x-auto scrollbar-thin">
      <table className="w-full min-w-[920px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
            <th className="py-2 pr-4 font-medium">Time</th>
            <th className="py-2 pr-4 font-medium">IP</th>
            <th className="py-2 pr-4 font-medium">Action</th>
            <th className="py-2 pr-4 font-medium">Outcome</th>
            <th className="py-2 pr-4 font-medium">Rule</th>
            <th className="py-2 pr-4 font-medium">MT3 Micro-State</th>
            <th className="py-2 pr-4 font-medium">Phase</th>
            <th className="py-2 pr-4 font-medium">Conf.</th>
            <th className="py-2 pr-4 font-medium">Reason</th>
          </tr>
        </thead>
        <tbody>
          {decisions.map((d, i) => (
            <tr key={d.decision_id ?? i} className="border-b border-border/60">
              <td className="py-2.5 pr-4 text-xs text-muted-foreground">{formatTs(d.ts)}</td>
              <td className="py-2.5 pr-4 font-mono text-xs text-foreground">{d.ip || '—'}</td>
              <td className="py-2.5 pr-4">
                <Pill value={d.action} styles={ACTION_STYLE} />
              </td>
              <td className={`py-2.5 pr-4 text-xs font-medium ${OUTCOME_STYLE[String(d.outcome)] ?? ''}`}>
                {d.outcome || '—'}
              </td>
              <td className="py-2.5 pr-4 font-mono text-xs text-muted-foreground">{d.rule || '—'}</td>
              <td className="py-2.5 pr-4 font-mono text-xs text-foreground">{d.micro_state || '—'}</td>
              <td className="py-2.5 pr-4 text-xs text-muted-foreground">
                {d.phase === -1 || d.phase === null || d.phase === undefined
                  ? '—'
                  : `${d.phase} · ${d.phase_name ?? ''}`}
              </td>
              <td className="py-2.5 pr-4 font-mono text-xs text-muted-foreground">
                {typeof d.confidence === 'number' ? d.confidence.toFixed(3) : '—'}
              </td>
              <td className="py-2.5 pr-4 text-xs text-muted-foreground">{d.reason || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
