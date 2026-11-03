function formatTs(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleTimeString('en-US', { hour12: false })
}

// Renders GET /api/live-access' `decisions[]` — traffic_gateway's PRE-FILTER
// verdicts (traffic_classifier.py), computed before any session reaches
// Cowrie/MT3. "score" here is that heuristic's [0,1] output, not an MT3
// confidence, and "verdict" is MALICIOUS/SUSPICIOUS/BENIGN, not a MITRE
// micro-state — labeled as such in the column headers on purpose.
export default function RoutingDecisionsTable({ decisions }) {
  return (
    <div className="overflow-x-auto scrollbar-thin">
      <table className="w-full min-w-[760px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
            <th className="py-2 pr-4 font-medium">Time</th>
            <th className="py-2 pr-4 font-medium">IP</th>
            <th className="py-2 pr-4 font-medium">Gateway Verdict</th>
            <th className="py-2 pr-4 font-medium">Gateway Score</th>
            <th className="py-2 pr-4 font-medium">Destination</th>
            <th className="py-2 pr-4 font-medium">Signals</th>
            <th className="py-2 pr-4 font-medium">Reason</th>
          </tr>
        </thead>
        <tbody>
          {decisions.map((d, i) => (
            <tr key={i} className="border-b border-border/60">
              <td className="py-2.5 pr-4 text-xs text-muted-foreground">{formatTs(d.ts)}</td>
              <td className="py-2.5 pr-4 font-mono text-xs text-foreground">{d.ip || '—'}</td>
              <td className="py-2.5 pr-4">
                <span
                  className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${
                    d.verdict === 'MALICIOUS'
                      ? 'border-risk-critical/30 bg-risk-critical/10 text-risk-critical'
                      : d.verdict === 'SUSPICIOUS'
                        ? 'border-risk-medium/30 bg-risk-medium/10 text-risk-medium'
                        : 'border-risk-low/30 bg-risk-low/10 text-risk-low'
                  }`}
                >
                  {d.verdict || d.destination || '—'}
                </span>
              </td>
              <td className="py-2.5 pr-4 tabular-nums text-foreground/80">
                {typeof d.score === 'number' ? d.score.toFixed(3) : '—'}
              </td>
              <td className="py-2.5 pr-4 text-foreground/80">{d.destination || '—'}</td>
              <td className="py-2.5 pr-4 text-xs text-muted-foreground">
                {Array.isArray(d.signals) && d.signals.length ? d.signals.join(', ') : '—'}
              </td>
              <td className="py-2.5 pr-4 text-xs text-muted-foreground">{d.reason || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
