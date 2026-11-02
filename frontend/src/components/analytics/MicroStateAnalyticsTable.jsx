import RiskBadge, { phaseToRisk } from '../common/RiskBadge'
import { phaseName } from '../../lib/schema'

// Table of per-micro-state analytics (services/analytics.js, computed from
// the sessions MT3 has classified).
// `total` is the denominator for the percentage column — pass the filtered
// set's own total so percentages stay meaningful when phase/confidence
// filters are active, not the full 45-state total.
export default function MicroStateAnalyticsTable({ rows, total }) {
  return (
    <div className="overflow-x-auto scrollbar-thin">
      <table className="w-full min-w-[680px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-base-border text-left text-xs uppercase tracking-wide text-text-muted">
            <th className="py-2 pr-4 font-medium">Micro-State</th>
            <th className="py-2 pr-4 font-medium">MITRE</th>
            <th className="py-2 pr-4 font-medium">Phase</th>
            <th className="py-2 pr-4 font-medium">Sessions</th>
            <th className="py-2 pr-4 font-medium">% of shown</th>
            <th className="py-2 pr-4 font-medium">Avg. Confidence</th>
            <th className="py-2 pr-4 font-medium">Risk</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((s) => (
            <tr key={s.id} className="border-b border-base-borderMuted">
              <td className="py-2.5 pr-4 font-mono text-xs text-accent">{s.label}</td>
              <td className="py-2.5 pr-4 font-mono text-xs text-text-muted">{s.mitre}</td>
              <td className="py-2.5 pr-4 text-text-secondary">{phaseName(s.phase)}</td>
              <td className="py-2.5 pr-4 tabular-nums text-text-primary">{s.count}</td>
              <td className="py-2.5 pr-4 tabular-nums text-text-muted">
                {total ? `${((s.count / total) * 100).toFixed(1)}%` : '—'}
              </td>
              <td className="py-2.5 pr-4 tabular-nums text-text-secondary">{(s.avgConfidence * 100).toFixed(1)}%</td>
              <td className="py-2.5 pr-4">
                <RiskBadge level={phaseToRisk(s.phase)} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
