import { useNavigate } from 'react-router-dom'
import { ConfidenceBar, PhaseBadge, VerdictBadge } from '../common/Badges'
import { microStateByLabel } from '../../lib/schema'
import { fmtTime, timeAgo } from '../../lib/format'

// Rows are full pipeline records from GET /api/live-feed
// (post_session_pipeline.py `result`). Clicking a row opens Session Details.
// `compact` drops the secondary columns for the Overview page.
export default function SessionTable({ records, compact = false }) {
  const navigate = useNavigate()

  return (
    <div className="overflow-x-auto scrollbar-thin">
      <table className="w-full min-w-[720px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-base-border text-left text-xs uppercase tracking-wide text-text-muted">
            <th className="py-2 pr-4 font-medium">Time</th>
            <th className="py-2 pr-4 font-medium">Source IP</th>
            <th className="py-2 pr-4 font-medium">MT3 Micro-State</th>
            {!compact && <th className="py-2 pr-4 font-medium">MITRE</th>}
            <th className="py-2 pr-4 font-medium">Phase</th>
            <th className="py-2 pr-4 font-medium">Confidence</th>
            {!compact && <th className="py-2 pr-4 font-medium">Gateway</th>}
            {!compact && <th className="py-2 pr-4 font-medium">Cmds</th>}
            <th className="py-2 pr-4 font-medium">Honeypot</th>
          </tr>
        </thead>
        <tbody>
          {records.map((r) => {
            const m = r.mt3_prediction || {}
            const act = r.honeypot_action || {}
            return (
              <tr
                key={`${r.session_id}-${r.processed_at}`}
                onClick={() => navigate(`/sessions/${encodeURIComponent(r.session_id)}`)}
                className="cursor-pointer border-b border-base-borderMuted transition-colors hover:bg-base-raised"
              >
                <td className="py-2.5 pr-4 text-xs text-text-muted" title={timeAgo(r.timestamp)}>
                  {fmtTime(r.timestamp)}
                </td>
                <td className="py-2.5 pr-4 font-mono text-xs text-text-primary">
                  {r.src_ip || '—'}
                  {r.auto_blacklisted && (
                    <span className="ml-1.5 rounded border border-risk-critical/30 px-1 text-[10px] font-semibold text-risk-critical">
                      BLOCKED
                    </span>
                  )}
                </td>
                <td className="py-2.5 pr-4 font-mono text-xs text-accent">{m.micro_state ?? '—'}</td>
                {!compact && (
                  <td className="py-2.5 pr-4 font-mono text-xs text-text-muted">
                    {microStateByLabel(m.micro_state)?.mitre ?? '—'}
                  </td>
                )}
                <td className="py-2.5 pr-4">
                  <PhaseBadge phase={m.phase} showName={!compact} />
                </td>
                <td className="py-2.5 pr-4">
                  <ConfidenceBar value={m.confidence} />
                </td>
                {!compact && (
                  <td className="py-2.5 pr-4">
                    <VerdictBadge verdict={r.gateway_verdict} />
                  </td>
                )}
                {!compact && (
                  <td className="py-2.5 pr-4 tabular-nums text-xs text-text-secondary">{r.commands?.length ?? 0}</td>
                )}
                <td className="py-2.5 pr-4 text-xs">
                  {act.changed ? (
                    <span className="font-medium text-risk-high">
                      → {act.new_config?.interaction_level ?? 'changed'}
                    </span>
                  ) : (
                    <span className="text-text-muted">no change</span>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
