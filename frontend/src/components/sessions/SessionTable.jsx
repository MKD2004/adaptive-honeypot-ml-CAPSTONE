import { useNavigate } from 'react-router-dom'
import RiskBadge, { phaseToRisk } from '../common/RiskBadge'
import StatusBadge from '../common/StatusBadge'

function timeAgo(iso) {
  const diffMs = Date.now() - new Date(iso).getTime()
  const mins = Math.round(diffMs / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.round(mins / 60)
  return `${hrs}h ago`
}

// variant:
//  - 'compact'   Dashboard's old mini table (kept for compatibility) — no MITRE column
//  - 'dashboard' Dashboard's Recent Sessions card — Session ID/Protocol/Status shown,
//                a single "MITRE State" column (micro-state only), no Confidence
//  - 'full'      Live Sessions page — every column, incl. MITRE id + Confidence
//  - default     original 6-column layout (Micro-State + MITRE id, no session id/status)
export default function SessionTable({ sessions, limit, variant = 'default' }) {
  const navigate = useNavigate()
  const rows = limit ? sessions.slice(0, limit) : sessions

  const showSessionId = variant === 'full' || variant === 'dashboard'
  const showProtocol = variant === 'full' || variant === 'dashboard'
  const showMitreId = variant !== 'compact' && variant !== 'dashboard'
  const showConfidence = variant !== 'dashboard'
  const showStatus = variant === 'full' || variant === 'dashboard'
  const mitreStateHeader = variant === 'dashboard' ? 'MITRE State' : 'Micro-State'
  const lastActivityHeader = variant === 'full' || variant === 'dashboard' ? 'Last Activity' : 'Seen'

  return (
    <div className="overflow-x-auto scrollbar-thin">
      <table className="w-full min-w-[760px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-base-border text-left text-xs uppercase tracking-wide text-text-muted">
            {showSessionId && <th className="py-2 pr-4 font-medium">Session ID</th>}
            <th className="py-2 pr-4 font-medium">Source IP</th>
            {showProtocol && <th className="py-2 pr-4 font-medium">Protocol</th>}
            <th className="py-2 pr-4 font-medium">{mitreStateHeader}</th>
            {showMitreId && <th className="py-2 pr-4 font-medium">MITRE</th>}
            <th className="py-2 pr-4 font-medium">Phase</th>
            {showConfidence && <th className="py-2 pr-4 font-medium">Confidence</th>}
            <th className="py-2 pr-4 font-medium">Risk</th>
            {showStatus && <th className="py-2 pr-4 font-medium">Status</th>}
            <th className="py-2 pr-4 font-medium">{lastActivityHeader}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((s) => (
            <tr
              key={s.session_id}
              onClick={() => navigate(`/sessions/${s.session_id}`)}
              className="cursor-pointer border-b border-base-borderMuted transition-colors hover:bg-base-raised"
            >
              {showSessionId && (
                <td className="py-2.5 pr-4 font-mono text-xs text-text-primary">{s.session_id}</td>
              )}
              <td className="py-2.5 pr-4 font-mono text-xs text-text-primary">{s.src_ip}</td>
              {showProtocol && <td className="py-2.5 pr-4 text-text-secondary">{s.protocol}</td>}
              <td className="py-2.5 pr-4 font-mono text-xs text-accent">{s.micro_state}</td>
              {showMitreId && <td className="py-2.5 pr-4 font-mono text-xs text-text-muted">{s.mitre}</td>}
              <td className="py-2.5 pr-4 text-text-secondary">{s.phase_name}</td>
              {showConfidence && (
                <td className="py-2.5 pr-4 tabular-nums text-text-secondary">
                  {(s.confidence * 100).toFixed(1)}%
                </td>
              )}
              <td className="py-2.5 pr-4">
                <RiskBadge level={s.risk ?? phaseToRisk(s.phase)} />
              </td>
              {showStatus && (
                <td className="py-2.5 pr-4">
                  <StatusBadge status={s.status} />
                </td>
              )}
              <td className="py-2.5 pr-4 text-xs text-text-muted">{timeAgo(s.timestamp)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
