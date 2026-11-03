import { useNavigate } from 'react-router-dom'
import RiskBadge from '../common/RiskBadge'
import StatusBadge from '../common/StatusBadge'

function formatDate(iso) {
  return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
}

function truncate(text, max = 140) {
  if (!text || text.length <= max) return text
  return `${text.slice(0, max).trimEnd()}…`
}

// variant: 'compact' hides the description column (used at narrower widths
// via CSS, not JS — kept simple since this table already scrolls
// horizontally like the rest of the app's tables).
export default function CveTable({ cves }) {
  const navigate = useNavigate()

  return (
    <div className="overflow-x-auto scrollbar-thin">
      <table className="w-full min-w-[860px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
            <th className="py-2 pr-4 font-medium">CVE ID</th>
            <th className="py-2 pr-4 font-medium">Description</th>
            <th className="py-2 pr-4 font-medium">Severity</th>
            <th className="py-2 pr-4 font-medium">CVSS</th>
            <th className="py-2 pr-4 font-medium">EPSS</th>
            <th className="py-2 pr-4 font-medium">KEV</th>
            <th className="py-2 pr-4 font-medium">Published</th>
          </tr>
        </thead>
        <tbody>
          {cves.map((c) => (
            <tr
              key={c.cve_id}
              onClick={() => navigate(`/cve/${c.cve_id}`)}
              className="cursor-pointer border-b border-border/60 transition-colors hover:bg-muted/50"
            >
              <td className="py-2.5 pr-4 font-mono text-xs text-chart-1">{c.cve_id}</td>
              <td className="max-w-md py-2.5 pr-4 text-foreground/80">{truncate(c.description)}</td>
              <td className="py-2.5 pr-4">
                <RiskBadge level={c.severity.toLowerCase()} />
              </td>
              <td className="py-2.5 pr-4 tabular-nums text-foreground">{c.cvss_score.toFixed(1)}</td>
              <td className="py-2.5 pr-4 tabular-nums text-foreground/80">
                {(c.epss_score * 100).toFixed(1)}%
              </td>
              <td className="py-2.5 pr-4">
                {c.is_kev ? (
                  <StatusBadge status="offline" label="KEV" />
                ) : (
                  <span className="text-xs text-muted-foreground">&mdash;</span>
                )}
              </td>
              <td className="py-2.5 pr-4 text-xs text-muted-foreground">{formatDate(c.published)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
