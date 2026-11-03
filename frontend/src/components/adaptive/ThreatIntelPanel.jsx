import { useState } from 'react'
import { Radar, RefreshCw } from 'lucide-react'
import Panel from '../common/Panel'
import Resource from '../common/Resource'
import StatusBadge from '../common/StatusBadge'
import { useToast } from '../common/Toasts'
import { useApiResource } from '../../hooks/useApiResource'
import { getThreatIntel, refreshThreatIntel } from '../../services/api'
import { fmtDateTime, num, timeAgo } from '../../lib/format'

function Freshness({ d }) {
  if (d.source !== 'live') return <StatusBadge status="degraded" label="Offline snapshot (June 2026)" />
  if (d.stale) return <StatusBadge status="degraded" label={`Live, stale: ${timeAgo(d.generated_at)}`} />
  return <StatusBadge status="online" label={`Live: fetched ${timeAgo(d.generated_at)}`} />
}

function SourceRow({ label, value, sub }) {
  return (
    <>
      <dt className="text-text-muted">{label}</dt>
      <dd className="text-right text-text-primary">
        {value}
        {sub && <span className="ml-1.5 text-xs text-text-muted">{sub}</span>}
      </dd>
    </>
  )
}

function ProfilesTable({ profiles }) {
  return (
    <div className="overflow-x-auto scrollbar-thin">
      <table className="w-full min-w-[680px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-base-border text-left text-xs uppercase tracking-wide text-text-muted">
            <th className="py-2 pr-3 font-medium">CVE</th>
            <th className="py-2 pr-3 font-medium">Attack type</th>
            <th className="py-2 pr-3 text-right font-medium">CVSS</th>
            <th className="py-2 pr-3 text-right font-medium">EPSS</th>
            <th className="py-2 pr-3 font-medium">Added to KEV</th>
            <th className="py-2 pr-3 font-medium">Priority</th>
          </tr>
        </thead>
        <tbody>
          {profiles.map((p) => (
            <tr key={p.cve_id} className="border-b border-base-borderMuted">
              <td className="py-2 pr-3 font-mono text-xs">
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${p.cve_id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-accent hover:underline"
                >
                  {p.cve_id}
                </a>
              </td>
              <td className="py-2 pr-3 text-xs text-text-secondary">{p.attack_type}</td>
              <td className="py-2 pr-3 text-right tabular-nums">{p.cvss_score ?? '—'}</td>
              <td className="py-2 pr-3 text-right tabular-nums">
                {p.epss_source === 'unscored' ? (
                  <span className="text-xs text-text-muted" title="FIRST has not scored this CVE yet">unscored</span>
                ) : typeof p.epss_score === 'number' ? (
                  <span title={p.epss_source ? `source: ${p.epss_source}` : 'source not recorded (snapshot)'}>
                    {p.epss_score.toFixed(3)}
                  </span>
                ) : (
                  '—'
                )}
              </td>
              <td className="py-2 pr-3 text-xs text-text-muted">{p.is_kev ? p.kev_date_added || 'yes' : '—'}</td>
              <td className="py-2 pr-3 text-xs text-text-secondary">{p.priority_tier}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// GET /api/threat-intel: the CVE feed (NVD + CISA KEV + FIRST EPSS) that the
// configurator uses for its trending-CVE banner overlay, and how fresh it is.
export default function ThreatIntelPanel() {
  const notify = useToast()
  const [busy, setBusy] = useState(false)
  const intel = useApiResource(() => getThreatIntel({ limit: 25 }), { intervalMs: 10000 })
  const running = intel.data?.refresher?.running

  async function refresh() {
    setBusy(true)
    try {
      await refreshThreatIntel()
      notify('info', 'Threat intel refresh started', 'Pulling NVD, CISA KEV and FIRST EPSS. This takes about a minute.')
      intel.reload()
    } catch (err) {
      notify('warn', 'Refresh failed', err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Panel
      title="Threat Intelligence Feed"
      icon={Radar}
      subtitle="Trending exploited CVEs from NVD + CISA KEV + FIRST EPSS; drives the honeypot's CVE banner overlay"
      actions={
        <button
          type="button"
          onClick={refresh}
          disabled={busy || running}
          className="flex items-center gap-1.5 rounded-md border border-base-border bg-base-raised px-3 py-1.5 text-xs font-medium text-text-secondary hover:text-text-primary disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${running ? 'animate-spin' : ''}`} />
          {running ? 'Refreshing…' : 'Refresh now'}
        </button>
      }
    >
      <Resource resource={intel}>
        {(d) => {
          const m = d.meta || {}
          const epss = m.epss || {}
          const r = d.refresher || {}
          return (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <Freshness d={d} />
                {d.mt3_threat_intel && (
                  <StatusBadge
                    status={String(d.mt3_threat_intel.kev_source).includes('live') ? 'online' : 'degraded'}
                    label={`MT3 KEV: ${num(d.mt3_threat_intel.kev_count)} (${d.mt3_threat_intel.kev_source})`}
                  />
                )}
                {r.last_error && <StatusBadge status="offline" label="Last refresh failed" />}
              </div>

              {d.source === 'live' ? (
                <dl className="mb-4 grid grid-cols-2 gap-y-1.5 text-sm">
                  <SourceRow label="Fetched" value={fmtDateTime(d.generated_at)} />
                  <SourceRow
                    label="NVD CVEs (last 7 days)"
                    value={num(m.cves_processed)}
                    sub={m.cve_source && m.cve_source !== 'nvd' ? `via ${m.cve_source}` : undefined}
                  />
                  <SourceRow label="CISA KEV catalog" value={num(m.kev_catalog_size)} sub={`${num(m.kev_flagged)} of these CVEs`} />
                  <SourceRow
                    label="EPSS (FIRST.org)"
                    value={`${num(epss['first.org'] ?? 0)} scored`}
                    sub={`${num(epss.unscored ?? 0)} not yet scored${epss.simulated ? `, ${epss.simulated} simulated` : ''}`}
                  />
                  <SourceRow
                    label="Trending profiles"
                    value={num(d.profile_count)}
                    sub={m.profiles_basis === 'trending' ? `KEV-added ≤ ${m.trending_window_days} d` : 'no recent KEV adds: all CVEs'}
                  />
                  <SourceRow
                    label="Next automatic refresh"
                    value={r.next_run ? fmtDateTime(r.next_run) : r.loop_started ? '—' : 'loop not running'}
                    sub={`every ${r.interval_hours} h`}
                  />
                </dl>
              ) : (
                <p className="mb-4 text-xs text-text-muted">
                  No live refresh has succeeded on this machine yet, so the configurator is using the committed
                  snapshot (cve_intelligence/data/trending_profiles.json). Its EPSS values pre-date the FIRST API fix
                  and are not reliable. Click <span className="font-medium">Refresh now</span> or start{' '}
                  <code className="font-mono">traffic_gateway.run_pipeline</code>.
                </p>
              )}
              {r.last_error && <p className="mb-3 text-xs text-risk-high">{r.last_error}</p>}

              {d.profiles.length ? (
                <ProfilesTable profiles={d.profiles} />
              ) : (
                <p className="text-xs text-text-muted">No profiles.</p>
              )}
            </>
          )
        }}
      </Resource>
    </Panel>
  )
}
