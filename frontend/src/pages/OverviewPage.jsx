import { Link } from 'react-router-dom'
import { Activity, Users, Ban, Gauge, ShieldHalf, BellRing, ArrowUpRight, Route } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import MetricCard from '../components/common/MetricCard'
import Panel from '../components/common/Panel'
import Resource from '../components/common/Resource'
import { VerdictBadge } from '../components/common/Badges'
import PipelineFlow from '../components/dashboard/PipelineFlow'
import ThreatDistributionDonut from '../components/dashboard/ThreatDistributionDonut'
import SystemStatusCard from '../components/dashboard/SystemStatusCard'
import ActiveConfigCard from '../components/dashboard/ActiveConfigCard'
import SessionTable from '../components/sessions/SessionTable'
import { useApiResource, hasData } from '../hooks/useApiResource'
import { getStats, getLiveFeed, getActiveConfig, getHealth } from '../services/api'
import { num, pct } from '../lib/format'

const POLL_MS = 5000

function GatewaySummary({ stats }) {
  const verdicts = stats.gateway_classifier?.verdicts || {}
  const ipTotals = stats.ip_status_totals || {}
  return (
    <Panel
      title="Gateway Pre-filter"
      icon={Route}
      subtitle="traffic_classifier.py verdicts at connection time (heuristic score, not MT3)"
      actions={
        <Link to="/access" className="flex items-center gap-1 text-xs font-medium text-accent hover:underline">
          Live access <ArrowUpRight className="h-3.5 w-3.5" />
        </Link>
      }
    >
      <ul className="space-y-2 text-sm">
        {['MALICIOUS', 'SUSPICIOUS', 'BENIGN'].map((v) => (
          <li key={v} className="flex items-center justify-between">
            <VerdictBadge verdict={v} />
            <span className="tabular-nums text-text-primary">{num(verdicts[v] ?? 0)}</span>
          </li>
        ))}
      </ul>
      <dl className="mt-3 grid grid-cols-2 gap-y-1.5 border-t border-base-borderMuted pt-3 text-xs">
        <dt className="text-text-muted">Tracked IPs</dt>
        <dd className="text-right tabular-nums text-text-secondary">{num(stats.tracked_ips)}</dd>
        {Object.entries(ipTotals).map(([status, n]) => (
          <div key={status} className="contents">
            <dt className="text-text-muted">IP status: {status}</dt>
            <dd className="text-right tabular-nums text-text-secondary">{num(n)}</dd>
          </div>
        ))}
        <dt className="text-text-muted">Rate-limited now</dt>
        <dd className="text-right tabular-nums text-text-secondary">
          {num(stats.rate_limiter?.currently_blocked ?? 0)}
        </dd>
      </dl>
      <p className="mt-2 text-[11px] text-text-muted">
        Counters are this API process's in-memory state; they reset when it restarts.
      </p>
    </Panel>
  )
}

export default function OverviewPage() {
  const stats = useApiResource(getStats, { intervalMs: POLL_MS })
  const feed = useApiResource(() => getLiveFeed({ limit: 8 }), {
    intervalMs: POLL_MS,
    isEmpty: (d) => !d?.results?.length,
  })
  const config = useApiResource(getActiveConfig, { intervalMs: POLL_MS })
  const health = useApiResource(getHealth, { intervalMs: POLL_MS })

  const s = stats.data

  return (
    <div>
      <PageHeader
        title="Overview"
        subtitle="Traffic gateway → Cowrie honeypot → MT3 classification → adaptive reconfiguration"
      />

      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <MetricCard icon={Activity} label="Sessions classified" value={hasData(stats) ? num(s.total_sessions) : '—'} sublabel="by MT3, all time" />
        <MetricCard icon={Users} label="Unique attackers" value={hasData(stats) ? num(s.unique_attackers) : '—'} sublabel="distinct source IPs" />
        <MetricCard icon={Ban} label="Blacklisted IPs" value={hasData(stats) ? num(s.blocked_ips) : '—'} sublabel={hasData(stats) ? `${num(s.whitelisted_ips)} whitelisted` : ''} accent="high" />
        <MetricCard icon={Gauge} label="Mean confidence" value={hasData(stats) ? pct(s.mean_confidence) : '—'} sublabel="MT3 top-1 probability" />
        <MetricCard icon={ShieldHalf} label="Config changes" value={hasData(stats) ? num(s.config_changes) : '—'} sublabel="honeypot adaptations" accent="medium" />
        <MetricCard icon={BellRing} label="Alerts fired" value={hasData(stats) ? num(s.alerts_fired) : '—'} sublabel="phase 7–8 reached" accent="critical" />
      </div>

      <div className="mb-6">
        <PipelineFlow />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel
          className="xl:col-span-2"
          title="Latest Classified Sessions"
          subtitle="GET /api/live-feed · click a row for the full session"
          actions={
            <Link to="/sessions" className="flex items-center gap-1 text-xs font-medium text-accent hover:underline">
              View all <ArrowUpRight className="h-3.5 w-3.5" />
            </Link>
          }
        >
          <Resource
            resource={feed}
            emptyTitle="No sessions classified yet"
            emptyDescription="Sessions appear here when Cowrie closes them and MT3 classifies them. Try demo/simulate_attack.py --reset-config."
          >
            {(d) => <SessionTable records={d.results} compact />}
          </Resource>
        </Panel>

        <Panel title="Kill-Chain Phase Distribution" subtitle="All MT3-classified sessions (GET /api/stats)">
          <Resource resource={stats}>
            {(d) => <ThreatDistributionDonut distribution={d.phase_distribution} />}
          </Resource>
        </Panel>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        {hasData(config) ? (
          <ActiveConfigCard config={config.data.active_config} compact />
        ) : (
          <Panel title="Active Honeypot Config" icon={ShieldHalf}>
            <Resource resource={config}>{() => null}</Resource>
          </Panel>
        )}
        <SystemStatusCard health={health} stats={stats} />
        {hasData(stats) ? (
          <GatewaySummary stats={stats.data} />
        ) : (
          <Panel title="Gateway Pre-filter" icon={Route}>
            <Resource resource={stats}>{() => null}</Resource>
          </Panel>
        )}
      </div>
    </div>
  )
}
