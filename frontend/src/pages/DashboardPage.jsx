import { Link } from 'react-router-dom'
import { Radio, Activity, ShieldAlert, Gauge, ArrowUpRight } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import MetricCard from '../components/common/MetricCard'
import StatusBadge from '../components/common/StatusBadge'
import DataSection from '../components/common/DataSection'
import SessionTable from '../components/sessions/SessionTable'
import ThreatDistributionDonut from '../components/dashboard/ThreatDistributionDonut'
import SystemStatusCard from '../components/dashboard/SystemStatusCard'
import { useApiResource, API_STATUS } from '../hooks/useApiResource'
import { getSessions, getSessionSummary } from '../services/sessions'

// Approved Stage 3 layout: 4 metric cards, Recent Sessions, Threat
// Distribution (by the real 9 kill-chain phases), System Status. Nothing
// else — no bot-activity trend, top-attacker ranking, geography, or other
// sections outside this scope.
//
// "Active Sessions" reads 0 by design: MT3 classifies a session only once it
// closes, because it needs the whole session for the temporal features, so
// every row here is a finished session.
export default function DashboardPage() {
  const resource = useApiResource(getSessions, {
    deps: [],
    isEmpty: (data) => !data?.sessions?.length,
  })
  const sessions = resource.data?.sessions ?? []
  const summary = getSessionSummary(sessions)
  const newest = sessions[0]?.timestamp

  return (
    <div>
      <PageHeader
        title="Dashboard"
        subtitle="Overview of honeypot activity and MT3 threat classification"
        actions={
          <div className="flex flex-col items-end gap-1">
            {resource.status === API_STATUS.UNREACHABLE ? (
              <StatusBadge status="offline" label="Gateway Unreachable" />
            ) : (
              <StatusBadge status="running" label="Live: GET /api/live-feed" />
            )}
            {newest && (
              <span className="text-[11px] text-text-muted">
                Latest session {new Date(newest).toLocaleString('en-US', { hour12: false })}
              </span>
            )}
          </div>
        }
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <MetricCard
          icon={Radio}
          label="Active Sessions"
          value={summary.active}
          sublabel="MT3 classifies on close"
        />
        <MetricCard
          icon={Activity}
          label="Sessions Classified"
          value={summary.total}
          sublabel="in this window"
        />
        <MetricCard
          icon={ShieldAlert}
          label="High Risk Sessions"
          value={summary.highRisk}
          sublabel="phase 4+ classifications"
          accent="high"
        />
        <MetricCard
          icon={Gauge}
          label="Avg. ML Confidence"
          value={`${(summary.avgConfidence * 100).toFixed(1)}%`}
          sublabel="MT3, d=256"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card lg:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-text-primary">Recent Sessions</h3>
            <Link
              to="/sessions"
              className="flex items-center gap-1 text-xs font-medium text-accent hover:underline"
            >
              View all
              <ArrowUpRight className="h-3.5 w-3.5" strokeWidth={1.75} />
            </Link>
          </div>
          <DataSection
            resource={resource}
            loadingLabel="Loading sessions…"
            emptyTitle="No sessions classified yet"
            emptyDescription="logs/pipeline_results.jsonl is empty — run python -m traffic_gateway.run_pipeline and send a session to the honeypot."
          >
            <SessionTable sessions={sessions} limit={5} variant="dashboard" />
          </DataSection>
        </div>

        <div className="space-y-4">
          <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
            <h3 className="mb-3 text-sm font-semibold text-text-primary">Threat Distribution</h3>
            <DataSection
              resource={resource}
              loadingLabel="Loading…"
              emptyTitle="Nothing to chart yet"
              emptyDescription="No classified sessions on this machine."
            >
              <ThreatDistributionDonut sessions={sessions} />
            </DataSection>
          </div>
          <SystemStatusCard />
        </div>
      </div>
    </div>
  )
}
