import { Link } from 'react-router-dom'
import { Radio, Activity, ShieldAlert, Gauge, ArrowUpRight } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import MetricCard from '../components/common/MetricCard'
import StatusBadge from '../components/common/StatusBadge'
import SessionTable from '../components/sessions/SessionTable'
import ThreatDistributionDonut from '../components/dashboard/ThreatDistributionDonut'
import SystemStatusCard from '../components/dashboard/SystemStatusCard'
import { mockLiveSessions, MOCK_DATA_GENERATED_AT, getSessionSummary } from '../data/mockData'

// Approved Stage 3 layout: 4 metric cards, Recent Sessions, Threat
// Distribution (by the real 9 kill-chain phases), System Status. Nothing
// else — no bot-activity trend, top-attacker ranking, geography, or other
// sections outside this scope.
export default function DashboardPage() {
  const summary = getSessionSummary(mockLiveSessions)

  return (
    <div>
      <PageHeader
        title="Dashboard"
        subtitle="Real-time overview of honeypot activity and ML-based threat detection"
        actions={
          <div className="flex flex-col items-end gap-1">
            <StatusBadge status="mock" label="Mock Data" />
            <span className="text-[11px] text-text-muted">
              Last updated {new Date(MOCK_DATA_GENERATED_AT).toLocaleString('en-US', { hour12: false })}
            </span>
          </div>
        }
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <MetricCard
          icon={Radio}
          label="Active Sessions"
          value={summary.active}
          sublabel="currently open"
        />
        <MetricCard
          icon={Activity}
          label="Total Sessions"
          value={summary.total}
          sublabel="in this mock window"
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
          <SessionTable sessions={mockLiveSessions} limit={5} variant="dashboard" />
        </div>

        <div className="space-y-4">
          <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
            <h3 className="mb-3 text-sm font-semibold text-text-primary">Threat Distribution</h3>
            <ThreatDistributionDonut sessions={mockLiveSessions} />
          </div>
          <SystemStatusCard />
        </div>
      </div>
    </div>
  )
}
