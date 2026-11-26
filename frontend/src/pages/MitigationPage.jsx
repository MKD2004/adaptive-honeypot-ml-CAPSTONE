import { ShieldAlert, ShieldCheck, Eye, FileText } from 'lucide-react'

import PageHeader from '../components/common/PageHeader'
import StatusBadge from '../components/common/StatusBadge'
import DataSection from '../components/common/DataSection'
import MetricCard from '../components/common/MetricCard'
import MitigationDecisionsTable from '../components/logs/MitigationDecisionsTable'
import { useApiResource, API_STATUS } from '../hooks/useApiResource'
import { getMitigation } from '../services/api'

// The response-mitigation layer (response_mitigation/) decides what to DO about
// an MT3 verdict: divert the source to the honeypot, alert, or observe only. It
// has written an append-only audit log since it was built and nothing read it,
// so the dashboard showed blacklisted IPs (the outcome) and never the decision
// behind them. This page is that log.
//
// Read it alongside Gateway Logs, not instead of it: the routing decisions there
// are the pre-filter's heuristic verdict at CONNECT time, while these are
// post-session decisions driven by MT3's micro-state and confidence.
export default function MitigationPage() {
  const mit = useApiResource(() => getMitigation({ limit: 100 }), {
    deps: [],
    isEmpty: (data) => !data?.decisions?.length,
  })

  const counts = mit.data?.counts ?? { action: {}, outcome: {}, mode: {} }
  const n = mit.data?.decisions?.length ?? 0
  const mode = mit.data?.mode

  const headerBadge =
    mit.status === API_STATUS.UNREACHABLE ? (
      <StatusBadge status="offline" label="Gateway Unreachable" />
    ) : (
      <StatusBadge status="running" label={`Mode: ${mode ?? 'unknown'}`} />
    )

  return (
    <div>
      <PageHeader
        title="Response Mitigation"
        subtitle="What the system decided to do about each MT3 verdict, and why — diverts, alerts and observe-only, with the rule that fired."
        actions={headerBadge}
      />

      {/* OBSERVE mode records decisions without carrying them out. Saying so
          here stops a reviewer reading "divert · applied" as a live block. */}
      {mode === 'observe' && (
        <div className="mb-6 rounded-xl border border-sky-500/30 bg-sky-500/5 p-4 text-xs text-sky-700 dark:text-sky-300">
          <strong>Observe mode.</strong> Decisions are computed and recorded but
          not enforced. &ldquo;applied&rdquo; here means the decision was written to
          the audit log, not that traffic was blocked. Switch modes in
          <code className="mx-1 font-mono">response_mitigation/config.py</code>.
        </div>
      )}

      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          icon={FileText}
          label="Decisions Logged"
          value={n}
          sublabel="most recent first"
        />
        <MetricCard
          icon={ShieldAlert}
          label="Divert"
          value={counts.action?.divert ?? 0}
          sublabel="sent to the honeypot"
          accent="high"
        />
        <MetricCard
          icon={Eye}
          label="Observe Only"
          value={counts.action?.observe ?? 0}
          sublabel="recorded, no action"
          accent="info"
        />
        <MetricCard
          icon={ShieldCheck}
          label="Applied"
          value={counts.outcome?.applied ?? 0}
          sublabel="carried out as planned"
          accent="low"
        />
      </div>

      <div className="rounded-2xl border border-border bg-card p-6 shadow-card">
        <h3 className="mb-1 text-sm font-semibold text-foreground">Decision Log</h3>
        <p className="mb-3 text-xs text-muted-foreground">
          GET /api/mitigation — response_mitigation&apos;s append-only audit log.
          Confidence and micro-state are MT3&apos;s. A phase of &ldquo;—&rdquo;
          means BENIGN, which has no kill-chain phase.
        </p>
        <DataSection
          resource={mit}
          emptyTitle="No mitigation decisions recorded"
          emptyDescription="response_mitigation/logs/mitigation_audit.jsonl is empty — the pipeline has not classified a session on this machine yet."
        >
          {mit.data?.decisions && (
            <MitigationDecisionsTable decisions={mit.data.decisions} />
          )}
        </DataSection>
        {mit.data?.audit_path && (
          <p className="mt-3 font-mono text-[11px] text-muted-foreground">
            {mit.data.audit_path}
          </p>
        )}
      </div>
    </div>
  )
}
