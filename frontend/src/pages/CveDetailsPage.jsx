import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, ShieldAlert } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import EmptyState from '../components/common/EmptyState'
import RiskBadge from '../components/common/RiskBadge'
import StatusBadge from '../components/common/StatusBadge'
import { getCveById, CVE_DATA_SNAPSHOT_NOTE } from '../data/mockCves'

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('en-US', { hour12: false })
}

function BackButton({ onClick }) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-1.5 rounded-md border border-base-border bg-base-raised px-3 py-1.5 text-xs font-medium text-text-secondary transition-colors hover:text-text-primary"
    >
      <ArrowLeft className="h-3.5 w-3.5" strokeWidth={1.75} />
      Back to CVE Intelligence
    </button>
  )
}

function Row({ label, value, mono }) {
  return (
    <div className="flex items-center justify-between gap-3 py-2">
      <dt className="text-text-muted">{label}</dt>
      <dd className={`text-right text-text-primary ${mono ? 'font-mono text-xs' : ''}`}>{value}</dd>
    </div>
  )
}

// Handles a missing/unknown CVE ID gracefully — same not-found pattern used
// by SessionDetailsPage, for visual/behavioral consistency across the app.
export default function CveDetailsPage() {
  const { cveId } = useParams()
  const navigate = useNavigate()
  const cve = getCveById(cveId)

  if (!cve) {
    return (
      <div>
        <PageHeader
          title="CVE not found"
          subtitle={`No sample record matches "${cveId}"`}
          actions={<BackButton onClick={() => navigate('/cve')} />}
        />
        <EmptyState
          title="No matching CVE record"
          description="It may not be part of this 45-record sample dataset. Go back and pick another row."
        />
      </div>
    )
  }

  return (
    <div>
      <PageHeader
        title={cve.cve_id}
        subtitle={cve.kev_name}
        actions={<BackButton onClick={() => navigate('/cve')} />}
      />

      <div className="mb-6 flex flex-wrap items-center gap-2">
        <RiskBadge level={cve.severity.toLowerCase()} />
        {cve.is_kev && <StatusBadge status="offline" label="CISA KEV listed" />}
        <span className="rounded-full border border-base-border px-2.5 py-1 text-xs text-text-secondary">
          {cve.priority_tier}
        </span>
        {cve.cwe && (
          <span className="rounded-full border border-base-border px-2.5 py-1 font-mono text-xs text-text-secondary">
            {cve.cwe}
          </span>
        )}
      </div>

      <div className="mb-6 rounded-lg border border-accent/30 bg-base-surface p-4 shadow-card">
        <div className="mb-3 flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-accent" strokeWidth={1.75} />
          <h3 className="text-sm font-semibold text-text-primary">Description</h3>
        </div>
        <p className="whitespace-pre-wrap break-words text-sm text-text-secondary">{cve.description}</p>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
          <h3 className="mb-1 text-sm font-semibold text-text-primary">Scoring</h3>
          <dl className="divide-y divide-base-borderMuted">
            <Row label="CVSS Score" value={cve.cvss_score.toFixed(1)} />
            <Row label="EPSS Score" value={`${(cve.epss_score * 100).toFixed(1)}%`} />
            <Row label="Severity" value={cve.severity} />
            <Row label="Attack Type" value={cve.attack_type} />
            <Row label="Priority Tier" value={cve.priority_tier} />
            <Row label="CWE" value={cve.cwe || 'Not classified in sample'} mono={!!cve.cwe} />
          </dl>
        </div>

        <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
          <h3 className="mb-1 text-sm font-semibold text-text-primary">Timeline &amp; KEV Status</h3>
          <dl className="divide-y divide-base-borderMuted">
            <Row label="Published" value={formatDate(cve.published)} />
            <Row label="Last Modified" value={formatDate(cve.last_modified)} />
            <Row label="CISA KEV Listed" value={cve.is_kev ? 'Yes' : 'No'} />
            <Row label="KEV Date Added" value={cve.kev_date_added || '—'} />
            <Row label="CVE ID" value={cve.cve_id} mono />
          </dl>
        </div>
      </div>

      <p className="mt-6 text-xs text-text-muted">{CVE_DATA_SNAPSHOT_NOTE}</p>
    </div>
  )
}
