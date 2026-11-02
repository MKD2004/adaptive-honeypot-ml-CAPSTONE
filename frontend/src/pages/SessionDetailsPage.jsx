import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import EmptyState from '../components/common/EmptyState'
import StatusBadge from '../components/common/StatusBadge'
import RiskBadge from '../components/common/RiskBadge'
import DataSection from '../components/common/DataSection'
import ConnectionInfoCard from '../components/sessions/ConnectionInfoCard'
import MLPredictionCard from '../components/sessions/MLPredictionCard'
import ActivityTimeline from '../components/sessions/ActivityTimeline'
import AdaptiveDecisionCard from '../components/sessions/AdaptiveDecisionCard'
import SessionMetadataCard from '../components/sessions/SessionMetadataCard'
import CommandsObservedCard from '../components/sessions/CommandsObservedCard'
import { useApiResource } from '../hooks/useApiResource'
import { getSessions } from '../services/sessions'

function BackButton({ onClick }) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-1.5 rounded-md border border-base-border bg-base-raised px-3 py-1.5 text-xs font-medium text-text-secondary transition-colors hover:text-text-primary"
    >
      <ArrowLeft className="h-3.5 w-3.5" strokeWidth={1.75} />
      Back to Sessions
    </button>
  )
}

function SessionBody({ session }) {
  return (
    <>
      <div className="mb-6 flex flex-wrap items-center gap-2">
        <StatusBadge status={session.status} />
        <RiskBadge level={session.risk} />
        <span className="rounded-full border border-base-border px-2.5 py-1 font-mono text-xs text-text-secondary">
          {session.src_ip}
        </span>
        {session.protocol && (
          <span className="rounded-full border border-base-border px-2.5 py-1 text-xs text-text-secondary">
            {session.protocol}
          </span>
        )}
        {session.source && (
          <span className="rounded-full border border-base-border px-2.5 py-1 text-xs text-text-secondary">
            source: {session.source}
          </span>
        )}
      </div>

      <div className="mb-6">
        <MLPredictionCard session={session} />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <ConnectionInfoCard session={session} />
        <AdaptiveDecisionCard session={session} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card lg:col-span-2">
          <h3 className="mb-4 text-sm font-semibold text-text-primary">Activity Timeline</h3>
          <ActivityTimeline events={session.timeline} />
        </div>
        <div className="space-y-4">
          <SessionMetadataCard session={session} />
          <CommandsObservedCard session={session} />
        </div>
      </div>
    </>
  )
}

// Reads the same GET /api/live-feed the list page does and picks the matching
// row out of it. There is no per-session endpoint on api.py, and the result
// file is small (one line per classified session), so fetching the window and
// filtering is cheaper than adding a backend route.
export default function SessionDetailsPage() {
  const { sessionId } = useParams()
  const navigate = useNavigate()

  const resource = useApiResource(getSessions, {
    deps: [],
    isEmpty: (data) => !data?.sessions?.length,
  })
  const session = resource.data?.sessions?.find((s) => s.session_id === sessionId)

  return (
    <div>
      <PageHeader
        title={session ? `Session ${session.session_id}` : 'Session'}
        subtitle={
          session
            ? `Started ${new Date(session.first_seen).toLocaleString('en-US', { hour12: false })}`
            : sessionId
        }
        actions={<BackButton onClick={() => navigate('/sessions')} />}
      />
      <DataSection
        resource={resource}
        loadingLabel="Loading session…"
        emptyTitle="No sessions classified yet"
        emptyDescription="logs/pipeline_results.jsonl is empty — run the pipeline and send a session to the honeypot."
      >
        {session ? (
          <SessionBody session={session} />
        ) : (
          <EmptyState
            title="No matching session"
            description={`No classified session has the id "${sessionId}". It may have scrolled out of the current window — go back and pick another row.`}
          />
        )}
      </DataSection>
    </div>
  )
}
