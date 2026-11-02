import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import EmptyState from '../components/common/EmptyState'
import StatusBadge from '../components/common/StatusBadge'
import RiskBadge from '../components/common/RiskBadge'
import ConnectionInfoCard from '../components/sessions/ConnectionInfoCard'
import MLPredictionCard from '../components/sessions/MLPredictionCard'
import ActivityTimeline from '../components/sessions/ActivityTimeline'
import AdaptiveDecisionCard from '../components/sessions/AdaptiveDecisionCard'
import SessionMetadataCard from '../components/sessions/SessionMetadataCard'
import CommandsObservedCard from '../components/sessions/CommandsObservedCard'
import { getSessionById } from '../data/mockData'

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

export default function SessionDetailsPage() {
  const { sessionId } = useParams()
  const navigate = useNavigate()
  const session = getSessionById(sessionId)

  if (!session) {
    return (
      <div>
        <PageHeader
          title="Session not found"
          subtitle={`No mock session matches "${sessionId}"`}
          actions={<BackButton onClick={() => navigate('/sessions')} />}
        />
        <EmptyState
          title="No matching session"
          description="It may have scrolled out of the mock data window. Go back and pick another row."
        />
      </div>
    )
  }

  return (
    <div>
      <PageHeader
        title={`Session ${session.session_id}`}
        subtitle={`Started ${new Date(session.first_seen).toLocaleString('en-US', { hour12: false })}`}
        actions={<BackButton onClick={() => navigate('/sessions')} />}
      />

      <div className="mb-6 flex flex-wrap items-center gap-2">
        <StatusBadge status={session.status} />
        <RiskBadge level={session.risk} />
        <span className="rounded-full border border-base-border px-2.5 py-1 font-mono text-xs text-text-secondary">
          {session.src_ip}
        </span>
        <span className="rounded-full border border-base-border px-2.5 py-1 text-xs text-text-secondary">
          {session.protocol}
        </span>
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
    </div>
  )
}
