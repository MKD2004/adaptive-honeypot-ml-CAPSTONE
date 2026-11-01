function Row({ label, value, mono }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-text-muted">{label}</dt>
      <dd className={`text-right text-text-primary ${mono ? 'font-mono text-xs' : ''}`}>{value}</dd>
    </div>
  )
}

export default function SessionMetadataCard({ session }) {
  return (
    <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
      <h3 className="mb-3 text-sm font-semibold text-text-primary">Session Metadata</h3>
      <dl className="space-y-2.5 text-sm">
        <Row label="Session ID" value={session.session_id} mono />
        <Row label="Model" value="MT3 (d=256, 4 layers)" />
        <Row label="Model Confidence" value={`${(session.confidence * 100).toFixed(1)}%`} />
        <Row label="MITRE Phase" value={`${session.phase_name} (Phase ${session.phase})`} />
        <Row label="Feature Groups Used" value="A–F (128 features)" />
        <Row label="Session State" value={session.status} />
      </dl>
    </div>
  )
}
