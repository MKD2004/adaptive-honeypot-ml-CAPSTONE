function Row({ label, value, mono }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={`text-right text-foreground ${mono ? 'font-mono text-xs' : ''}`}>{value}</dd>
    </div>
  )
}

export default function SessionMetadataCard({ session }) {
  return (
    <div className="rounded-2xl border border-border bg-card p-6 shadow-card">
      <h3 className="mb-4 text-base font-semibold text-foreground">Session Metadata</h3>
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
