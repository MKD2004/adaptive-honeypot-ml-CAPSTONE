import { Network } from 'lucide-react'

function formatDuration(s) {
  const m = Math.floor(s / 60)
  const sec = s % 60
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`
}

function formatTs(iso) {
  return new Date(iso).toLocaleString('en-US', { hour12: false })
}

function Row({ label, value, mono }) {
  return (
    <>
      <dt className="text-text-muted">{label}</dt>
      <dd className={`text-right text-text-primary ${mono ? 'font-mono text-xs' : ''}`}>{value}</dd>
    </>
  )
}

export default function ConnectionInfoCard({ session }) {
  return (
    <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
      <div className="mb-3 flex items-center gap-2">
        <Network className="h-4 w-4 text-accent" strokeWidth={1.75} />
        <h3 className="text-sm font-semibold text-text-primary">Connection Information</h3>
      </div>
      <dl className="grid grid-cols-2 gap-y-2.5 text-sm">
        <Row label="Source IP" value={session.src_ip} mono />
        <Row label="Destination" value={session.destination} mono />
        <Row label="Protocol" value={session.protocol} />
        <Row label="Source Port" value={session.src_port} mono />
        <Row label="Destination Port" value={session.dst_port} mono />
        <Row label="Session Duration" value={formatDuration(session.duration_s)} />
        <Row label="First Seen" value={formatTs(session.first_seen)} />
        <Row label="Last Activity" value={formatTs(session.timestamp)} />
      </dl>
    </div>
  )
}
