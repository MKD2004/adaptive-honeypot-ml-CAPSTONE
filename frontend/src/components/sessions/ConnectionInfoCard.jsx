import { Network } from 'lucide-react'

function formatDuration(s) {
  const m = Math.floor(s / 60)
  const sec = s % 60
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`
}

function formatTs(iso) {
  return new Date(iso).toLocaleString('en-US', { hour12: false })
}

// A dash, not a blank cell: the pipeline result carries no destination address
// and no ports (see services/sessions.js UNAVAILABLE_FIELDS), and an empty row
// reads as a rendering bug rather than as "the API does not report this".
function Row({ label, value, mono }) {
  const missing = value === null || value === undefined || value === ''
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd
        className={`text-right ${missing ? 'text-muted-foreground' : 'text-foreground'} ${
          mono && !missing ? 'font-mono text-xs' : ''
        }`}
      >
        {missing ? '—' : value}
      </dd>
    </>
  )
}

export default function ConnectionInfoCard({ session }) {
  return (
    <div className="rounded-2xl border border-border bg-card p-6 shadow-card">
      <div className="mb-3 flex items-center gap-2">
        <Network className="h-4 w-4 text-chart-1" strokeWidth={1.75} />
        <h3 className="text-base font-semibold text-foreground">Connection Information</h3>
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
