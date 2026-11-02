function formatTs(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleTimeString('en-US', { hour12: false })
}

const KIND_LABEL = {
  input: 'command',
  failed: 'login failed',
  success: 'login success',
  connect: 'session opened',
}

// Renders GET /api/footprints' `footprints[]` — raw Cowrie-captured input
// (traffic_gateway/api.py:383-442). This is literal attacker keystrokes, not
// a MITRE-classified event; no micro-state/phase/confidence exists on this
// endpoint, so none is shown here.
export default function FootprintsTable({ footprints }) {
  return (
    <div className="overflow-x-auto scrollbar-thin">
      <table className="w-full min-w-[600px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-base-border text-left text-xs uppercase tracking-wide text-text-muted">
            <th className="py-2 pr-4 font-medium">Time</th>
            <th className="py-2 pr-4 font-medium">IP</th>
            <th className="py-2 pr-4 font-medium">Kind</th>
            <th className="py-2 pr-4 font-medium">Detail</th>
          </tr>
        </thead>
        <tbody>
          {footprints.map((f, i) => (
            <tr key={i} className="border-b border-base-borderMuted">
              <td className="py-2.5 pr-4 text-xs text-text-muted">{formatTs(f.ts)}</td>
              <td className="py-2.5 pr-4 font-mono text-xs text-text-primary">{f.ip || '—'}</td>
              <td className="py-2.5 pr-4 text-text-secondary">{KIND_LABEL[f.kind] || f.kind || '—'}</td>
              <td className="py-2.5 pr-4 font-mono text-xs text-text-secondary">{f.detail || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
