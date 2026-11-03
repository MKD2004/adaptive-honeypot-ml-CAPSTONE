// Small display helpers shared by every page. All timestamps from the API are
// ISO-8601 strings (UTC); these render them in the viewer's local time.

export function fmtTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleTimeString('en-US', { hour12: false })
}

export function fmtDateTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString('en-US', { hour12: false })
}

export function timeAgo(iso) {
  if (!iso) return '—'
  const ms = Date.now() - new Date(iso).getTime()
  if (Number.isNaN(ms)) return '—'
  const s = Math.round(ms / 1000)
  if (s < 60) return `${Math.max(s, 0)}s ago`
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.round(m / 60)
  if (h < 48) return `${h}h ago`
  return `${Math.round(h / 24)}d ago`
}

export function pct(p, digits = 1) {
  return typeof p === 'number' ? `${(p * 100).toFixed(digits)}%` : '—'
}

export function num(n) {
  return typeof n === 'number' ? n.toLocaleString('en-US') : '—'
}

export function duration(s) {
  if (typeof s !== 'number') return '—'
  if (s < 60) return `${s.toFixed(1)}s`
  const m = Math.floor(s / 60)
  return `${m}m ${Math.round(s % 60)}s`
}
