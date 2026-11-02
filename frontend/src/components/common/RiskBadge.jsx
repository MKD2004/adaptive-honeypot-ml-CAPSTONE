import { cn } from '../../lib/cn'

const LEVELS = {
  critical: { label: 'Critical', cls: 'bg-risk-critical/10 text-risk-critical border-risk-critical/30' },
  high: { label: 'High', cls: 'bg-risk-high/10 text-risk-high border-risk-high/30' },
  medium: { label: 'Medium', cls: 'bg-risk-medium/10 text-risk-medium border-risk-medium/30' },
  low: { label: 'Low', cls: 'bg-risk-low/10 text-risk-low border-risk-low/30' },
  info: { label: 'Info', cls: 'bg-risk-info/10 text-risk-info border-risk-info/30' },
}

// Maps a kill-chain phase id (0-8) to a risk tier for consistent coloring
// across Dashboard, Live Sessions and Adaptive Honeypot pages.
export function phaseToRisk(phaseId) {
  if (phaseId >= 7) return 'critical'
  if (phaseId >= 4) return 'high'
  if (phaseId >= 2) return 'medium'
  return 'low'
}

export default function RiskBadge({ level = 'info', label }) {
  const cfg = LEVELS[level] ?? LEVELS.info
  return (
    <span className={cn('inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium', cfg.cls)}>
      {label ?? cfg.label}
    </span>
  )
}
