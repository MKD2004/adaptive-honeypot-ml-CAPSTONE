import { cn } from '../../lib/cn'

// Borderless tinted pills with an uppercase label, as the Pulse console
// renders its severity chips.
const LEVELS = {
  critical: { label: 'Critical', cls: 'bg-destructive/20 text-destructive' },
  high: { label: 'High', cls: 'bg-destructive/10 text-destructive' },
  medium: { label: 'Medium', cls: 'bg-chart-4/20 text-chart-4' },
  low: { label: 'Low', cls: 'bg-success/15 text-success' },
  info: { label: 'Info', cls: 'bg-info/10 text-info' },
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
    <span className={cn('inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide', cfg.cls)}>
      {label ?? cfg.label}
    </span>
  )
}
