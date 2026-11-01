import { ChevronRight } from 'lucide-react'

const STAGES = [
  'Traffic', 'Gateway', 'Session', '128 Features', 'ML Classification',
  'MITRE Micro-State', 'Kill-Chain Phase', 'Adaptive Config', 'Cowrie', 'Logs',
]

export default function PipelineFlow({ activeIndex = -1 }) {
  return (
    <div className="flex flex-wrap items-center gap-y-2 rounded-lg border border-base-border bg-base-surface px-4 py-3">
      {STAGES.map((stage, i) => (
        <div key={stage} className="flex items-center">
          <span
            className={
              i === activeIndex
                ? 'rounded-md border border-accent/40 bg-accent-soft px-2.5 py-1 text-xs font-medium text-accent'
                : 'px-2.5 py-1 text-xs text-text-secondary'
            }
          >
            {stage}
          </span>
          {i < STAGES.length - 1 && <ChevronRight className="h-3.5 w-3.5 text-text-muted" />}
        </div>
      ))}
    </div>
  )
}
