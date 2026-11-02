import { PHASE_COLORS } from '../../lib/schema'
import { cn } from '../../lib/cn'

// All 9 phases, in kill-chain order, with session counts derived from the
// sessions MT3 has classified (GET /api/live-feed) — see
// MitreAnalysisPage.jsx. Clicking a card selects it for the detail panel
// below and filters the micro-state explorer.
export default function KillChainOverview({ phases, selectedPhase, onSelectPhase }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-9">
      {phases.map((p, i) => {
        const isSelected = String(p.id) === selectedPhase
        return (
          <button
            key={p.id}
            onClick={() => onSelectPhase(isSelected ? 'all' : String(p.id))}
            className={cn(
              'rounded-lg border p-3 text-left transition-colors',
              isSelected
                ? 'border-accent bg-accent-soft'
                : 'border-base-border bg-base-surface hover:bg-base-raised',
            )}
          >
            <span
              className="mb-2 block h-2 w-2 rounded-full"
              style={{ background: PHASE_COLORS[i] }}
            />
            <div className="text-[11px] font-medium uppercase tracking-wide text-text-muted">
              Phase {p.id}
            </div>
            <div className="mt-0.5 text-sm font-semibold text-text-primary">{p.name}</div>
            <div className="mt-1 text-xs text-text-secondary">
              {p.count} session{p.count === 1 ? '' : 's'}
            </div>
            <div className="text-[11px] text-text-muted">{p.stateCount} micro-states</div>
          </button>
        )
      })}
    </div>
  )
}
