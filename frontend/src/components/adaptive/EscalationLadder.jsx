import { INTERACTION_LEVELS, phaseName } from '../../lib/schema'
import { LevelBadge } from '../common/Badges'
import { cn } from '../../lib/cn'

// The configurator's phase -> interaction-level policy
// (adaptive_honeypot/configurator.py PHASE_TO_LEVEL / INTERACTION_PROFILES),
// with the level currently in force highlighted.
export default function EscalationLadder({ currentLevel }) {
  return (
    <ol className="space-y-2">
      {INTERACTION_LEVELS.map((l) => {
        const active = l.key === currentLevel
        return (
          <li
            key={l.key}
            className={cn(
              'rounded-md border p-3 transition-colors',
              active ? 'border-accent bg-accent-soft' : 'border-base-borderMuted',
            )}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <LevelBadge level={l.key} />
              <span className="text-xs text-text-muted">
                Phases {l.phases.join(', ')}: {l.phases.map(phaseName).join(' / ')}
              </span>
            </div>
            <p className="mt-1.5 text-xs text-text-secondary">{l.purpose}</p>
            <p className="mt-1 text-[11px] text-text-muted">
              {l.filesystem} filesystem · {l.delayMs} ms response delay · bait: {l.bait}
            </p>
            {active && <p className="mt-1 text-[11px] font-semibold text-accent">← current posture</p>}
          </li>
        )
      })}
    </ol>
  )
}
