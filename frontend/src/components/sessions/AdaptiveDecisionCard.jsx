import { ShieldHalf } from 'lucide-react'

const LEVEL_LABEL = { low: 'Low', medium: 'Medium', high: 'High', maximum: 'Maximum' }

// Per-session mock of the adaptive honeypot's decision. Not a live read of
// adaptive_honeypot/configurator.py — that project-wide state is shown on
// the Adaptive Honeypot page (later stage).
export default function AdaptiveDecisionCard({ session }) {
  return (
    <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
      <div className="mb-3 flex items-center gap-2">
        <ShieldHalf className="h-4 w-4 text-accent" strokeWidth={1.75} />
        <h3 className="text-sm font-semibold text-text-primary">Adaptive Decision</h3>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <div className="text-xs uppercase tracking-wide text-text-muted">Previous Interaction Level</div>
          <div className="mt-1 text-sm font-medium text-text-secondary">
            {LEVEL_LABEL[session.previous_interaction_level]}
          </div>
        </div>
        <div>
          <div className="text-xs uppercase tracking-wide text-text-muted">Current Interaction Level</div>
          <div className="mt-1 text-sm font-medium text-text-primary">
            {LEVEL_LABEL[session.interaction_level]}
          </div>
        </div>
      </div>

      <p className="mt-3 border-t border-base-borderMuted pt-3 text-xs text-text-muted">
        <span className="font-medium text-text-secondary">Reason: </span>
        {session.adaptive_reason}
      </p>
    </div>
  )
}
