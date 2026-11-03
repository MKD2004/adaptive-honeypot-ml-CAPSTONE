import { ShieldHalf } from 'lucide-react'

const LEVEL_LABEL = { low: 'Low', medium: 'Medium', high: 'High', maximum: 'Maximum' }

// Per-session mock of the adaptive honeypot's decision. Not a live read of
// adaptive_honeypot/configurator.py — that project-wide state is shown on
// the Adaptive Honeypot page (later stage).
export default function AdaptiveDecisionCard({ session }) {
  return (
    <div className="rounded-2xl border border-border bg-card p-6 shadow-card">
      <div className="mb-3 flex items-center gap-2">
        <ShieldHalf className="h-4 w-4 text-chart-1" strokeWidth={1.75} />
        <h3 className="text-base font-semibold text-foreground">Adaptive Decision</h3>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <div className="text-xs uppercase tracking-wide text-muted-foreground">Previous Interaction Level</div>
          <div className="mt-1 text-sm font-medium text-foreground/80">
            {LEVEL_LABEL[session.previous_interaction_level]}
          </div>
        </div>
        <div>
          <div className="text-xs uppercase tracking-wide text-muted-foreground">Current Interaction Level</div>
          <div className="mt-1 text-sm font-medium text-foreground">
            {LEVEL_LABEL[session.interaction_level]}
          </div>
        </div>
      </div>

      <p className="mt-3 border-t border-border/60 pt-3 text-xs text-muted-foreground">
        <span className="font-medium text-foreground/80">Reason: </span>
        {session.adaptive_reason}
      </p>
    </div>
  )
}
