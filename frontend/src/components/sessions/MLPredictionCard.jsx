import { BrainCircuit } from 'lucide-react'
import RiskBadge from '../common/RiskBadge'
import { cn } from '../../lib/cn'

function Stat({ label, value, mono, big, accent }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-text-muted">{label}</div>
      <div
        className={cn(
          'mt-1',
          big ? 'text-2xl font-semibold tabular-nums' : 'text-sm font-medium',
          mono && 'font-mono',
          accent ? 'text-accent' : 'text-text-primary',
        )}
      >
        {value}
      </div>
    </div>
  )
}

// MT3 prediction summary for a single session. No inference happens in the
// frontend — these values come from GET /api/live-feed, which reads the
// pipeline's own logs/pipeline_results.jsonl.
export default function MLPredictionCard({ session }) {
  return (
    <div className="rounded-lg border border-accent/30 bg-base-surface p-4 shadow-card">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <BrainCircuit className="h-4 w-4 text-accent" strokeWidth={1.75} />
          <h3 className="text-sm font-semibold text-text-primary">ML Prediction</h3>
        </div>
        <RiskBadge level={session.risk} />
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="Predicted Micro-State" value={session.micro_state} mono accent />
        <Stat label="MITRE Technique" value={session.mitre} mono />
        <Stat label="Kill-Chain Phase" value={`${session.phase_name} (Phase ${session.phase})`} />
        <Stat label="Confidence" value={`${(session.confidence * 100).toFixed(1)}%`} big />
      </div>

      {Array.isArray(session.top3) && session.top3.length > 0 && (
        <div className="mt-4 border-t border-base-borderMuted pt-3">
          <div className="mb-1.5 text-xs uppercase tracking-wide text-text-muted">Top-3 Candidates</div>
          <ul className="space-y-1">
            {session.top3.map((t, i) => (
              <li key={i} className="flex items-center justify-between text-xs">
                <span className="font-mono text-text-secondary">{t.label}</span>
                <span className="tabular-nums text-text-muted">{(t.prob * 100).toFixed(1)}%</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <p className="mt-4 border-t border-base-borderMuted pt-3 text-xs text-text-muted">
        Mock prediction for UI development — the frontend performs no inference; this mirrors the
        shape of the real MT3 pipeline output.
      </p>
    </div>
  )
}
