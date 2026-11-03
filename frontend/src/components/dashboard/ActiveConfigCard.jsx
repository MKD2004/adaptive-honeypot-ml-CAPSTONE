import { ShieldHalf } from 'lucide-react'
import RiskBadge, { phaseToRisk } from '../common/RiskBadge'
import StatusBadge from '../common/StatusBadge'

const LEVEL_LABEL = { low: 'Low', medium: 'Medium', high: 'High', maximum: 'Maximum' }

// Also used against the REAL /api/active-config response (Stage 5A) — its
// shape matches this component's expected fields exactly (Stage 4 report §G).
// When micro_state is null the backend has never seen a session and is
// serving HoneypotConfigurator.default_config() (adaptive_honeypot/
// configurator.py:235-247) — flagged explicitly so it's never mistaken for
// a real adaptation.
export default function ActiveConfigCard({ config }) {
  const isDefault = !config.micro_state

  return (
    <div className="rounded-2xl border border-border bg-card p-6 shadow-card">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldHalf className="h-4 w-4 text-chart-1" strokeWidth={1.75} />
          <h3 className="text-base font-semibold text-foreground">Adaptive Honeypot — Active Config</h3>
        </div>
        <RiskBadge level={phaseToRisk(config.phase)} label={`${LEVEL_LABEL[config.interaction_level]} interaction`} />
      </div>

      {isDefault && (
        <div className="mb-3">
          <StatusBadge status="unknown" label="Backend default — no session observed yet" />
        </div>
      )}

      <dl className="grid grid-cols-2 gap-y-2.5 text-sm">
        <dt className="text-muted-foreground">Honeypot target</dt>
        <dd className="text-right font-mono text-xs text-foreground">{config.honeypot_target}</dd>

        <dt className="text-muted-foreground">Kill-chain phase</dt>
        <dd className="text-right text-foreground">{config.phase_name}</dd>

        <dt className="text-muted-foreground">Triggering micro-state</dt>
        <dd className="text-right font-mono text-xs text-chart-1">{config.micro_state ?? '—'}</dd>

        <dt className="text-muted-foreground">Banner</dt>
        <dd className="text-right font-mono text-xs text-foreground/80">{config.banner}</dd>
      </dl>

      <p className="mt-3 border-t border-border/60 pt-3 text-xs text-muted-foreground">{config.reason}</p>
    </div>
  )
}
