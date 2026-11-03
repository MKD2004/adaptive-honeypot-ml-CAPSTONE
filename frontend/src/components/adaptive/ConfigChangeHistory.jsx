import RiskBadge, { phaseToRisk } from '../common/RiskBadge'

function formatTs(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('en-US', { hour12: false })
}

// Renders GET /api/config-changes' `changes[]` / GET /api/active-config's
// `recent_changes[]` — both come from HoneypotConfigurator.recent_changes()
// (adaptive_honeypot/configurator.py:427-439) and share this exact shape:
// { ts, reason, diff, trigger: {session_id, src_ip, micro_state, phase,
// confidence}, previous_config, new_config }. Only fields present in that
// shape are rendered — nothing here is invented.
export default function ConfigChangeHistory({ changes }) {
  return (
    <ol className="divide-y divide-border/60">
      {changes.map((c, i) => {
        const trigger = c.trigger || {}
        const newCfg = c.new_config || {}
        return (
          <li key={i} className="py-3 first:pt-0 last:pb-0">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <p className="text-sm text-foreground">{c.reason || '—'}</p>
              <span className="font-mono text-xs text-muted-foreground">{formatTs(c.ts)}</span>
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              {newCfg.interaction_level && (
                <RiskBadge
                  level={newCfg.phase !== undefined ? phaseToRisk(newCfg.phase) : 'info'}
                  label={`${newCfg.interaction_level} interaction`}
                />
              )}
              {trigger.session_id && (
                <span className="font-mono">
                  {trigger.session_id}
                  {trigger.src_ip ? ` · ${trigger.src_ip}` : ''}
                </span>
              )}
              {trigger.micro_state && (
                <span className="font-mono text-chart-1">{trigger.micro_state}</span>
              )}
              {typeof trigger.confidence === 'number' && (
                <span>p={trigger.confidence.toFixed(3)}</span>
              )}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
