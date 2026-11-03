import { Link } from 'react-router-dom'
import { LevelBadge } from '../common/Badges'
import { fmtDateTime, pct } from '../../lib/format'

function show(v) {
  if (v === true) return 'on'
  if (v === false) return 'off'
  if (v === null || v === undefined || v === '') return '—'
  return String(v)
}

// Entries from GET /api/config-changes (adaptive_honeypot/configurator.py
// _log_change): { ts, reason, diff: {field: {from, to}}, trigger:
// {session_id, src_ip, micro_state, phase, confidence}, previous_config,
// new_config }. Newest first.
export default function ConfigChangeHistory({ changes, compact = false }) {
  return (
    <ol className="divide-y divide-base-borderMuted">
      {changes.map((c, i) => {
        const trigger = c.trigger || {}
        const diff = Object.entries(c.diff || {})
        return (
          <li key={`${c.ts}-${i}`} className="py-3 first:pt-0 last:pb-0">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <p className="text-sm text-text-primary">{c.reason || '—'}</p>
              <span className="font-mono text-xs text-text-muted">{fmtDateTime(c.ts)}</span>
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-text-muted">
              {c.new_config?.interaction_level && <LevelBadge level={c.new_config.interaction_level} />}
              {trigger.micro_state && <span className="font-mono text-accent">{trigger.micro_state}</span>}
              {typeof trigger.confidence === 'number' && <span>p={pct(trigger.confidence)}</span>}
              {trigger.src_ip && <span className="font-mono">{trigger.src_ip}</span>}
              {trigger.session_id && (
                <Link
                  to={`/sessions/${encodeURIComponent(trigger.session_id)}`}
                  className="font-mono text-accent hover:underline"
                >
                  {trigger.session_id}
                </Link>
              )}
            </div>
            {!compact && diff.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {diff.map(([field, d]) => (
                  <span
                    key={field}
                    className="rounded border border-base-border bg-base-raised px-1.5 py-0.5 font-mono text-[11px] text-text-secondary"
                  >
                    {field}: {show(d.from)} → <span className="text-text-primary">{show(d.to)}</span>
                  </span>
                ))}
              </div>
            )}
          </li>
        )
      })}
    </ol>
  )
}
