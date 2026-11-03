import { Link, useNavigate } from 'react-router-dom'
import { Activity, Server, Cpu, Shield, Layers } from 'lucide-react'
import { useApiResource, API_STATUS } from '../../hooks/useApiResource'
import { getHealth, getActiveConfig } from '../../services/api'
import { getSessions } from '../../services/sessions'
import AnimatedList from '../common/AnimatedList'
import { KILL_CHAIN_PHASES } from '../../lib/schema'
import { cn } from '../../lib/cn'

// The Pulse console's 280px right rail: a system-status block, then a live
// activity feed. Here that is the pipeline's own state and the most recent MT3
// classifications, which is the closest equivalent to its incident feed.

const INTERACTION_TONE = {
  low: 'bg-success/15 text-success',
  medium: 'bg-chart-4/20 text-chart-4',
  high: 'bg-destructive/15 text-destructive',
  maximum: 'bg-destructive/20 text-destructive',
}

function StatusRow({ icon: Icon, label, value, ok }) {
  return (
    <div className="flex items-center gap-2.5">
      <Icon className="h-4 w-4 shrink-0 text-muted-foreground" strokeWidth={1.75} />
      <span className="flex-1 text-xs text-muted-foreground">{label}</span>
      <span
        className={cn(
          'flex items-center gap-1.5 text-xs font-medium',
          ok === false ? 'text-destructive' : ok === true ? 'text-success' : 'text-foreground',
        )}
      >
        {ok !== null && ok !== undefined && (
          <span
            className={cn(
              'h-1.5 w-1.5 rounded-full',
              ok ? 'bg-success' : 'bg-destructive',
            )}
          />
        )}
        {value}
      </span>
    </div>
  )
}

function phaseTone(phase) {
  if (phase >= 7) return 'bg-destructive/20 text-destructive'
  if (phase >= 4) return 'bg-destructive/10 text-destructive'
  if (phase >= 2) return 'bg-chart-4/20 text-chart-4'
  return 'bg-chart-1/10 text-chart-1'
}

function relativeTime(iso) {
  if (!iso) return ''
  const diff = Date.now() - new Date(iso).getTime()
  if (Number.isNaN(diff)) return ''
  const mins = Math.round(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.round(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.round(hrs / 24)}d ago`
}

export default function RightPanel() {
  const navigate = useNavigate()
  const health = useApiResource(getHealth, { deps: [] })
  const config = useApiResource(getActiveConfig, { deps: [] })
  const sessions = useApiResource(getSessions, {
    deps: [],
    isEmpty: (data) => !data?.sessions?.length,
  })

  const offline = health.status === API_STATUS.UNREACHABLE || health.status === API_STATUS.ERROR
  const h = health.data ?? {}
  const active = config.data?.active_config ?? null
  const rows = sessions.data?.sessions ?? []
  // AnimatedList keys on `id`, falling back to the array index. Index keys
  // would let React reuse a row's DOM — and with it the engine's per-item
  // reveal state — when a new session lands at the top and shifts the rest.
  const recent = rows.slice(0, 8).map((s) => ({ ...s, id: s.session_id }))

  const level = active?.interaction_level
  const phaseMeta = Number.isFinite(active?.phase) ? KILL_CHAIN_PHASES[active.phase] : null

  return (
    <aside className="hidden h-screen w-[280px] shrink-0 flex-col overflow-hidden border-l border-border bg-card xl:flex">
      {/* System status */}
      <div className="border-b border-border p-5">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-base font-semibold text-foreground">System Status</h3>
          <span
            className={cn(
              'rounded-full px-2 py-0.5 text-[10px] font-medium',
              offline ? 'bg-destructive/10 text-destructive' : 'bg-success/10 text-success',
            )}
          >
            {offline ? 'offline' : 'online'}
          </span>
        </div>
        <div className="space-y-3">
          <StatusRow
            icon={Server}
            label="Flask API"
            value={offline ? 'unreachable' : 'up'}
            ok={!offline}
          />
          <StatusRow
            icon={Cpu}
            label="MT3 model"
            value={h.mt3 ? 'loaded' : 'not loaded'}
            ok={offline ? null : Boolean(h.mt3)}
          />
          <StatusRow
            icon={Activity}
            label="Watcher"
            value={h.pipeline_started ? 'running' : 'idle'}
            ok={offline ? null : Boolean(h.pipeline_started)}
          />
          <StatusRow
            icon={Shield}
            label="Classifier routing"
            value={h.classifier_routing ? 'on' : 'off'}
            ok={null}
          />
          <StatusRow icon={Layers} label="Gateway port" value={h.gateway_port ?? '—'} ok={null} />
        </div>
      </div>

      {/* Honeypot posture */}
      <div className="border-b border-border p-5">
        <h3 className="mb-4 text-base font-semibold text-foreground">Honeypot Posture</h3>
        {active ? (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Interaction</span>
              <span
                className={cn(
                  'rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase',
                  INTERACTION_TONE[level] ?? 'bg-muted text-muted-foreground',
                )}
              >
                {level ?? 'unknown'}
              </span>
            </div>
            <div className="rounded-xl bg-muted/50 p-3">
              <p className="font-mono text-[11px] text-foreground">{active.micro_state ?? '—'}</p>
              <p className="mt-1 text-[11px] text-muted-foreground">
                {phaseMeta ? `Phase ${active.phase} · ${phaseMeta.name}` : 'No phase recorded'}
              </p>
            </div>
            <p className="text-[11px] leading-relaxed text-muted-foreground">{active.reason ?? ''}</p>
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">
            No configuration recorded yet — the honeypot has not adapted on this machine.
          </p>
        )}
      </div>

      {/* Recent classifications */}
      <div className="flex-1 overflow-y-auto p-5">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-base font-semibold text-foreground">Recent Classifications</h3>
          <Link to="/sessions" className="text-[11px] font-medium text-chart-1 hover:underline">
            All
          </Link>
        </div>
        {recent.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            Nothing classified yet. MT3 runs when a session closes.
          </p>
        ) : (
          // frame={false}: the rail already is the surface, so the list's own
          // panel would be a second card inside a card. Width is fluid rather
          // than the component's 420px default, and arrow-key navigation is
          // off because this is a peripheral rail -- the arrows belong to
          // whatever the reader is actually working in.
          <AnimatedList
            items={recent}
            frame={false}
            width="100%"
            maxHeight={420}
            gap={8}
            radius={12}
            fadeSize={28}
            stagger={0.04}
            animation="pop"
            animateOnce
            displayScrollbar={false}
            enableArrowNavigation={false}
            onItemSelect={(s) => navigate(`/sessions/${s.session_id}`)}
            renderItem={(s) => (
              <span className="min-w-0 flex-1">
                <span className="mb-1.5 flex items-start justify-between gap-2">
                  <span
                    className={cn(
                      'rounded-full px-2 py-0.5 text-[10px] font-semibold',
                      phaseTone(s.phase ?? 0),
                    )}
                  >
                    P{s.phase ?? '?'}
                  </span>
                  <span className="font-mono text-[10px] text-muted-foreground">
                    {s.session_id.slice(0, 8)}
                  </span>
                </span>
                <span className="block truncate font-mono text-[11px] font-medium text-foreground">
                  {s.micro_state ?? 'unclassified'}
                </span>
                <span className="mt-1.5 flex items-center justify-between text-[10px] text-muted-foreground">
                  <span>{Number.isFinite(s.confidence) ? `${(s.confidence * 100).toFixed(0)}%` : '—'}</span>
                  <span>{relativeTime(s.timestamp)}</span>
                </span>
              </span>
            )}
          />
        )}
      </div>
    </aside>
  )
}
