import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Network, ShieldHalf, Terminal, Route } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import Panel from '../components/common/Panel'
import Resource from '../components/common/Resource'
import EmptyState from '../components/common/EmptyState'
import IpActions from '../components/common/IpActions'
import { LevelBadge, VerdictBadge } from '../components/common/Badges'
import PredictionCard from '../components/sessions/PredictionCard'
import { useApiResource } from '../hooks/useApiResource'
import { getLiveFeed, getBlacklist, getWhitelist } from '../services/api'
import { duration, fmtDateTime } from '../lib/format'

function BackButton() {
  const navigate = useNavigate()
  return (
    <button
      type="button"
      onClick={() => navigate('/sessions')}
      className="flex items-center gap-1.5 rounded-md border border-base-border bg-base-raised px-3 py-1.5 text-xs font-medium text-text-secondary hover:text-text-primary"
    >
      <ArrowLeft className="h-3.5 w-3.5" /> Back to sessions
    </button>
  )
}

function Row({ label, children, mono }) {
  return (
    <>
      <dt className="text-text-muted">{label}</dt>
      <dd className={`text-right text-text-primary ${mono ? 'font-mono text-xs' : ''}`}>{children}</dd>
    </>
  )
}

function show(v) {
  if (v === true) return 'on'
  if (v === false) return 'off'
  if (v === null || v === undefined || v === '') return '—'
  return String(v)
}

function ConnectionCard({ r, lists, onChanged }) {
  const ip = r.src_ip
  const bl = lists.bl.has(ip)
  const wl = lists.wl.has(ip)
  return (
    <Panel title="Session" icon={Network} actions={ip && <IpActions ip={ip} isBlacklisted={bl} isWhitelisted={wl} onDone={onChanged} />}>
      <dl className="grid grid-cols-2 gap-y-2 text-sm">
        <Row label="Session ID" mono>{r.session_id}</Row>
        <Row label="Source IP" mono>
          {ip || '—'}
          {bl && <span className="ml-1.5 text-[10px] font-semibold text-risk-critical">BLACKLISTED</span>}
          {wl && <span className="ml-1.5 text-[10px] font-semibold text-risk-low">WHITELISTED</span>}
        </Row>
        {r.observed_src_ip && <Row label="Cowrie saw" mono>{r.observed_src_ip} (proxy; peer recovered from gateway log)</Row>}
        <Row label="Started">{fmtDateTime(r.timestamp)}</Row>
        <Row label="Classified">{fmtDateTime(r.processed_at)}</Row>
        <Row label="Duration">{duration(r.duration_s)}</Row>
        <Row label="Login attempts">{r.login_attempts ?? '—'}</Row>
        <Row label="Pipeline latency">{typeof r.latency_ms === 'number' ? `${r.latency_ms} ms` : '—'}</Row>
        <Row label="Auto-blacklisted by MT3">{r.auto_blacklisted ? 'yes' : 'no'}</Row>
      </dl>
    </Panel>
  )
}

function GatewayCard({ r }) {
  return (
    <Panel title="Gateway Pre-filter" icon={Route} subtitle="traffic_classifier.py at connection time (not MT3)">
      <dl className="grid grid-cols-2 gap-y-2 text-sm">
        <Row label="Verdict"><VerdictBadge verdict={r.gateway_verdict} /></Row>
        <Row label="Score">{typeof r.gateway_score === 'number' ? r.gateway_score.toFixed(3) : '—'}</Row>
      </dl>
      <div className="mt-3 text-xs text-text-muted">Signals fired</div>
      {r.gateway_signals?.length ? (
        <div className="mt-1 flex flex-wrap gap-1.5">
          {r.gateway_signals.map((s) => (
            <span key={s} className="rounded border border-base-border bg-base-raised px-1.5 py-0.5 font-mono text-[11px] text-text-secondary">
              {s}
            </span>
          ))}
        </div>
      ) : (
        <p className="mt-1 text-xs text-text-muted">none</p>
      )}
    </Panel>
  )
}

function AdaptationCard({ r }) {
  const a = r.honeypot_action || {}
  const diff = Object.entries(a.diff || {})
  const honeyfs = Object.entries(a.honeyfs || {})
  return (
    <Panel title="Honeypot Response" icon={ShieldHalf} subtitle="adaptive_honeypot/configurator.py — applies to the NEXT session">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <LevelBadge level={a.previous_config?.interaction_level} />
        <span className="text-text-muted">→</span>
        <LevelBadge level={a.new_config?.interaction_level} />
        {a.changed ? (
          <span className="text-xs font-medium text-risk-high">config changed</span>
        ) : (
          <span className="text-xs text-text-muted">no change</span>
        )}
        {a.alert_fired && <span className="text-xs font-semibold text-risk-critical">EXTERNAL ALERT FIRED</span>}
      </div>
      <p className="mt-2 text-xs text-text-secondary">{a.reason || '—'}</p>
      {diff.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {diff.map(([field, d]) => (
            <span key={field} className="rounded border border-base-border bg-base-raised px-1.5 py-0.5 font-mono text-[11px] text-text-secondary">
              {field}: {show(d.from)} → <span className="text-text-primary">{show(d.to)}</span>
            </span>
          ))}
        </div>
      )}
      {honeyfs.length > 0 && (
        <div className="mt-3 text-xs">
          <div className="text-text-muted">Honeyfs bait</div>
          <ul className="mt-1 space-y-0.5 font-mono">
            {honeyfs.map(([path, what]) => (
              <li key={path} className={what === 'planted' ? 'text-risk-critical' : 'text-text-secondary'}>
                /{path} {what}
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  )
}

function CommandsCard({ r }) {
  const cmds = r.commands || []
  return (
    <Panel title="Commands Typed" icon={Terminal} actions={<span className="text-xs text-text-muted">{cmds.length}</span>}>
      {cmds.length === 0 ? (
        <p className="text-xs text-text-muted">No shell commands in this session.</p>
      ) : (
        <ol className="space-y-1">
          {cmds.map((c, i) => (
            <li key={i} className="flex gap-2 rounded-md bg-base-raised px-2.5 py-1.5 font-mono text-xs">
              <span className="text-text-muted">$</span>
              <span className="break-all text-text-primary">{c}</span>
            </li>
          ))}
        </ol>
      )}
    </Panel>
  )
}

export default function SessionDetailsPage() {
  const { sessionId } = useParams()
  const feed = useApiResource(() => getLiveFeed({ limit: 1000 }), { deps: [sessionId] })
  const bl = useApiResource(getBlacklist)
  const wl = useApiResource(getWhitelist)

  const lists = {
    bl: new Set((bl.data?.blacklist || []).map((e) => e.ip)),
    wl: new Set((wl.data?.whitelist || []).map((e) => e.ip)),
  }
  const reloadLists = () => {
    bl.reload()
    wl.reload()
  }

  return (
    <Resource resource={feed}>
      {(d) => {
        const r = (d.results || []).find((x) => x.session_id === sessionId)
        if (!r) {
          return (
            <div>
              <PageHeader title="Session not found" subtitle={`No classified session "${sessionId}"`} actions={<BackButton />} />
              <EmptyState
                title="Not in the latest 1,000 results"
                description="It may be older than the window /api/live-feed returns, or the results log was cleared."
              />
            </div>
          )
        }
        return (
          <div>
            <PageHeader
              title={`Session ${r.session_id}`}
              subtitle={`${r.src_ip || 'unknown source'} · started ${fmtDateTime(r.timestamp)}`}
              actions={<BackButton />}
            />
            <div className="mb-4">
              <PredictionCard record={r} />
            </div>
            <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
              <ConnectionCard r={r} lists={lists} onChanged={reloadLists} />
              <GatewayCard r={r} />
              <AdaptationCard r={r} />
            </div>
            <CommandsCard r={r} />
            <p className="mt-4 text-xs text-text-muted">
              Keystroke-level events for this IP are on{' '}
              <Link to="/access" className="text-accent hover:underline">Live Access</Link>.
            </p>
          </div>
        )
      }}
    </Resource>
  )
}
