import { useEffect, useRef, useState } from 'react'
import { Network, Server, Bug, Ban, Users, Terminal, X } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import MetricCard from '../components/common/MetricCard'
import Panel from '../components/common/Panel'
import Resource from '../components/common/Resource'
import IpActions from '../components/common/IpActions'
import { DestinationLabel, ListTags, VerdictBadge } from '../components/common/Badges'
import { useToast } from '../components/common/Toasts'
import { useApiResource, hasData } from '../hooks/useApiResource'
import { getLiveAccess, getFootprints } from '../services/api'
import { fmtTime, num } from '../lib/format'
import { cn } from '../lib/cn'

const POLL_MS = 2000

const KIND = {
  input: { label: 'CMD', cls: 'text-risk-critical border-risk-critical/30' },
  failed: { label: 'AUTH ✗', cls: 'text-risk-medium border-risk-medium/30' },
  success: { label: 'LOGIN', cls: 'text-risk-high border-risk-high/30' },
  connect: { label: 'OPEN', cls: 'text-risk-info border-risk-info/30' },
}

// Pops a toast for every routing decision that wasn't there on the previous
// poll ("192.168.0.42 connected: diverted to the HONEYPOT").
function useDecisionToasts(decisions) {
  const notify = useToast()
  const seen = useRef(null)

  useEffect(() => {
    if (!decisions) return
    const keys = decisions.map((d) => `${d.ts}|${d.ip}`)
    if (seen.current === null) {
      seen.current = new Set(keys) // first load: don't replay history
      return
    }
    decisions
      .filter((d) => !seen.current.has(`${d.ts}|${d.ip}`))
      .reverse()
      .forEach((d) => {
        if (d.target_type === 'honeypot') {
          notify('bad', `${d.ip} connected`, `Detected ${d.verdict || 'HOSTILE'}: diverted to the HONEYPOT`)
        } else if (d.target_type === 'backend') {
          notify('good', `${d.ip} connected`, 'Classified BENIGN: forwarded to the REAL SERVER')
        } else {
          notify('warn', `${d.ip} rejected`, d.reason || 'Rate limit / blocked')
        }
      })
    keys.forEach((k) => seen.current.add(k))
  }, [decisions, notify])
}

function RoutingBanner({ data }) {
  const realPort = String(data.real_backend || '').split(':').pop()
  const hpPorts = (data.honeypots || []).map((h) => String(h).split(':').pop()).join(', ')
  return (
    <div
      className={cn(
        'mb-6 rounded-lg border px-4 py-3 text-sm',
        data.classifier_routing ? 'border-risk-low/40 bg-risk-low/5' : 'border-risk-medium/40 bg-risk-medium/5',
      )}
    >
      {data.classifier_routing ? (
        <span>
          <b className="text-risk-low">Classifier routing ON:</b>{' '}
          <span className="text-text-secondary">benign IPs reach the real server, hostile ones the honeypot.</span>
        </span>
      ) : (
        <span>
          <b className="text-risk-medium">Zero-trust mode:</b>{' '}
          <span className="text-text-secondary">
            only whitelisted IPs reach the real server. Set <code className="font-mono">GATEWAY_CLASSIFIER_ROUTING=1</code>{' '}
            to let the classifier decide.
          </span>
        </span>
      )}
      <span className="ml-2 text-xs text-text-muted">
        real server :{realPort || '—'} · honeypot :{hpPorts || '—'}
      </span>
    </div>
  )
}

function PeersTable({ peers, onSelect, selectedIp, onChanged }) {
  return (
    <div className="overflow-x-auto scrollbar-thin">
      <table className="w-full min-w-[620px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-base-border text-left text-xs uppercase tracking-wide text-text-muted">
            <th className="py-2 pr-3 font-medium">IP</th>
            <th className="py-2 pr-3 font-medium">Last verdict</th>
            <th className="py-2 pr-3 font-medium">Status</th>
            <th className="py-2 pr-3 text-right font-medium">→ Real</th>
            <th className="py-2 pr-3 text-right font-medium">→ Honeypot</th>
            <th className="py-2 pr-3 text-right font-medium">Rejected</th>
            <th className="py-2 pr-3 font-medium">Last seen</th>
            <th className="py-2 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {peers.map((p) => (
            <tr
              key={p.ip}
              className={cn('border-b border-base-borderMuted', selectedIp === p.ip && 'bg-accent-soft')}
            >
              <td className="py-2 pr-3 font-mono text-xs">
                <button
                  type="button"
                  onClick={() => onSelect(selectedIp === p.ip ? '' : p.ip)}
                  title="Show this IP's keystrokes"
                  className="text-text-primary hover:text-accent hover:underline"
                >
                  {p.ip}
                </button>
                <ListTags blacklisted={p.is_blacklisted} whitelisted={p.is_whitelisted} />
              </td>
              <td className="py-2 pr-3">
                {/* rejects carry no verdict (CONN_REJECTED happens before scoring) */}
                <VerdictBadge verdict={p.last_verdict || (p.rejected ? 'REJECTED' : null)} />
              </td>
              <td className="py-2 pr-3 text-xs text-text-secondary">{p.ip_status}</td>
              <td className="py-2 pr-3 text-right tabular-nums text-risk-low">{p.to_real}</td>
              <td className="py-2 pr-3 text-right tabular-nums text-risk-critical">{p.to_honeypot}</td>
              <td className="py-2 pr-3 text-right tabular-nums text-risk-info">{p.rejected}</td>
              <td className="py-2 pr-3 text-xs text-text-muted">{fmtTime(p.last_seen)}</td>
              <td className="py-2">
                <IpActions
                  ip={p.ip}
                  isBlacklisted={p.is_blacklisted}
                  isWhitelisted={p.is_whitelisted}
                  onDone={onChanged}
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function DecisionList({ decisions }) {
  return (
    <ul className="max-h-[520px] space-y-2 overflow-y-auto pr-1 scrollbar-thin">
      {decisions.map((d, i) => (
        <li key={`${d.ts}-${d.ip}-${i}`} className="rounded-md border border-base-borderMuted p-2.5">
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-xs text-text-primary">
              {d.ip}
              <ListTags blacklisted={d.is_blacklisted} whitelisted={d.is_whitelisted} />
            </span>
            <span className="font-mono text-[11px] text-text-muted">{fmtTime(d.ts)}</span>
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs">
            <VerdictBadge verdict={d.target_type === 'reject' ? 'REJECTED' : d.verdict} />
            {typeof d.score === 'number' && <span className="text-text-muted">score {d.score.toFixed(2)}</span>}
            <span className="text-text-muted">→</span>
            <DestinationLabel destination={d.destination} />
            {d.target && <span className="font-mono text-[11px] text-text-muted">{d.target}</span>}
          </div>
          {d.signals?.length > 0 && (
            <div className="mt-1 text-[11px] text-text-secondary">signals: {d.signals.join(', ')}</div>
          )}
          {d.reason && <div className="mt-0.5 text-[11px] text-text-muted">{d.reason}</div>}
        </li>
      ))}
    </ul>
  )
}

function FootprintList({ footprints }) {
  return (
    <ul className="max-h-[520px] space-y-1 overflow-y-auto pr-1 font-mono text-xs scrollbar-thin">
      {footprints.map((f, i) => {
        const k = KIND[f.kind] ?? { label: f.kind, cls: 'text-text-muted border-base-border' }
        return (
          <li key={`${f.ts}-${i}`} className="flex items-baseline gap-2 border-b border-base-borderMuted py-1.5">
            <span className={cn('w-14 shrink-0 rounded border px-1 text-center text-[10px] font-semibold', k.cls)}>
              {k.label}
            </span>
            <span className="shrink-0 text-text-muted">{fmtTime(f.ts)}</span>
            <span className="shrink-0 text-text-secondary" title={f.observed_ip ? `Cowrie saw ${f.observed_ip}` : undefined}>
              {f.ip}
            </span>
            <span className={cn('break-all', f.kind === 'input' ? 'text-text-primary' : 'text-text-muted')}>{f.detail}</span>
          </li>
        )
      })}
    </ul>
  )
}

export default function LiveAccessPage() {
  const [ipFilter, setIpFilter] = useState('')
  const access = useApiResource(() => getLiveAccess({ limit: 80 }), { intervalMs: POLL_MS })
  const footprints = useApiResource(() => getFootprints({ limit: 120, ip: ipFilter }), {
    intervalMs: POLL_MS,
    deps: [ipFilter],
    isEmpty: (d) => !d?.footprints?.length,
  })

  useDecisionToasts(access.data?.decisions)

  const d = access.data
  const decisions = d?.decisions ?? []
  const toReal = decisions.filter((x) => x.target_type === 'backend').length
  const toHp = decisions.filter((x) => x.target_type === 'honeypot').length
  const rejected = decisions.filter((x) => x.target_type === 'reject').length

  return (
    <div>
      <PageHeader
        title="Live Access"
        subtitle="Every connection through the gateway, where it was routed, and what attackers typed inside the honeypot. Refreshes every 2 s."
      />

      {hasData(access) && <RoutingBanner data={d} />}

      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <MetricCard icon={Network} label="Connections" value={hasData(access) ? num(d.count) : '—'} sublabel="latest routing decisions" />
        <MetricCard icon={Users} label="Peers" value={hasData(access) ? num(d.peers.length) : '—'} sublabel="distinct source IPs" />
        <MetricCard icon={Server} label="→ Real server" value={hasData(access) ? num(toReal) : '—'} accent="low" />
        <MetricCard icon={Bug} label="→ Honeypot" value={hasData(access) ? num(toHp) : '—'} accent="critical" />
        <MetricCard icon={Ban} label="Rejected" value={hasData(access) ? num(rejected) : '—'} sublabel="rate limit / blocked" accent="medium" />
        <MetricCard
          icon={Terminal}
          label="Footprints"
          value={hasData(footprints) ? num(footprints.data?.count ?? 0) : '—'}
          sublabel="Cowrie events shown"
        />
      </div>

      <Panel
        className="mb-6"
        title="Connected Peers"
        subtitle="BLOCK forces the next connection into the honeypot · TRUST sends it to the real server · RESET lets the classifier decide · click an IP to filter keystrokes"
      >
        <Resource
          resource={access}
          emptyTitle="No connections yet"
          emptyDescription="Connect through the gateway (ssh root@<this laptop> -p 8080) or run demo/attack_client.py."
        >
          {(data) =>
            data.peers.length ? (
              <PeersTable peers={data.peers} onSelect={setIpFilter} selectedIp={ipFilter} onChanged={access.reload} />
            ) : (
              <p className="py-6 text-center text-xs text-text-muted">
                No connections yet. Connect through the gateway (ssh root@&lt;this laptop&gt; -p 8080) or run
                demo/attack_client.py.
              </p>
            )
          }
        </Resource>
      </Panel>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel
          title="Routing Decisions"
          subtitle="traffic_classifier.py pre-filter: score in [0,1] from IP reputation, behaviour and payload signals (not MT3)"
        >
          <Resource resource={access}>
            {(data) =>
              data.decisions.length ? (
                <DecisionList decisions={data.decisions} />
              ) : (
                <p className="py-6 text-center text-xs text-text-muted">
                  traffic_gateway/data/sessions.jsonl has no routing events yet.
                </p>
              )
            }
          </Resource>
        </Panel>

        <Panel
          title="Honeypot Footprints"
          subtitle="Raw Cowrie events: every password tried and every command typed"
          actions={
            ipFilter && (
              <button
                type="button"
                onClick={() => setIpFilter('')}
                className="flex items-center gap-1 rounded-full border border-accent/40 bg-accent-soft px-2 py-0.5 font-mono text-xs text-accent"
              >
                {ipFilter} <X className="h-3 w-3" />
              </button>
            )
          }
        >
          <Resource
            resource={footprints}
            emptyTitle={ipFilter ? `Nothing captured from ${ipFilter}` : 'Nothing captured yet'}
            emptyDescription="Reads honeypot_dataset/cowrie/logs/cowrie.json. It fills once a hostile peer lands in Cowrie."
          >
            {(data) => <FootprintList footprints={data.footprints} />}
          </Resource>
        </Panel>
      </div>
    </div>
  )
}
