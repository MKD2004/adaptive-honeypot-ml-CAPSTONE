import { useState } from 'react'
import { Ban, ShieldCheck, X } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import Panel from '../components/common/Panel'
import Resource from '../components/common/Resource'
import { useToast } from '../components/common/Toasts'
import { useApiResource } from '../hooks/useApiResource'
import { getBlacklist, getWhitelist, blacklistIp, whitelistIp, unblacklistIp, unwhitelistIp } from '../services/api'
import { fmtDateTime, num } from '../lib/format'

const inputCls =
  'rounded-md border border-base-border bg-base-raised px-2.5 py-1.5 text-sm text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none'

function AddForm({ placeholderReason, buttonLabel, buttonCls, onAdd }) {
  const [ip, setIp] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    if (!ip.trim()) return
    setBusy(true)
    const ok = await onAdd(ip.trim(), reason.trim())
    setBusy(false)
    if (ok) {
      setIp('')
      setReason('')
    }
  }

  return (
    <form onSubmit={submit} className="mb-3 flex flex-wrap gap-2">
      <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="IP address" className={`${inputCls} w-40 font-mono`} />
      <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder={placeholderReason} className={`${inputCls} min-w-[160px] flex-1`} />
      <button type="submit" disabled={busy || !ip.trim()} className={`rounded-md px-3 py-1.5 text-xs font-semibold disabled:opacity-50 ${buttonCls}`}>
        {buttonLabel}
      </button>
    </form>
  )
}

function ListTable({ entries, sinceKey, onRemove, removeTitle }) {
  if (!entries.length) return <p className="py-6 text-center text-xs text-text-muted">Empty.</p>
  return (
    <div className="overflow-x-auto scrollbar-thin">
      <table className="w-full min-w-[560px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-base-border text-left text-xs uppercase tracking-wide text-text-muted">
            <th className="py-2 pr-3 font-medium">IP</th>
            <th className="py-2 pr-3 font-medium">Reason</th>
            <th className="py-2 pr-3 font-medium">Source</th>
            <th className="py-2 pr-3 text-right font-medium">Conns</th>
            <th className="py-2 pr-3 font-medium">Added</th>
            <th className="py-2" />
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.ip} className="border-b border-base-borderMuted">
              <td className="py-2 pr-3 font-mono text-xs text-text-primary">{e.ip}</td>
              <td className="py-2 pr-3 text-xs text-text-secondary">{e.reason || '—'}</td>
              <td className="py-2 pr-3 text-xs text-text-muted">{e.source || '—'}</td>
              <td className="py-2 pr-3 text-right tabular-nums text-xs">{num(e.total_connections ?? 0)}</td>
              <td className="py-2 pr-3 text-xs text-text-muted">{fmtDateTime(e[sinceKey])}</td>
              <td className="py-2 text-right">
                <button
                  type="button"
                  title={removeTitle}
                  onClick={() => onRemove(e.ip)}
                  className="rounded p-1 text-text-muted hover:bg-base-raised hover:text-text-primary"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// GET/POST/DELETE /api/blacklist and /api/whitelist. Blacklisted IPs are always
// routed to the honeypot; whitelisted IPs reach the real server (and get the
// higher trusted rate limit, not an exemption).
export default function AccessListsPage() {
  const notify = useToast()
  const bl = useApiResource(getBlacklist, { intervalMs: 5000 })
  const wl = useApiResource(getWhitelist, { intervalMs: 5000 })

  async function act(fn, okTitle, okBody, reload) {
    try {
      const res = await fn()
      notify('good', okTitle(res), okBody)
      reload()
      return true
    } catch (err) {
      notify('warn', 'Request failed', err.message)
      return false
    }
  }

  return (
    <div>
      <PageHeader
        title="Access Lists"
        subtitle="Manual control over the gateway's routing. MT3 also auto-blacklists any source it classifies at phase ≥ 1 (Initial Access) with confidence ≥ 0.5."
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel
          title="Blacklist"
          icon={Ban}
          subtitle="Always routed to the honeypot"
          actions={bl.data && <span className="text-xs text-text-muted">{bl.data.count}</span>}
        >
          <AddForm
            placeholderReason="Reason (optional)"
            buttonLabel="BLOCK"
            buttonCls="bg-risk-critical/15 text-risk-critical hover:bg-risk-critical/25"
            onAdd={(ip, reason) =>
              act(() => blacklistIp(ip, reason), (r) => `${r.ip} blacklisted`, 'Their next connection goes to the honeypot.', bl.reload)
            }
          />
          <Resource resource={bl}>
            {(d) => (
              <ListTable
                entries={d.blacklist}
                sinceKey="blacklisted_at"
                removeTitle="Unblock"
                onRemove={(ip) => act(() => unblacklistIp(ip), () => `${ip} unblocked`, 'Back to UNKNOWN; the classifier re-evaluates it.', bl.reload)}
              />
            )}
          </Resource>
        </Panel>

        <Panel
          title="Whitelist"
          icon={ShieldCheck}
          subtitle="Reach the real server; rate-limited at the trusted ceiling (100/min)"
          actions={wl.data && <span className="text-xs text-text-muted">{wl.data.count}</span>}
        >
          <AddForm
            placeholderReason="Reason (optional)"
            buttonLabel="TRUST"
            buttonCls="bg-risk-low/15 text-risk-low hover:bg-risk-low/25"
            onAdd={(ip, reason) =>
              act(() => whitelistIp(ip, reason), (r) => `${r.ip} whitelisted`, 'Their next connection reaches the real server.', wl.reload)
            }
          />
          <Resource resource={wl}>
            {(d) => (
              <ListTable
                entries={d.whitelist}
                sinceKey="whitelisted_at"
                removeTitle="Remove"
                onRemove={(ip) => act(() => unwhitelistIp(ip), () => `${ip} removed`, 'Back to UNKNOWN; the classifier re-evaluates it.', wl.reload)}
              />
            )}
          </Resource>
        </Panel>
      </div>
    </div>
  )
}
