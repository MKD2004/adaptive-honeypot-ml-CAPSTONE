import { useState } from 'react'
import { blacklistIp, whitelistIp, resetIp } from '../../services/api'
import { useToast } from './Toasts'
import { cn } from '../../lib/cn'

const btn =
  'rounded border px-2 py-0.5 text-[11px] font-semibold tracking-wide transition-colors disabled:cursor-not-allowed disabled:opacity-50'

// BLOCK / TRUST / RESET for one IP — the live demo's access-control buttons.
// BLOCK  -> POST /api/blacklist   (next connection is forced into the honeypot)
// TRUST  -> POST /api/whitelist   (next connection reaches the real server)
// RESET  -> DELETE from both lists (the classifier decides afresh)
export default function IpActions({ ip, isBlacklisted, isWhitelisted, onDone }) {
  const notify = useToast()
  const [busy, setBusy] = useState(false)

  async function run(action) {
    setBusy(true)
    try {
      if (action === 'block') {
        await blacklistIp(ip, 'blocked from dashboard')
        notify('bad', `${ip} blacklisted`, 'Their next connection is forced into the honeypot.')
      } else if (action === 'trust') {
        await whitelistIp(ip, 'trusted from dashboard')
        notify('good', `${ip} whitelisted`, 'Their next connection reaches the real server.')
      } else {
        await resetIp(ip)
        notify('warn', `${ip} reset`, 'Removed from both lists; the classifier decides on their next connection.')
      }
      onDone?.()
    } catch (err) {
      notify('warn', `Could not update ${ip}`, err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <span className="inline-flex gap-1.5 whitespace-nowrap">
      <button
        type="button"
        disabled={busy || isBlacklisted}
        onClick={() => run('block')}
        className={cn(btn, 'border-risk-critical/40 text-risk-critical hover:bg-risk-critical/10')}
      >
        BLOCK
      </button>
      <button
        type="button"
        disabled={busy || isWhitelisted}
        onClick={() => run('trust')}
        className={cn(btn, 'border-risk-low/40 text-risk-low hover:bg-risk-low/10')}
      >
        TRUST
      </button>
      <button
        type="button"
        disabled={busy || (!isBlacklisted && !isWhitelisted)}
        onClick={() => run('reset')}
        className={cn(btn, 'border-base-border text-text-secondary hover:bg-base-raised')}
      >
        RESET
      </button>
    </span>
  )
}
