import { useEffect, useState } from 'react'
import StatusBadge from '../common/StatusBadge'
import { useApiResource, API_STATUS } from '../../hooks/useApiResource'
import { getHealth } from '../../services/api'

// Live connection strip, polled from GET /api/health: is the API up, is MT3
// loaded, which routing mode is the gateway in, and the command peers type.
export default function Topbar() {
  const [now, setNow] = useState(new Date())
  const health = useApiResource(getHealth, { intervalMs: 5000 })

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  const h = health.data
  const up = health.status === API_STATUS.SUCCESS
  const down = health.status === API_STATUS.UNREACHABLE || health.status === API_STATUS.ERROR

  return (
    <header className="flex h-14 items-center gap-3 border-b border-base-border bg-base-surface px-6">
      {up && h?.lan_ip && (
        <div className="hidden min-w-0 items-center gap-2 text-xs text-text-muted md:flex">
          <span>Peers connect with</span>
          <code className="truncate rounded bg-base-raised px-2 py-1 font-mono text-text-primary">
            ssh root@{h.lan_ip} -p {h.gateway_port}
          </code>
        </div>
      )}

      <div className="ml-auto flex items-center gap-2">
        {health.status === API_STATUS.LOADING && <StatusBadge status="unknown" label="Connecting…" />}
        {down && <StatusBadge status="offline" label="API offline" />}
        {up && (
          <>
            <StatusBadge status="online" label="API live" pulse />
            <StatusBadge
              status={h.mt3 ? 'online' : 'degraded'}
              label={h.mt3 ? 'MT3 loaded' : 'MT3 not loaded'}
            />
            <StatusBadge
              status="info"
              label={h.classifier_routing ? 'Classifier routing' : 'Zero-trust routing'}
            />
          </>
        )}
        <span className="hidden pl-1 font-mono text-xs text-text-muted sm:inline">
          {now.toLocaleTimeString('en-US', { hour12: false })}
        </span>
      </div>
    </header>
  )
}
