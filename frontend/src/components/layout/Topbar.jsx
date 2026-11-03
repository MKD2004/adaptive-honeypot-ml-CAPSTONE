import { useLocation, matchPath } from 'react-router-dom'
import { RefreshCw, Wifi, WifiOff } from 'lucide-react'
import { useApiResource, API_STATUS } from '../../hooks/useApiResource'
import { getHealth } from '../../services/api'
import { cn } from '../../lib/cn'

// The Pulse console's 64px header: title and subtitle on the left, status and
// actions on the right. Titles come from the route rather than from each page,
// which is why PageHeader now renders only a page's own actions.
const ROUTE_TITLES = [
  { path: '/', end: true, title: 'System Overview', subtitle: 'Live honeypot activity and MT3 classification' },
  { path: '/sessions/:sessionId', title: 'Session Detail', subtitle: 'One classified attacker session' },
  { path: '/sessions', title: 'Sessions', subtitle: 'Attacker sessions classified by MT3' },
  { path: '/mitre', title: 'MITRE Analysis', subtitle: '45 micro-states across 9 kill-chain phases' },
  { path: '/analytics', title: 'Threat Analytics', subtitle: 'Per-micro-state prediction analytics' },
  { path: '/adaptive', title: 'Honeypot Configuration', subtitle: 'Interaction level and adaptation history' },
  { path: '/logs', title: 'Gateway Logs', subtitle: 'Routing decisions and captured footprints' },
  { path: '/cve/:cveId', title: 'CVE Detail', subtitle: 'Vulnerability record' },
  { path: '/cve', title: 'CVE Intelligence', subtitle: 'Vulnerability context for honeypot baiting' },
]

function titleFor(pathname) {
  for (const entry of ROUTE_TITLES) {
    if (matchPath({ path: entry.path, end: entry.end ?? false }, pathname)) return entry
  }
  return { title: 'Not Found', subtitle: 'No such page' }
}

export default function Topbar() {
  const { pathname } = useLocation()
  const { title, subtitle } = titleFor(pathname)

  // One global connection indicator, rather than a badge repeated on every
  // page. /api/health is the cheapest endpoint on the Flask API.
  const health = useApiResource(getHealth, { deps: [] })
  const offline =
    health.status === API_STATUS.UNREACHABLE || health.status === API_STATUS.ERROR
  const mt3Loaded = Boolean(health.data?.mt3)

  return (
    <header className="flex h-16 shrink-0 items-center justify-between border-b border-border bg-card px-8">
      <div className="min-w-0">
        <h1 className="truncate text-lg font-semibold tracking-tight text-foreground">{title}</h1>
        <p className="truncate text-sm text-muted-foreground">{subtitle}</p>
      </div>

      <div className="flex items-center gap-3">
        {!offline && (
          <span
            className={cn(
              'hidden rounded-full px-2.5 py-1 text-[11px] font-medium lg:inline-flex',
              mt3Loaded ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground',
            )}
            title={
              mt3Loaded
                ? 'The pipeline has MT3 loaded in memory'
                : 'The API is up but the MT3 watcher has not started'
            }
          >
            {mt3Loaded ? 'MT3 loaded' : 'MT3 not loaded'}
          </span>
        )}

        <span
          className={cn(
            'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium',
            offline ? 'bg-destructive/10 text-destructive' : 'bg-success/10 text-success',
          )}
        >
          {offline ? (
            <WifiOff className="h-3.5 w-3.5" strokeWidth={2} />
          ) : (
            <Wifi className="h-3.5 w-3.5" strokeWidth={2} />
          )}
          {offline ? 'Gateway offline' : 'Gateway live'}
        </span>

        <button
          type="button"
          onClick={() => window.location.reload()}
          className="inline-flex items-center gap-2 rounded-lg border border-border bg-transparent px-3 py-1.5 text-sm text-foreground/80 transition-colors hover:bg-muted hover:text-foreground"
        >
          <RefreshCw className="h-4 w-4" strokeWidth={1.75} />
          <span className="hidden sm:inline">Refresh</span>
        </button>
      </div>
    </header>
  )
}
