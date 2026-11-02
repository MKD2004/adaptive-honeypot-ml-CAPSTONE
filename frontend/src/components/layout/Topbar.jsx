import { useEffect, useState } from 'react'
import { Search } from 'lucide-react'
import StatusBadge from '../common/StatusBadge'

// No notification bell or user/profile chip here on purpose — this project
// has no auth or notification system, and inventing one was explicitly
// ruled out for this stage. The gateway indicator says "Mock Data", never
// "Online"/"Live", since no backend connection exists yet.
export default function Topbar() {
  const [now, setNow] = useState(new Date())

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  return (
    <header className="flex h-14 items-center gap-4 border-b border-base-border bg-base-surface px-6">
      <div className="relative max-w-md flex-1">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-muted" />
        {/* Disabled rather than a plain enabled-but-inert input — a search
            box that looks active but silently does nothing on Enter is a
            worse experience than one that's honestly disabled (Stage 7 QA). */}
        <input
          type="text"
          disabled
          placeholder="Search (not yet implemented)"
          title="Global search is not implemented yet"
          className="w-full cursor-not-allowed rounded-md border border-base-border bg-base-raised py-1.5 pl-8 pr-3 text-sm text-text-muted placeholder:text-text-muted opacity-60 focus:outline-none"
        />
      </div>

      <div className="ml-auto flex items-center gap-3">
        <StatusBadge status="mock" label="Mock Data" />
        <span className="hidden font-mono text-xs text-text-muted sm:inline">
          {now.toLocaleTimeString('en-US', { hour12: false })}
        </span>
      </div>
    </header>
  )
}
