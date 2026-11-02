import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Activity,
  ShieldHalf,
  BarChart3,
  Crosshair,
  Bug,
  ScrollText,
  ShieldCheck,
} from 'lucide-react'
import { cn } from '../../lib/cn'
import ThemeToggle from './ThemeToggle'

// Session Details is deliberately not a nav item — it's only reached by
// clicking a session row, per the approved navigation design.
const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/sessions', label: 'Live Sessions', icon: Activity },
  { to: '/analytics', label: 'Threat Analytics', icon: BarChart3 },
  { to: '/mitre', label: 'MITRE Analysis', icon: Crosshair },
  { to: '/adaptive', label: 'Honeypot Configuration', icon: ShieldHalf },
  { to: '/cve', label: 'CVE Intelligence', icon: Bug },
  { to: '/logs', label: 'Logs', icon: ScrollText },
]

export default function Sidebar() {
  return (
    <aside className="flex h-screen w-60 shrink-0 flex-col border-r border-base-border bg-base-surface">
      <div className="flex items-center gap-2 border-b border-base-border px-4 py-4">
        <ShieldCheck className="h-5 w-5 text-accent" strokeWidth={1.75} />
        <div className="leading-tight">
          <div className="text-sm font-semibold text-text-primary">Adaptive Honeypot</div>
          <div className="text-[11px] text-text-muted">ML Security Dashboard</div>
        </div>
      </div>

      <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 py-3 scrollbar-thin">
        {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors',
                isActive
                  ? 'bg-accent-soft text-text-primary'
                  : 'text-text-secondary hover:bg-base-raised hover:text-text-primary',
              )
            }
          >
            <Icon className="h-4 w-4 shrink-0" strokeWidth={1.75} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-base-border p-3">
        <ThemeToggle />
      </div>
    </aside>
  )
}
