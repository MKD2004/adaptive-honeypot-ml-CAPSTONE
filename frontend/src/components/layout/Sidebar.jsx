import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Radar,
  Activity,
  ShieldHalf,
  BarChart3,
  ListChecks,
  Crosshair,
  BrainCircuit,
  ShieldCheck,
} from 'lucide-react'
import { cn } from '../../lib/cn'
import ThemeToggle from './ThemeToggle'

// One entry per stage of the pipeline the panel needs to see:
// gateway routing -> classified sessions -> adaptive config -> analytics,
// plus access control and the reference pages (taxonomy, model).
// Session Details is reached by clicking a session, not from the nav.
const NAV_SECTIONS = [
  {
    heading: 'Live',
    items: [
      { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
      { to: '/access', label: 'Live Access', icon: Radar },
      { to: '/sessions', label: 'Classified Sessions', icon: Activity },
      { to: '/adaptive', label: 'Adaptive Honeypot', icon: ShieldHalf },
    ],
  },
  {
    heading: 'Analysis',
    items: [
      { to: '/analytics', label: 'Threat Analytics', icon: BarChart3 },
      { to: '/lists', label: 'Access Lists', icon: ListChecks },
    ],
  },
  {
    heading: 'Reference',
    items: [
      { to: '/mitre', label: 'MITRE Taxonomy', icon: Crosshair },
      { to: '/model', label: 'Model & Dataset', icon: BrainCircuit },
    ],
  },
]

export default function Sidebar() {
  return (
    <aside className="flex h-screen w-60 shrink-0 flex-col border-r border-base-border bg-base-surface">
      <div className="flex items-center gap-2 border-b border-base-border px-4 py-4">
        <ShieldCheck className="h-5 w-5 text-accent" strokeWidth={1.75} />
        <div className="leading-tight">
          <div className="text-sm font-semibold text-text-primary">Adaptive Honeypot</div>
          <div className="text-[11px] text-text-muted">Gateway · Cowrie · MT3</div>
        </div>
      </div>

      <nav className="flex-1 space-y-4 overflow-y-auto px-2 py-3 scrollbar-thin">
        {NAV_SECTIONS.map((section) => (
          <div key={section.heading}>
            <div className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-wider text-text-muted">
              {section.heading}
            </div>
            <div className="space-y-0.5">
              {section.items.map(({ to, label, icon: Icon, end }) => (
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
            </div>
          </div>
        ))}
      </nav>

      <div className="border-t border-base-border p-3">
        <ThemeToggle />
      </div>
    </aside>
  )
}
