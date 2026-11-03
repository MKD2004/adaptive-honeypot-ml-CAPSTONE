import { useLayoutEffect, useRef, useState } from 'react'
import { NavLink, useLocation, matchPath } from 'react-router-dom'
import {
  LayoutDashboard,
  Radio,
  Crosshair,
  BarChart3,
  SlidersHorizontal,
  ScrollText,
  Database,
  ShieldAlert,
  Moon,
  Sun,
} from 'lucide-react'
import { useTheme } from '../../hooks/useTheme'
import { cn } from '../../lib/cn'

// Structure and spacing follow the Pulse console's app-sidebar: 260px, card
// background, a logo row with a live pill, grouped nav with uppercase section
// labels, and a solid primary pill for the active item.
//
// The highlight itself borrows GlideSelect's gliding pill: one pill per group
// that slides to whatever row the pointer is over, in the same black as the
// active item, with the same easing and durations. Unlike GlideSelect, which
// derives row positions arithmetically from a fixed row height, this measures
// each row — sidebar items are padding-sized, not a fixed height, so hardcoded
// geometry would drift the moment a label wraps or the type scale changes.

const GLIDE_MS = 220
const FADE_MS = 150
const EASE = 'cubic-bezier(0.16, 1, 0.3, 1)'

const QUICK_ACCESS = [
  { to: '/sessions', label: 'Latest Sessions', icon: Radio },
  { to: '/adaptive', label: 'Honeypot State', icon: SlidersHorizontal },
]

const PIPELINE = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/sessions', label: 'Sessions', icon: Radio },
  { to: '/mitre', label: 'MITRE Analysis', icon: Crosshair },
  { to: '/analytics', label: 'Threat Analytics', icon: BarChart3 },
  { to: '/adaptive', label: 'Honeypot Config', icon: SlidersHorizontal },
  { to: '/logs', label: 'Gateway Logs', icon: ScrollText },
]

const INTEL = [{ to: '/cve', label: 'CVE Intelligence', icon: Database, muted: true }]

// Quick Access never shows an active state — the Pulse sidebar passes
// isActive={false} for its favourites for the same reason: those routes also
// appear in the main group below, and two lit pills for one route reads as a
// bug. Here the shortcut rows light on hover only.
function activeIndexOf(items, pathname, enabled) {
  if (!enabled) return null
  const i = items.findIndex((it) => matchPath({ path: it.to, end: it.end ?? false }, pathname))
  return i === -1 ? null : i
}

// `hovered` is owned by AppSidebar, not by each group, so the sidebar can only
// ever show ONE highlight. Two rows can point at the same route (Quick Access
// duplicates Pipeline on purpose), and with per-group state both would light.
function NavGroup({ id, items, pathname, hovered, onHover, trackActive = true }) {
  // `jump` rides along with the geometry so the decision is made inside the
  // effect, never by mutating a ref during render (which StrictMode's double
  // invoke would get wrong).
  const [pill, setPill] = useState(null) // { top, height, jump }
  const listRef = useRef(null)
  const rowRefs = useRef([])
  const shown = useRef(false)

  const activeIndex = activeIndexOf(items, pathname, trackActive)
  const isHoveredGroup = hovered !== null && hovered.group === id
  // This group's pill shows when the pointer is in it, or -- when nothing
  // anywhere is hovered -- on the active route, the way GlideSelect opens with
  // its pill already on the selected row. Any hover elsewhere releases it, so
  // the resting highlight never doubles up with a hovered one.
  const index = isHoveredGroup ? hovered.index : hovered !== null ? null : activeIndex
  const setHover = (i) =>
    onHover(i === null ? null : { group: id, index: i })

  useLayoutEffect(() => {
    if (index === null || index === undefined) {
      shown.current = false
      setPill(null)
      return undefined
    }

    const measure = () => {
      const row = rowRefs.current[index]
      const list = listRef.current
      if (!row || !list) return
      // getBoundingClientRect, not offsetTop: offsetTop is relative to the
      // element's offsetParent, so mixing a row's offsetTop with the nav's own
      // offsetTop subtracts the nav's distance from the top of the sidebar and
      // throws the pill off-screen. Rects are both viewport-relative, so the
      // difference is correct whatever the positioning context, and it stays
      // correct while the Pipeline group scrolls.
      const r = row.getBoundingClientRect()
      const l = list.getBoundingClientRect()
      // Appear in place the first time rather than sliding in from the top
      // edge, matching GlideSelect's `instant` jump when its menu opens.
      const jump = !shown.current
      shown.current = true
      setPill({ top: r.top - l.top, height: r.height, jump })
    }

    measure()
    // Row heights move with the viewport (a long label can wrap), so keep the
    // pill honest rather than trusting the first measurement forever.
    window.addEventListener('resize', measure)
    return () => window.removeEventListener('resize', measure)
  }, [index, items.length])

  return (
    <nav
      ref={listRef}
      className="relative space-y-0.5"
      onPointerLeave={() => {
        if (isHoveredGroup) onHover(null)
      }}
    >
      <span
        aria-hidden="true"
        className="nav-glide-pill pointer-events-none absolute inset-x-0 top-0 rounded-lg bg-primary"
        style={{
          height: pill ? `${pill.height}px` : 0,
          transform: `translateY(${pill ? pill.top : 0}px)`,
          opacity: pill ? 1 : 0,
          transition: pill?.jump
            ? `opacity ${FADE_MS}ms ease`
            : `transform ${GLIDE_MS}ms ${EASE}, opacity ${FADE_MS}ms ease`,
        }}
      />
      {items.map((item, i) => {
        const Icon = item.icon
        const lit = index === i
        return (
          <NavLink
            key={`${item.to}-${item.label}`}
            to={item.to}
            end={item.end}
            ref={(el) => {
              rowRefs.current[i] = el
            }}
            onPointerEnter={(e) => {
              if (e.pointerType === 'touch') return
              setHover(i)
            }}
            onFocus={() => setHover(i)}
            onBlur={() => {
              if (isHoveredGroup && hovered.index === i) onHover(null)
            }}
            className={cn(
              'relative z-[1] flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm',
              'transition-colors duration-200',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
              lit ? 'font-medium text-primary-foreground' : 'text-foreground/80',
            )}
          >
            <Icon className="h-[18px] w-[18px] shrink-0" strokeWidth={1.75} />
            <span className="flex-1 text-left">{item.label}</span>
            {item.muted && (
              <span
                className={cn(
                  'rounded-full px-2 py-0.5 text-[10px] font-medium transition-colors duration-200',
                  lit ? 'bg-primary-foreground/20 text-primary-foreground' : 'bg-muted text-muted-foreground',
                )}
              >
                mock
              </span>
            )}
          </NavLink>
        )
      })}
    </nav>
  )
}

function SectionLabel({ children }) {
  return (
    <p className="mb-2 px-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
      {children}
    </p>
  )
}

export default function AppSidebar() {
  const { theme, toggleTheme } = useTheme()
  const { pathname } = useLocation()
  // { group, index } | null -- one highlight for the whole sidebar.
  const [hovered, setHovered] = useState(null)

  return (
    <aside className="flex h-screen w-[260px] shrink-0 flex-col border-r border-sidebar-border bg-sidebar">
      {/* Logo */}
      <div className="flex h-16 items-center gap-3 border-b border-sidebar-border px-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-chart-1">
          <ShieldAlert className="h-5 w-5 text-primary-foreground" strokeWidth={2} />
        </div>
        <span className="text-[15px] font-semibold tracking-tight text-foreground">Honeypot</span>
        <span className="ml-auto rounded-full bg-success/10 px-2 py-0.5 text-[10px] font-medium text-success">
          MT3
        </span>
      </div>

      {/* Model identity, in place of Pulse's search box: this is the one fact
          every page is relative to, and it does not change at runtime. */}
      <div className="px-4 py-4">
        <div className="rounded-xl bg-muted/60 px-3.5 py-2.5">
          <p className="text-[11px] uppercase tracking-wider text-muted-foreground">Classifier</p>
          <p className="mt-0.5 font-mono text-xs text-foreground">MT3 · d=256 · 45 states</p>
        </div>
      </div>

      <div className="mb-2 px-4">
        <SectionLabel>Quick Access</SectionLabel>
        <NavGroup
          id="quick"
          items={QUICK_ACCESS}
          pathname={pathname}
          hovered={hovered}
          onHover={setHovered}
          trackActive={false}
        />
      </div>

      <div className="flex-1 overflow-y-auto px-4">
        <SectionLabel>Pipeline</SectionLabel>
        <NavGroup
          id="pipeline"
          items={PIPELINE}
          pathname={pathname}
          hovered={hovered}
          onHover={setHovered}
        />

        <div className="mt-5">
          <SectionLabel>Intelligence</SectionLabel>
          <NavGroup
            id="intel"
            items={INTEL}
            pathname={pathname}
            hovered={hovered}
            onHover={setHovered}
          />
        </div>
      </div>

      {/* Footer */}
      <div className="space-y-2 border-t border-sidebar-border px-4 py-4">
        <div className="flex items-center gap-3 rounded-xl px-2 py-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-chart-1/20">
            <span className="text-sm font-medium text-chart-1">HS</span>
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium text-foreground">HoneySynth-960k</p>
            <p className="truncate text-xs text-muted-foreground">128 features · 9 phases</p>
          </div>
          <button
            type="button"
            onClick={toggleTheme}
            className="rounded-lg p-1.5 transition-colors hover:bg-muted"
            aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          >
            {theme === 'dark' ? (
              <Sun className="h-4 w-4 text-muted-foreground" strokeWidth={1.75} />
            ) : (
              <Moon className="h-4 w-4 text-muted-foreground" strokeWidth={1.75} />
            )}
          </button>
        </div>
      </div>
    </aside>
  )
}
