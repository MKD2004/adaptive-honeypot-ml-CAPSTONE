import { useTheme } from './useTheme'

const FALLBACK = {
  grid: '#1a202c',
  axis: '#5f6b81',
  tooltipBg: '#161b25',
  tooltipBorder: '#232a38',
  tooltipText: '#e6e9ef',
  accent: '#3b82f6',
  accentSoft: 'rgba(59,130,246,0.06)',
}

function readVar(styles, name, fallback) {
  const v = styles.getPropertyValue(name).trim()
  return v ? `rgb(${v})` : fallback
}

function readVarAlpha(styles, name, alpha, fallback) {
  const v = styles.getPropertyValue(name).trim()
  return v ? `rgb(${v} / ${alpha})` : fallback
}

// Recharts renders literal SVG color attributes / inline tooltip styles, so
// it can't consume Tailwind classes directly. This reads the current theme's
// resolved CSS variables (index.css) so charts stay in sync with the active
// theme without hardcoding a second light/dark palette per chart.
//
// Subscribing to `theme` from context guarantees a re-render (and therefore
// a fresh read) whenever the user flips the toggle — useTheme.jsx applies
// the `dark` class synchronously before that state update, so this always
// reads the already-updated computed styles, never a stale value.
export function useChartColors() {
  const { theme } = useTheme()
  void theme // re-run this read on theme change

  if (typeof window === 'undefined') return FALLBACK

  const styles = getComputedStyle(document.documentElement)
  return {
    grid: readVar(styles, '--color-base-border-muted', FALLBACK.grid),
    axis: readVar(styles, '--color-text-muted', FALLBACK.axis),
    tooltipBg: readVar(styles, '--color-base-raised', FALLBACK.tooltipBg),
    tooltipBorder: readVar(styles, '--color-base-border', FALLBACK.tooltipBorder),
    tooltipText: readVar(styles, '--color-text-primary', FALLBACK.tooltipText),
    accent: readVar(styles, '--color-accent', FALLBACK.accent),
    accentSoft: readVarAlpha(styles, '--color-accent', 0.06, FALLBACK.accentSoft),
  }
}
