import { useTheme } from './useTheme'

// Literal values matching the light Pulse theme, used when getComputedStyle is
// unavailable (SSR, a very early render) so a chart never draws with no colour.
const FALLBACK = {
  grid: 'oklch(0.92 0.005 250)',
  axis: 'oklch(0.55 0.01 250)',
  tooltipBg: 'oklch(1 0 0)',
  tooltipBorder: 'oklch(0.92 0.005 250)',
  tooltipText: 'oklch(0.2 0.015 250)',
  accent: 'oklch(0.55 0.18 250)',
  accentSoft: 'oklch(0.55 0.18 250 / 0.2)',
  series: [
    'oklch(0.55 0.18 250)',
    'oklch(0.65 0.15 155)',
    'oklch(0.7 0.18 350)',
    'oklch(0.78 0.18 85)',
    'oklch(0.6 0.12 200)',
  ],
}

// Tokens in index.css hold oklch CHANNELS ("L C H") so Tailwind can apply
// opacity modifiers to them; wrap them back into a colour here.
function readVar(styles, name, fallback) {
  const v = styles.getPropertyValue(name).trim()
  return v ? `oklch(${v})` : fallback
}

function readVarAlpha(styles, name, alpha, fallback) {
  const v = styles.getPropertyValue(name).trim()
  return v ? `oklch(${v} / ${alpha})` : fallback
}

// Recharts renders literal SVG colour attributes and inline tooltip styles, so
// it cannot consume Tailwind classes. This reads the active theme's resolved
// variables (src/index.css) so charts track the theme without each one
// carrying its own light/dark palette.
//
// Subscribing to `theme` guarantees a re-render, and therefore a fresh read,
// whenever the toggle flips — useTheme applies the `dark` class synchronously
// before that state update, so this always reads already-updated styles.
export function useChartColors() {
  const { theme } = useTheme()
  void theme // re-run this read on theme change

  if (typeof window === 'undefined') return FALLBACK

  const styles = getComputedStyle(document.documentElement)
  return {
    grid: readVar(styles, '--border', FALLBACK.grid),
    axis: readVar(styles, '--muted-foreground', FALLBACK.axis),
    tooltipBg: readVar(styles, '--card', FALLBACK.tooltipBg),
    tooltipBorder: readVar(styles, '--border', FALLBACK.tooltipBorder),
    tooltipText: readVar(styles, '--card-foreground', FALLBACK.tooltipText),
    accent: readVar(styles, '--chart-1', FALLBACK.accent),
    accentSoft: readVarAlpha(styles, '--chart-1', 0.2, FALLBACK.accentSoft),
    // The design's five-colour categorical ramp, in order.
    series: [
      readVar(styles, '--chart-1', FALLBACK.series[0]),
      readVar(styles, '--chart-2', FALLBACK.series[1]),
      readVar(styles, '--chart-3', FALLBACK.series[2]),
      readVar(styles, '--chart-4', FALLBACK.series[3]),
      readVar(styles, '--chart-5', FALLBACK.series[4]),
    ],
  }
}
