/** @type {import('tailwindcss').Config} */
// Token names and values match the Pulse console's theme
// (pulse-engineering-metrics-and-incident-response-console/app/globals.css).
// That project is Tailwind v4 and declares them with `@theme inline`; this one
// is v3, so each token is an oklch channel triple in src/index.css and is
// wrapped here as oklch(var(--x) / <alpha-value>). The <alpha-value> is what
// keeps the design's opacity modifiers working -- bg-destructive/10,
// bg-success/15, bg-chart-1/20 and friends.
const c = (name) => `oklch(var(--${name}) / <alpha-value>)`

export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        background: c('background'),
        foreground: c('foreground'),
        card: {
          DEFAULT: c('card'),
          foreground: c('card-foreground'),
        },
        popover: {
          DEFAULT: c('popover'),
          foreground: c('popover-foreground'),
        },
        primary: {
          DEFAULT: c('primary'),
          foreground: c('primary-foreground'),
        },
        secondary: {
          DEFAULT: c('secondary'),
          foreground: c('secondary-foreground'),
        },
        muted: {
          DEFAULT: c('muted'),
          foreground: c('muted-foreground'),
        },
        accent: {
          DEFAULT: c('accent'),
          foreground: c('accent-foreground'),
        },
        destructive: {
          DEFAULT: c('destructive'),
          foreground: c('destructive-foreground'),
        },
        border: c('border'),
        input: c('input'),
        ring: c('ring'),

        'chart-1': c('chart-1'),
        'chart-2': c('chart-2'),
        'chart-3': c('chart-3'),
        'chart-4': c('chart-4'),
        'chart-5': c('chart-5'),

        sidebar: {
          DEFAULT: c('sidebar'),
          foreground: c('sidebar-foreground'),
          border: c('sidebar-border'),
        },

        'surface-elevated': c('surface-elevated'),
        'surface-sunken': c('surface-sunken'),
        success: c('success'),
        warning: c('warning'),
        info: c('info'),

        // Kill-chain risk ramp, kept from the previous theme because the
        // RiskBadge and the phase charts key off it. Mapped onto the Pulse
        // palette so it belongs to the same system: critical/high borrow
        // destructive and warning, medium the amber accent, low success.
        risk: {
          critical: c('destructive'),
          high: c('warning'),
          medium: c('chart-4'),
          low: c('success'),
          info: c('info'),
        },
      },
      fontFamily: {
        sans: ['"DM Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        serif: ['"Source Serif 4"', 'Georgia', 'serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      borderRadius: {
        sm: 'calc(var(--radius) - 4px)',
        md: 'calc(var(--radius) - 2px)',
        lg: 'var(--radius)',
        xl: 'calc(var(--radius) + 4px)',
        '2xl': 'calc(var(--radius) + 8px)',
      },
      boxShadow: {
        card: 'var(--shadow-card)',
        'card-hover': 'var(--shadow-card-hover)',
      },
    },
  },
  plugins: [],
}
