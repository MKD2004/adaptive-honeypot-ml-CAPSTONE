/** @type {import('tailwindcss').Config} */
// Color values are CSS variables (see src/index.css :root / .dark), so every
// utility class below is theme-aware automatically — no per-component
// light/dark branching needed. `<alpha-value>` lets Tailwind's opacity
// modifiers (e.g. bg-risk-low/10) keep working through the variable.
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        base: {
          bg: 'rgb(var(--color-base-bg) / <alpha-value>)',
          surface: 'rgb(var(--color-base-surface) / <alpha-value>)',
          raised: 'rgb(var(--color-base-raised) / <alpha-value>)',
          border: 'rgb(var(--color-base-border) / <alpha-value>)',
          borderMuted: 'rgb(var(--color-base-border-muted) / <alpha-value>)',
        },
        text: {
          primary: 'rgb(var(--color-text-primary) / <alpha-value>)',
          secondary: 'rgb(var(--color-text-secondary) / <alpha-value>)',
          muted: 'rgb(var(--color-text-muted) / <alpha-value>)',
        },
        accent: {
          DEFAULT: 'rgb(var(--color-accent) / <alpha-value>)',
          dim: 'rgb(var(--color-accent-dim) / <alpha-value>)',
          soft: 'rgb(var(--color-accent-soft) / <alpha-value>)',
        },
        risk: {
          critical: 'rgb(var(--color-risk-critical) / <alpha-value>)',
          high: 'rgb(var(--color-risk-high) / <alpha-value>)',
          medium: 'rgb(var(--color-risk-medium) / <alpha-value>)',
          low: 'rgb(var(--color-risk-low) / <alpha-value>)',
          info: 'rgb(var(--color-risk-info) / <alpha-value>)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 2px var(--shadow-card)',
      },
    },
  },
  plugins: [],
}
