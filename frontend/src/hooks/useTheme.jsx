import { createContext, useCallback, useContext, useEffect, useState } from 'react'

// Keep in sync with the inline no-flash script in index.html.
const STORAGE_KEY = 'honeypot-frontend-theme'

const ThemeContext = createContext(null)

function getSystemTheme() {
  // Light-first: the Pulse theme this dashboard uses is designed light-only,
  // so dark is opt-in (explicit choice or an OS that asks for it). Keep this in
  // sync with the pre-paint script in index.html.
  if (typeof window === 'undefined') return 'light'
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function getInitialTheme() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored === 'light' || stored === 'dark') return stored
  } catch {
    // localStorage unavailable (private browsing, blocked storage, etc.)
  }
  return getSystemTheme()
}

// Mutate the DOM class synchronously (not inside an effect) so it happens
// before React re-renders — anything that reads computed CSS variables
// during render (e.g. hooks/useChartColors.js) sees the new theme immediately
// instead of racing a child-before-parent effect order.
function applyTheme(theme) {
  document.documentElement.classList.toggle('dark', theme === 'dark')
}

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(getInitialTheme)

  // Safety net for the very first mount (the inline script already handles
  // this in practice, but this keeps React's state and the DOM in sync even
  // if that script were ever removed).
  useEffect(() => {
    applyTheme(theme)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const setTheme = useCallback((next) => {
    applyTheme(next)
    try {
      localStorage.setItem(STORAGE_KEY, next)
    } catch {
      // theme still applies for this session even if it can't persist
    }
    setThemeState(next)
  }, [])

  const toggleTheme = useCallback(() => {
    setTheme(theme === 'dark' ? 'light' : 'dark')
  }, [theme, setTheme])

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used within a ThemeProvider')
  return ctx
}
