import { createContext, useCallback, useContext, useState } from 'react'
import { cn } from '../../lib/cn'

const ToastContext = createContext(() => {})

const TONE = {
  good: 'border-risk-low/40 bg-base-surface',
  bad: 'border-risk-critical/50 bg-base-surface',
  warn: 'border-risk-medium/50 bg-base-surface',
  info: 'border-risk-info/40 bg-base-surface',
}
const BAR = { good: 'bg-risk-low', bad: 'bg-risk-critical', warn: 'bg-risk-medium', info: 'bg-risk-info' }

let nextId = 1

// Pop-up notifications: "192.168.0.42 connected — diverted to the HONEYPOT",
// "IP blacklisted", etc. Same role as live.html's toasts.
export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])

  const notify = useCallback((tone, title, body, ms = 8000) => {
    const id = nextId++
    setToasts((t) => [...t.slice(-4), { id, tone, title, body }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), ms)
  }, [])

  return (
    <ToastContext.Provider value={notify}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            role="status"
            className={cn('pointer-events-auto overflow-hidden rounded-lg border shadow-card', TONE[t.tone] ?? TONE.info)}
          >
            <div className={cn('h-0.5', BAR[t.tone] ?? BAR.info)} />
            <div className="px-3 py-2.5">
              <div className="text-sm font-medium text-text-primary">{t.title}</div>
              {t.body && <div className="mt-0.5 text-xs text-text-secondary">{t.body}</div>}
            </div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast() {
  return useContext(ToastContext)
}
