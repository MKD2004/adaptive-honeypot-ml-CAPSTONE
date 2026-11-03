import { Sun, Moon } from 'lucide-react'
import { useTheme } from '../../hooks/useTheme'
import { cn } from '../../lib/cn'

export default function ThemeToggle() {
  const { theme, setTheme } = useTheme()

  return (
    <div
      role="radiogroup"
      aria-label="Theme"
      className="flex items-center gap-1 rounded-md border border-base-border bg-base-raised p-1"
    >
      <button
        type="button"
        role="radio"
        aria-checked={theme === 'light'}
        onClick={() => setTheme('light')}
        className={cn(
          'flex flex-1 items-center justify-center gap-1.5 rounded px-2 py-1.5 text-xs font-medium transition-colors',
          theme === 'light'
            ? 'bg-base-surface text-text-primary shadow-card'
            : 'text-text-muted hover:text-text-secondary',
        )}
      >
        <Sun className="h-3.5 w-3.5" strokeWidth={1.75} />
        Light
      </button>
      <button
        type="button"
        role="radio"
        aria-checked={theme === 'dark'}
        onClick={() => setTheme('dark')}
        className={cn(
          'flex flex-1 items-center justify-center gap-1.5 rounded px-2 py-1.5 text-xs font-medium transition-colors',
          theme === 'dark'
            ? 'bg-base-surface text-text-primary shadow-card'
            : 'text-text-muted hover:text-text-secondary',
        )}
      >
        <Moon className="h-3.5 w-3.5" strokeWidth={1.75} />
        Dark
      </button>
    </div>
  )
}
