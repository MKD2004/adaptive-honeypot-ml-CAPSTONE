import { cn } from '../../lib/cn'

// The standard card every page section sits in.
export default function Panel({ title, subtitle, actions, icon: Icon, className, children }) {
  return (
    <section className={cn('rounded-lg border border-base-border bg-base-surface p-4 shadow-card', className)}>
      {(title || actions) && (
        <div className="mb-3 flex flex-wrap items-start justify-between gap-2">
          <div>
            <h3 className="flex items-center gap-2 text-sm font-semibold text-text-primary">
              {Icon && <Icon className="h-4 w-4 text-accent" strokeWidth={1.75} />}
              {title}
            </h3>
            {subtitle && <p className="mt-0.5 text-xs text-text-muted">{subtitle}</p>}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  )
}
