import { Inbox } from 'lucide-react'

// "The backend answered, there's just no data yet" — always says what would
// produce data, so an empty panel during a demo is self-explanatory.
export default function EmptyState({ icon: Icon = Inbox, title, description }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-base-border bg-base-surface/50 px-6 py-10 text-center">
      <Icon className="h-7 w-7 text-text-muted" strokeWidth={1.5} />
      <h3 className="mt-3 text-sm font-semibold text-text-secondary">{title}</h3>
      {description && <p className="mt-1 max-w-md text-xs text-text-muted">{description}</p>}
    </div>
  )
}
