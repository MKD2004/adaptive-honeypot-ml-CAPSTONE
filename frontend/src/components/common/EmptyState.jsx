import { Construction } from 'lucide-react'

// Used for backend functionality that is not yet implemented or not yet
// wired live — communicates this honestly instead of faking data.
export default function EmptyState({ icon: Icon = Construction, title, description }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-card/50 px-6 py-16 text-center">
      <Icon className="h-8 w-8 text-muted-foreground" strokeWidth={1.5} />
      <h3 className="mt-3 text-sm font-semibold text-foreground/80">{title}</h3>
      {description && <p className="mt-1 max-w-md text-xs text-muted-foreground">{description}</p>}
    </div>
  )
}
