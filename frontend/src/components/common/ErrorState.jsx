import { AlertTriangle } from 'lucide-react'

export default function ErrorState({ title = 'Something went wrong', description }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-risk-high/30 bg-risk-high/5 px-6 py-16 text-center">
      <AlertTriangle className="h-8 w-8 text-risk-high" strokeWidth={1.5} />
      <h3 className="mt-3 text-sm font-semibold text-text-primary">{title}</h3>
      {description && <p className="mt-1 max-w-md text-xs text-text-muted">{description}</p>}
    </div>
  )
}
