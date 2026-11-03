import { PlugZap } from 'lucide-react'

// Distinct from ErrorState on purpose: this means "the gateway API isn't
// reachable at all" (connection refused / timeout), not "it responded with
// an error." Conflating the two would make a simple "server isn't running"
// case look like a real bug.
export default function DisconnectedState({ title = 'Backend unavailable', description, action }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-risk-info/40 bg-risk-info/5 px-6 py-10 text-center">
      <PlugZap className="h-7 w-7 text-risk-info" strokeWidth={1.5} />
      <h3 className="mt-3 text-sm font-semibold text-foreground">{title}</h3>
      {description && <p className="mt-1 max-w-md text-xs text-muted-foreground">{description}</p>}
      {action}
    </div>
  )
}
