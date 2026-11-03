import { Terminal } from 'lucide-react'

// Surfaces session.commands / session.login_attempts — the literal commands
// Cowrie captured, as the pipeline recorded them. `break-all` keeps long
// captured commands from overflowing the card on narrow screens.
export default function CommandsObservedCard({ session }) {
  const commands = session.commands || []

  return (
    <div className="rounded-2xl border border-border bg-card p-6 shadow-card">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-chart-1" strokeWidth={1.75} />
          <h3 className="text-base font-semibold text-foreground">Commands Observed</h3>
        </div>
        <span className="text-xs text-muted-foreground">
          {session.login_attempts} login attempt{session.login_attempts === 1 ? '' : 's'}
        </span>
      </div>

      {commands.length === 0 ? (
        <p className="text-xs text-muted-foreground">No shell commands captured for this session.</p>
      ) : (
        <ul className="space-y-1.5">
          {commands.map((cmd, i) => (
            <li
              key={i}
              className="break-all rounded-xl bg-muted/50 px-2.5 py-1.5 font-mono text-xs text-foreground/80"
            >
              {cmd}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
