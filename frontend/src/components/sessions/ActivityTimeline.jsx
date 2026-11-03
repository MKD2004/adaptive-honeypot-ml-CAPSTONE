function formatTs(iso) {
  return new Date(iso).toLocaleTimeString('en-US', { hour12: false })
}

export default function ActivityTimeline({ events }) {
  return (
    <ol className="relative ml-2 border-l border-border pl-5">
      {events.map((e, i) => (
        <li key={i} className="relative mb-5 last:mb-0">
          <span className="absolute -left-[25px] mt-1 h-2.5 w-2.5 rounded-full border-2 border-card bg-chart-1" />
          <div className="flex flex-wrap items-baseline justify-between gap-x-3">
            <span className="text-sm font-medium text-foreground">{e.label}</span>
            <span className="font-mono text-xs text-muted-foreground">{formatTs(e.ts)}</span>
          </div>
          {e.detail && <p className="mt-0.5 text-xs text-foreground/80">{e.detail}</p>}
        </li>
      ))}
    </ol>
  )
}
