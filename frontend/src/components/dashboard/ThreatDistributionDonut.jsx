import { useMemo } from 'react'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { KILL_CHAIN_PHASES, PHASE_COLORS } from '../../lib/schema'
import { useChartColors } from '../../hooks/useChartColors'
import EmptyState from '../common/EmptyState'

function CustomTooltip({ active, payload, colors }) {
  if (!active || !payload?.length) return null
  const p = payload[0].payload
  return (
    <div
      className="rounded-md border px-3 py-2 text-xs shadow-card"
      style={{ background: colors.tooltipBg, borderColor: colors.tooltipBorder, color: colors.tooltipText }}
    >
      <div className="font-medium">{p.name}</div>
      <div style={{ color: colors.axis }}>{p.value} session{p.value === 1 ? '' : 's'}</div>
    </div>
  )
}

// Derives the distribution directly from the same session array the
// summary cards and Recent Sessions table use, so all three always agree —
// this never carries its own separate/fabricated percentages.
export default function ThreatDistributionDonut({ sessions }) {
  const colors = useChartColors()

  const data = useMemo(() => {
    const counts = new Array(KILL_CHAIN_PHASES.length).fill(0)
    sessions.forEach((s) => {
      if (counts[s.phase] !== undefined) counts[s.phase] += 1
    })
    return KILL_CHAIN_PHASES.map((p, i) => ({ name: p.name, value: counts[i], color: PHASE_COLORS[i] }))
      .filter((d) => d.value > 0)
  }, [sessions])

  const total = sessions.length

  if (total === 0 || data.length === 0) {
    return (
      <EmptyState
        title="No session data"
        description="No mock sessions are available to chart yet."
      />
    )
  }

  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
      <div className="relative mx-auto h-[190px] w-[190px] shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius={58}
              outerRadius={88}
              paddingAngle={2}
              stroke="none"
            >
              {data.map((d) => (
                <Cell key={d.name} fill={d.color} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip colors={colors} />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-semibold tabular-nums text-foreground">{total}</span>
          <span className="text-[11px] text-muted-foreground">Total Sessions</span>
        </div>
      </div>

      <ul className="flex-1 space-y-1.5 text-xs">
        {data.map((d) => (
          <li key={d.name} className="flex items-center justify-between gap-3">
            <span className="flex items-center gap-2 text-foreground/80">
              <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: d.color }} />
              {d.name}
            </span>
            <span className="tabular-nums text-muted-foreground">{Math.round((d.value / total) * 100)}%</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
