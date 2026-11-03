import { useMemo } from 'react'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { PHASE_COLORS } from '../../lib/schema'
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

// MT3-classified sessions per kill-chain phase, from GET /api/stats
// `phase_distribution` ([{phase, phase_name, count}] for all 9 phases).
export default function ThreatDistributionDonut({ distribution }) {
  const colors = useChartColors()

  const data = useMemo(
    () =>
      (distribution || [])
        .map((p) => ({ name: p.phase_name, value: p.count, color: PHASE_COLORS[p.phase] }))
        .filter((d) => d.value > 0),
    [distribution],
  )
  const total = data.reduce((s, d) => s + d.value, 0)

  if (total === 0) {
    return (
      <EmptyState
        title="No sessions classified yet"
        description="MT3 classifies each Cowrie session when it closes. Run demo/simulate_attack.py or connect through the gateway."
      />
    )
  }

  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
      <div className="relative mx-auto h-[180px] w-[180px] shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" innerRadius={55} outerRadius={84} paddingAngle={2} stroke="none">
              {data.map((d) => (
                <Cell key={d.name} fill={d.color} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip colors={colors} />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-semibold tabular-nums text-text-primary">{total}</span>
          <span className="text-[11px] text-text-muted">sessions</span>
        </div>
      </div>

      <ul className="flex-1 space-y-1.5 text-xs">
        {data.map((d) => (
          <li key={d.name} className="flex items-center justify-between gap-3">
            <span className="flex items-center gap-2 text-text-secondary">
              <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: d.color }} />
              {d.name}
            </span>
            <span className="tabular-nums text-text-muted">
              {d.value} · {Math.round((d.value / total) * 100)}%
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}
