import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { PHASE_COLORS } from '../../lib/schema'
import { useChartColors } from '../../hooks/useChartColors'

function CustomTooltip({ active, payload, colors }) {
  if (!active || !payload?.length) return null
  const p = payload[0].payload
  return (
    <div
      className="rounded-md border px-3 py-2 text-xs shadow-card"
      style={{ background: colors.tooltipBg, borderColor: colors.tooltipBorder, color: colors.tooltipText }}
    >
      <div className="font-medium">{p.name}</div>
      <div style={{ color: colors.axis }}>{p.count} sessions &middot; avg {(p.avgConfidence * 100).toFixed(1)}% confidence</div>
      <div className="mt-1 text-[10px]" style={{ color: colors.axis }}>Click to filter by this phase</div>
    </div>
  )
}

// Clickable bar chart of the 9 kill-chain phases — clicking a bar sets the
// page's phase filter (bidirectional with the phase dropdown). Selected
// phase is highlighted; others dim slightly so the selection reads clearly.
export default function PhaseAnalyticsChart({ data, selectedPhase, onSelectPhase }) {
  const colors = useChartColors()
  const chartData = data.map((p, i) => ({ ...p, color: PHASE_COLORS[i] }))

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={chartData} margin={{ top: 4, right: 8, left: -16, bottom: 24 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} vertical={false} />
        <XAxis
          dataKey="name"
          tick={{ fill: colors.axis, fontSize: 10 }}
          axisLine={{ stroke: colors.tooltipBorder }}
          tickLine={false}
          angle={-30}
          textAnchor="end"
          interval={0}
          height={50}
        />
        <YAxis tick={{ fill: colors.axis, fontSize: 11 }} axisLine={false} tickLine={false} width={32} />
        <Tooltip cursor={{ fill: colors.accentSoft }} content={<CustomTooltip colors={colors} />} />
        <Bar
          dataKey="count"
          radius={[3, 3, 0, 0]}
          maxBarSize={40}
          cursor="pointer"
          onClick={(entry) => onSelectPhase(String(entry.id))}
        >
          {chartData.map((entry) => (
            <Cell
              key={entry.id}
              fill={entry.color}
              opacity={selectedPhase === 'all' || String(entry.id) === selectedPhase ? 1 : 0.35}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
