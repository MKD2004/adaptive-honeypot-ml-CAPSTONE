import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useChartColors } from '../../hooks/useChartColors'

function CustomTooltip({ active, payload, colors }) {
  if (!active || !payload?.length) return null
  const p = payload[0].payload
  return (
    <div
      className="rounded-md border px-3 py-2 text-xs shadow-card"
      style={{ background: colors.tooltipBg, borderColor: colors.tooltipBorder, color: colors.tooltipText }}
    >
      <div className="font-medium">{p.label} confidence</div>
      <div style={{ color: colors.axis }}>{p.count} simulated predictions</div>
    </div>
  )
}

// Simulated confidence distribution — a model *probability* bucketed by
// range, not a measure of whether any prediction was actually correct.
export default function ConfidenceHistogram({ buckets }) {
  const colors = useChartColors()

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={buckets} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} vertical={false} />
        <XAxis dataKey="label" tick={{ fill: colors.axis, fontSize: 11 }} axisLine={{ stroke: colors.tooltipBorder }} tickLine={false} />
        <YAxis tick={{ fill: colors.axis, fontSize: 11 }} axisLine={false} tickLine={false} width={32} />
        <Tooltip cursor={{ fill: colors.accentSoft }} content={<CustomTooltip colors={colors} />} />
        <Bar dataKey="count" fill={colors.accent} radius={[3, 3, 0, 0]} maxBarSize={44} />
      </BarChart>
    </ResponsiveContainer>
  )
}
