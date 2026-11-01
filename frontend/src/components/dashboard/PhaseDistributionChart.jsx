import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useChartColors } from '../../hooks/useChartColors'

// Not currently used by DashboardPage (replaced by ThreatDistributionDonut
// in the Stage 3 redesign) — kept as a reusable bar-chart component for a
// future page. Uses useChartColors so it stays theme-correct if reused.
export default function PhaseDistributionChart({ data }) {
  const colors = useChartColors()
  const chartData = data.map((d) => ({
    name: d.phase_name,
    count: d.count,
    phase: d.phase,
  }))

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={chartData} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} vertical={false} />
        <XAxis
          dataKey="phase"
          tick={{ fill: colors.axis, fontSize: 11 }}
          axisLine={{ stroke: colors.tooltipBorder }}
          tickLine={false}
        />
        <YAxis tick={{ fill: colors.axis, fontSize: 11 }} axisLine={false} tickLine={false} width={28} />
        <Tooltip
          cursor={{ fill: colors.accentSoft }}
          contentStyle={{
            background: colors.tooltipBg,
            border: `1px solid ${colors.tooltipBorder}`,
            borderRadius: 8,
            fontSize: 12,
            color: colors.tooltipText,
          }}
          labelFormatter={(_, payload) => payload?.[0]?.payload?.name ?? ''}
        />
        <Bar dataKey="count" fill={colors.accent} radius={[3, 3, 0, 0]} maxBarSize={36} />
      </BarChart>
    </ResponsiveContainer>
  )
}
