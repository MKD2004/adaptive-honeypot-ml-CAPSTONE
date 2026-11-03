import Panel, { PanelHeader } from './Panel'

export default function ChartCard({ title, subtitle, actions, children, height = 240 }) {
  return (
    <Panel>
      <PanelHeader title={title} subtitle={subtitle} right={actions} />
      <div style={{ height }}>{children}</div>
    </Panel>
  )
}
