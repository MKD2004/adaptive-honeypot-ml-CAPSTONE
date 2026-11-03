import { History, TrendingUp } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import Panel from '../components/common/Panel'
import Resource from '../components/common/Resource'
import ActiveConfigCard from '../components/dashboard/ActiveConfigCard'
import ConfigChangeHistory from '../components/adaptive/ConfigChangeHistory'
import EscalationLadder from '../components/adaptive/EscalationLadder'
import ThreatIntelPanel from '../components/adaptive/ThreatIntelPanel'
import { useApiResource, hasData } from '../hooks/useApiResource'
import { getActiveConfig, getConfigChanges } from '../services/api'

const POLL_MS = 5000

export default function HoneypotConfigPage() {
  const active = useApiResource(getActiveConfig, { intervalMs: POLL_MS })
  const history = useApiResource(() => getConfigChanges({ limit: 50 }), {
    intervalMs: POLL_MS,
    isEmpty: (d) => !d?.changes?.length,
  })

  return (
    <div>
      <PageHeader
        title="Adaptive Honeypot"
        subtitle="MT3's kill-chain phase sets the honeypot's interaction level; the configurator plants or removes bait in Cowrie's honeyfs, so the next attacker sees a different system with no container restart."
      />

      <div className="mb-6 grid grid-cols-1 gap-4 xl:grid-cols-2">
        {hasData(active) ? (
          <ActiveConfigCard config={active.data.active_config} />
        ) : (
          <Panel title="Active Honeypot Config">
            <Resource resource={active}>{() => null}</Resource>
          </Panel>
        )}
        <Panel title="Escalation Policy" icon={TrendingUp} subtitle="Deeper in the kill chain → more the attacker is allowed to touch">
          <EscalationLadder currentLevel={active.data?.active_config?.interaction_level} />
        </Panel>
      </div>

      <div className="mb-6">
        <ThreatIntelPanel />
      </div>

      <Panel
        title="Configuration History"
        icon={History}
        subtitle="logs/honeypot_config_changes.jsonl · every change with its cause, newest first"
      >
        <Resource
          resource={history}
          emptyTitle="No configuration changes yet"
          emptyDescription="The honeypot changes when MT3 classifies a session into a different phase band. demo/simulate_attack.py --reset-config walks it low → medium → high."
        >
          {(d) => <ConfigChangeHistory changes={d.changes} />}
        </Resource>
      </Panel>
    </div>
  )
}
