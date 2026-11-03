import PageHeader from '../components/common/PageHeader'
import StatusBadge from '../components/common/StatusBadge'
import LoadingState from '../components/common/LoadingState'
import DisconnectedState from '../components/common/DisconnectedState'
import ErrorState from '../components/common/ErrorState'
import EmptyState from '../components/common/EmptyState'
import ActiveConfigCard from '../components/dashboard/ActiveConfigCard'
import ConfigChangeHistory from '../components/adaptive/ConfigChangeHistory'
import { useApiResource, API_STATUS } from '../hooks/useApiResource'
import { getActiveConfig, getConfigChanges, API_BASE_URL } from '../services/api'

const UNREACHABLE_MSG = `Could not reach ${API_BASE_URL}. Start it with: python -m traffic_gateway.run_pipeline (or traffic_gateway.api).`

export default function HoneypotConfigPage() {
  const activeConfig = useApiResource(getActiveConfig, { deps: [] })
  const history = useApiResource(getConfigChanges, {
    deps: [],
    isEmpty: (data) => !data?.changes?.length,
  })

  // Reflects what actually happened, not an assumption — was previously a
  // hardcoded "Live" badge shown even while both requests below were
  // reporting "Gateway API unreachable."
  const anyUnreachable =
    activeConfig.status === API_STATUS.UNREACHABLE || history.status === API_STATUS.UNREACHABLE
  const headerBadge = anyUnreachable ? (
    <StatusBadge status="offline" label="Gateway Unreachable" />
  ) : (
    <StatusBadge status="running" label="Live: traffic_gateway/api.py" />
  )

  return (
    <div>
      <PageHeader
        title="Honeypot Configuration"
        subtitle="Interaction level, configuration history, adaptation events"
        actions={headerBadge}
      />

      <div className="mb-6">
        {activeConfig.status === API_STATUS.LOADING && <LoadingState label="Loading active configuration…" />}
        {activeConfig.status === API_STATUS.UNREACHABLE && (
          <DisconnectedState title="Gateway API unreachable" description={UNREACHABLE_MSG} />
        )}
        {activeConfig.status === API_STATUS.ERROR && (
          <ErrorState title="Could not load /api/active-config" description={activeConfig.error?.message} />
        )}
        {(activeConfig.status === API_STATUS.SUCCESS || activeConfig.status === API_STATUS.EMPTY) &&
          activeConfig.data?.active_config && <ActiveConfigCard config={activeConfig.data.active_config} />}
      </div>

      <div className="rounded-2xl border border-border bg-card p-6 shadow-card">
        <h3 className="mb-4 text-base font-semibold text-foreground">Configuration History</h3>

        {history.status === API_STATUS.LOADING && <LoadingState label="Loading configuration history…" />}
        {history.status === API_STATUS.UNREACHABLE && (
          <DisconnectedState title="Gateway API unreachable" description={UNREACHABLE_MSG} />
        )}
        {history.status === API_STATUS.ERROR && (
          <ErrorState title="Could not load /api/config-changes" description={history.error?.message} />
        )}
        {history.status === API_STATUS.EMPTY && (
          <EmptyState
            title="No configuration changes recorded yet"
            description="The honeypot hasn't adapted to any session on this machine — logs/honeypot_config_changes.jsonl doesn't exist yet (see the Stage 4 inspection report)."
          />
        )}
        {history.status === API_STATUS.SUCCESS && history.data?.changes && (
          <ConfigChangeHistory changes={history.data.changes} />
        )}
      </div>
    </div>
  )
}
