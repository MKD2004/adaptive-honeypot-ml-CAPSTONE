import { Server, Cpu, FileText, Activity, RefreshCw } from 'lucide-react'
import { useApiResource, API_STATUS } from '../../hooks/useApiResource'
import { getHealth, API_BASE_URL } from '../../services/api'
import StatusBadge from '../common/StatusBadge'
import LoadingState from '../common/LoadingState'
import DisconnectedState from '../common/DisconnectedState'
import ErrorState from '../common/ErrorState'

function StatusRow({ icon: Icon, label, ok, value }) {
  return (
    <li className="flex items-center justify-between text-sm">
      <span className="flex items-center gap-2 text-text-secondary">
        <Icon className="h-3.5 w-3.5 text-text-muted" strokeWidth={1.75} />
        {label}
      </span>
      <StatusBadge status={ok ? 'running' : 'offline'} label={value} />
    </li>
  )
}

// Connected to GET /api/health (traffic_gateway/api.py). Shows only fields
// that endpoint actually returns — it does NOT poll the traffic proxy,
// Cowrie, or cve_intelligence/, so this card never claims those are
// running just because the Flask API answered. See Stage 4 report §B, §I.
export default function SystemStatusCard() {
  const { status, data, error, reload } = useApiResource(getHealth, { deps: [] })

  return (
    <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-text-primary">System Status</h3>
          {(status === API_STATUS.SUCCESS || status === API_STATUS.EMPTY) && (
            <StatusBadge status="running" label="Live: /api/health" />
          )}
        </div>
        <button
          onClick={reload}
          disabled={status === API_STATUS.LOADING}
          className="text-text-muted transition-colors hover:text-text-primary disabled:opacity-50"
          title="Re-check /api/health"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${status === API_STATUS.LOADING ? 'animate-spin' : ''}`} strokeWidth={1.75} />
        </button>
      </div>

      {status === API_STATUS.LOADING && <LoadingState label="Checking gateway API…" />}

      {status === API_STATUS.UNREACHABLE && (
        <DisconnectedState
          title="Gateway API unreachable"
          description={`Could not reach ${API_BASE_URL}/api/health. Start it with: python -m traffic_gateway.run_pipeline (or traffic_gateway.api).`}
        />
      )}

      {status === API_STATUS.ERROR && (
        <ErrorState title="Gateway API error" description={error?.message} />
      )}

      {(status === API_STATUS.SUCCESS || status === API_STATUS.EMPTY) && data && (
        <>
          <ul className="space-y-2.5">
            <StatusRow icon={Server} label="Gateway API" ok value="Reachable" />
            <StatusRow
              icon={Activity}
              label="Pipeline"
              ok={!!data.pipeline_started}
              value={data.pipeline_started ? 'Started' : 'Not started'}
            />
            <StatusRow
              icon={Cpu}
              label="MT3 model"
              ok={!!data.mt3}
              value={data.mt3 ? `Loaded${data.mt3.n_params ? ` (${data.mt3.n_params.toLocaleString()} params)` : ''}` : 'Not loaded'}
            />
            <StatusRow
              icon={FileText}
              label="Results log"
              ok={!!data.results_exist}
              value={data.results_exist ? 'Present' : 'Not yet created'}
            />
          </ul>
          <p className="mt-3 border-t border-base-borderMuted pt-3 text-xs text-text-muted">
            Reflects only <code className="font-mono">/api/health</code>. A reachable API does
            not mean the traffic proxy, Cowrie, or the adaptive honeypot are running — those are
            separate processes (see traffic_gateway/run_pipeline.py).
          </p>
        </>
      )}
    </div>
  )
}
