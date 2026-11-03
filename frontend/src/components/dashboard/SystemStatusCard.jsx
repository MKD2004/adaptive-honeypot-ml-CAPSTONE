import { Server, Cpu, FileText, Activity, Route, FolderSearch } from 'lucide-react'
import StatusBadge from '../common/StatusBadge'
import Panel from '../common/Panel'
import Resource from '../common/Resource'
import { num } from '../../lib/format'

function StatusRow({ icon: Icon, label, ok, value, tone }) {
  return (
    <li className="flex items-center justify-between gap-3 text-sm">
      <span className="flex items-center gap-2 text-text-secondary">
        <Icon className="h-3.5 w-3.5 text-text-muted" strokeWidth={1.75} />
        {label}
      </span>
      <StatusBadge status={tone ?? (ok ? 'running' : 'offline')} label={value} />
    </li>
  )
}

// GET /api/health + the `pipeline` block of GET /api/stats. Reports only what
// those endpoints return; a reachable API does not prove the gateway proxy or
// Cowrie are running (they are separate processes).
export default function SystemStatusCard({ health, stats }) {
  const pipe = stats.data?.pipeline

  return (
    <Panel title="System Status" subtitle="GET /api/health · refreshes every 5 s">
      <Resource resource={health}>
        {(h) => (
          <>
            <ul className="space-y-2.5">
              <StatusRow icon={Server} label="Gateway API" ok value="Reachable" />
              <StatusRow
                icon={Activity}
                label="Post-session pipeline"
                ok={!!h.pipeline_started}
                value={h.pipeline_started ? 'Watching Cowrie' : 'Not started'}
              />
              <StatusRow
                icon={Cpu}
                label="MT3 model"
                ok={!!h.mt3}
                value={h.mt3 ? `${num(h.mt3.n_params)} params · ${h.mt3.device}` : 'Not loaded'}
              />
              <StatusRow
                icon={FileText}
                label="Results log"
                ok={!!h.results_exist}
                value={h.results_exist ? 'Present' : 'Not created yet'}
              />
              <StatusRow
                icon={Route}
                label="Routing mode"
                tone="info"
                value={h.classifier_routing ? 'Classifier (benign → real)' : 'Zero-trust'}
              />
              {pipe && (
                <StatusRow
                  icon={FolderSearch}
                  label="Cowrie logs found"
                  ok={pipe.cowrie_logs_found > 0}
                  value={`${pipe.cowrie_logs_found} file(s) · ${pipe.processed} processed`}
                />
              )}
            </ul>
            {!h.pipeline_started && (
              <p className="mt-3 border-t border-base-borderMuted pt-3 text-xs text-text-muted">
                The API is running without the MT3 watcher (traffic_gateway.api). Start{' '}
                <code className="font-mono">python -m traffic_gateway.run_pipeline</code> to classify
                new sessions live.
              </p>
            )}
          </>
        )}
      </Resource>
    </Panel>
  )
}
