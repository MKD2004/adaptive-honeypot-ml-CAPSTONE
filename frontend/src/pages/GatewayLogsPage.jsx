import PageHeader from '../components/common/PageHeader'
import StatusBadge from '../components/common/StatusBadge'
import DataSection from '../components/common/DataSection'
import RoutingDecisionsTable from '../components/logs/RoutingDecisionsTable'
import FootprintsTable from '../components/logs/FootprintsTable'
import { useApiResource, API_STATUS } from '../hooks/useApiResource'
import { getLiveAccess, getFootprints } from '../services/api'

// Gateway-level activity only — the pre-filter's routing decisions
// (traffic_classifier.py, via GET /api/live-access) and raw Cowrie keystrokes
// (GET /api/footprints). Deliberately NOT MT3 predictions: this data exists
// upstream of MT3 in the pipeline and has no micro-state/phase/confidence of
// its own (Stage 4 report §D, §K).
export default function GatewayLogsPage() {
  const access = useApiResource(getLiveAccess, {
    deps: [],
    isEmpty: (data) => !data?.decisions?.length,
  })
  const footprints = useApiResource(getFootprints, {
    deps: [],
    isEmpty: (data) => !data?.footprints?.length,
  })

  // Reflects what actually happened, not an assumption — was previously a
  // hardcoded "Live" badge shown even while both requests below were
  // reporting "Gateway API unreachable."
  const anyUnreachable =
    access.status === API_STATUS.UNREACHABLE || footprints.status === API_STATUS.UNREACHABLE
  const headerBadge = anyUnreachable ? (
    <StatusBadge status="offline" label="Gateway Unreachable" />
  ) : (
    <StatusBadge status="running" label="Live: traffic_gateway/api.py" />
  )

  return (
    <div>
      <PageHeader
        title="Logs"
        subtitle="Gateway-level activity — connection routing decisions and honeypot keystrokes. Not MT3 predictions."
        actions={headerBadge}
      />

      <div className="mb-6 rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
        <h3 className="mb-1 text-sm font-semibold text-text-primary">Routing Decisions</h3>
        <p className="mb-3 text-xs text-text-muted">
          traffic_classifier.py's pre-filter verdict per connection (GET /api/live-access) — a
          heuristic score in [0,1], not an MT3 confidence or MITRE classification.
        </p>
        <DataSection
          resource={access}
          emptyTitle="No routing decisions recorded"
          emptyDescription="traffic_gateway/data/sessions.jsonl has no CONN_ROUTED events yet."
        >
          {access.data?.decisions && <RoutingDecisionsTable decisions={access.data.decisions} />}
        </DataSection>
      </div>

      <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
        <h3 className="mb-1 text-sm font-semibold text-text-primary">Honeypot Footprints</h3>
        <p className="mb-3 text-xs text-text-muted">
          Raw commands and login attempts captured by Cowrie (GET /api/footprints) — literal
          attacker input, not a MITRE-classified event.
        </p>
        <DataSection
          resource={footprints}
          emptyTitle="No footprints captured"
          emptyDescription="honeypot_dataset/cowrie/logs/ doesn't exist on this machine (Stage 4 report, Part 1) — Cowrie hasn't run here."
        >
          {footprints.data?.footprints && <FootprintsTable footprints={footprints.data.footprints} />}
        </DataSection>
      </div>
    </div>
  )
}
