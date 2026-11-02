import LoadingState from './LoadingState'
import DisconnectedState from './DisconnectedState'
import ErrorState from './ErrorState'
import EmptyState from './EmptyState'
import { API_STATUS } from '../../hooks/useApiResource'
import { API_BASE_URL } from '../../services/api'

export const UNREACHABLE_MSG =
  `Could not reach ${API_BASE_URL}. Start it with: ` +
  'python -m traffic_gateway.run_pipeline (or traffic_gateway.api).'

// Renders one useApiResource state at a time so a page never collapses
// "loading", "the API is down", "the request failed" and "there is genuinely
// nothing yet" into a single blank panel. Extracted from GatewayLogsPage once
// the session pages moved onto the API and needed the same five branches.
export default function DataSection({
  resource,
  emptyTitle,
  emptyDescription,
  loadingLabel = 'Loading…',
  children,
}) {
  if (resource.status === API_STATUS.LOADING) return <LoadingState label={loadingLabel} />
  if (resource.status === API_STATUS.UNREACHABLE) {
    return <DisconnectedState title="Gateway API unreachable" description={UNREACHABLE_MSG} />
  }
  if (resource.status === API_STATUS.ERROR) {
    return <ErrorState title="Request failed" description={resource.error?.message} />
  }
  if (resource.status === API_STATUS.EMPTY) {
    return <EmptyState title={emptyTitle} description={emptyDescription} />
  }
  return children
}
