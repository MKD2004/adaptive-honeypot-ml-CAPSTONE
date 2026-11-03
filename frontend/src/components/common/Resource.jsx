import LoadingState from './LoadingState'
import DisconnectedState from './DisconnectedState'
import ErrorState from './ErrorState'
import EmptyState from './EmptyState'
import { API_STATUS } from '../../hooks/useApiResource'
import { START_HINT } from '../../services/api'

// Renders the right state for a useApiResource() result, and `children(data)`
// once data is available. Keeps every page's loading / unreachable / error /
// empty handling identical.
export default function Resource({ resource, emptyTitle, emptyDescription, emptyIcon, loadingLabel, children }) {
  switch (resource.status) {
    case API_STATUS.LOADING:
      return <LoadingState label={loadingLabel} />
    case API_STATUS.UNREACHABLE:
      return <DisconnectedState title="Gateway API unreachable" description={START_HINT} />
    case API_STATUS.ERROR:
      return <ErrorState title="Request failed" description={resource.error?.message} />
    case API_STATUS.EMPTY:
      return <EmptyState icon={emptyIcon} title={emptyTitle ?? 'Nothing yet'} description={emptyDescription} />
    default:
      return children(resource.data)
  }
}
