import { Link, useLocation } from 'react-router-dom'
import { Compass } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import EmptyState from '../components/common/EmptyState'

// Catch-all for any URL that doesn't match a known route. Without this,
// React Router renders nothing at all for an unmatched path — not even the
// sidebar/topbar shell — which is a blank white page with no way back
// except the browser's own Back button (found in Stage 7 QA).
export default function NotFoundPage() {
  const location = useLocation()

  return (
    <div>
      <PageHeader title="Page not found" subtitle={`No route matches "${location.pathname}"`} />
      <EmptyState
        icon={Compass}
        title="This page doesn't exist"
        description="Check the URL, or use the sidebar to get back to a known page."
      />
      <Link to="/" className="mt-4 inline-block text-sm font-medium text-chart-1 hover:underline">
        Go to Dashboard
      </Link>
    </div>
  )
}
