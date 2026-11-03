import { Link, useLocation } from 'react-router-dom'
import { Compass } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import EmptyState from '../components/common/EmptyState'

// Catch-all route, so an unknown URL still renders inside the app shell.
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
      <Link to="/" className="mt-4 inline-block text-sm font-medium text-accent hover:underline">
        Go to Overview
      </Link>
    </div>
  )
}
