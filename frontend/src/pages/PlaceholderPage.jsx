import PageHeader from '../components/common/PageHeader'
import EmptyState from '../components/common/EmptyState'

// Shared shell for sections not yet built. Stage 1 only implements the
// Dashboard on mock data; every other route renders this until its own
// stage is approved, so the sidebar nav is fully wired without pretending
// unfinished pages are done.
export default function PlaceholderPage({ title, subtitle, note }) {
  return (
    <div>
      <PageHeader title={title} subtitle={subtitle} />
      <EmptyState
        title="Not built yet"
        description={note ?? 'This section lands in a later stage, once the Dashboard visual foundation is approved.'}
      />
    </div>
  )
}
