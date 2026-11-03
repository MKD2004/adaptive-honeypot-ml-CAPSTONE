import { Outlet, useLocation } from 'react-router-dom'
import AppSidebar from './AppSidebar'
import Topbar from './Topbar'
import RightPanel from './RightPanel'

// Three columns, full height, no page scroll — the Pulse console's shell.
// Only the centre column scrolls; the rails stay put.
export default function AppShell() {
  const { pathname } = useLocation()

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <AppSidebar />

      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <Topbar />
        <main className="flex-1 overflow-y-auto p-8">
          {/* Keyed on the route so each navigation replays the fade-in, as the
              Pulse main-content does when its section changes. */}
          <div key={pathname} className="animate-fade-in">
            <Outlet />
          </div>
        </main>
      </div>

      <RightPanel />
    </div>
  )
}
