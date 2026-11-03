import { Routes, Route } from 'react-router-dom'
import AppShell from './components/layout/AppShell'
import OverviewPage from './pages/OverviewPage'
import LiveAccessPage from './pages/LiveAccessPage'
import SessionsPage from './pages/SessionsPage'
import SessionDetailsPage from './pages/SessionDetailsPage'
import HoneypotConfigPage from './pages/HoneypotConfigPage'
import ThreatAnalyticsPage from './pages/ThreatAnalyticsPage'
import AccessListsPage from './pages/AccessListsPage'
import MitreTaxonomyPage from './pages/MitreTaxonomyPage'
import ModelPage from './pages/ModelPage'
import NotFoundPage from './pages/NotFoundPage'

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/access" element={<LiveAccessPage />} />
        <Route path="/sessions" element={<SessionsPage />} />
        <Route path="/sessions/:sessionId" element={<SessionDetailsPage />} />
        <Route path="/adaptive" element={<HoneypotConfigPage />} />
        <Route path="/analytics" element={<ThreatAnalyticsPage />} />
        <Route path="/lists" element={<AccessListsPage />} />
        <Route path="/mitre" element={<MitreTaxonomyPage />} />
        <Route path="/model" element={<ModelPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
