import { Routes, Route } from 'react-router-dom'
import AppShell from './components/layout/AppShell'
import DashboardPage from './pages/DashboardPage'
import LiveSessionsPage from './pages/LiveSessionsPage'
import SessionDetailsPage from './pages/SessionDetailsPage'
import HoneypotConfigPage from './pages/HoneypotConfigPage'
import GatewayLogsPage from './pages/GatewayLogsPage'
import ThreatAnalyticsPage from './pages/ThreatAnalyticsPage'
import MitreAnalysisPage from './pages/MitreAnalysisPage'
import CveIntelligencePage from './pages/CveIntelligencePage'
import CveDetailsPage from './pages/CveDetailsPage'
import NotFoundPage from './pages/NotFoundPage'

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/sessions" element={<LiveSessionsPage />} />
        <Route path="/sessions/:sessionId" element={<SessionDetailsPage />} />
        <Route path="/adaptive" element={<HoneypotConfigPage />} />
        <Route path="/analytics" element={<ThreatAnalyticsPage />} />
        <Route path="/mitre" element={<MitreAnalysisPage />} />
        <Route path="/cve" element={<CveIntelligencePage />} />
        <Route path="/cve/:cveId" element={<CveDetailsPage />} />
        <Route path="/logs" element={<GatewayLogsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
