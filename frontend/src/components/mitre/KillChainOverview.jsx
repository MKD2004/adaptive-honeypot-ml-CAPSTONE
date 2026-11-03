import PhaseAccordion from './PhaseAccordion'
import { PHASE_COLORS } from '../../lib/schema'

// All 9 phases, in kill-chain order, with session counts derived from the
// sessions MT3 has classified (GET /api/live-feed) — see MitreAnalysisPage.jsx.
// Clicking a phase selects it for the detail panel below and filters the
// micro-state explorer; clicking it again clears the filter.
//
// This was a `lg:grid-cols-9` row of equal cards, which left each phase about
// 90px — enough for a number and not much else. PhaseAccordion gives the phase
// under the pointer roughly half the width and folds the rest away.
export default function KillChainOverview({ phases, selectedPhase, onSelectPhase }) {
  return (
    <PhaseAccordion
      phases={phases}
      colors={PHASE_COLORS}
      selectedPhase={selectedPhase}
      onSelectPhase={onSelectPhase}
      height={300}
      gap={8}
      radius={14}
      expandRatio={0.4}
    />
  )
}
