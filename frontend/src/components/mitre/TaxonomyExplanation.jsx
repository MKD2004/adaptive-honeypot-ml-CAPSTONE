import { Info } from 'lucide-react'
import { N_PHASES, N_MICRO_STATES, N_FEATURES, FEATURE_GROUPS } from '../../lib/schema'

// Static explanation of the project's own taxonomy — deliberately does NOT
// render an ATT&CK matrix or claim any official MITRE mapping has been
// verified. The `mitre` field shown elsewhere on this page is this
// project's own curated reference ID (honeypot_dataset/configs/schema.py /
// SCHEMA.md), not an independently-validated ATT&CK classification.
export default function TaxonomyExplanation() {
  return (
    <div className="rounded-lg border border-base-border bg-base-surface p-4 shadow-card">
      <div className="mb-3 flex items-center gap-2">
        <Info className="h-4 w-4 text-accent" strokeWidth={1.75} />
        <h3 className="text-sm font-semibold text-text-primary">About This Taxonomy</h3>
      </div>

      <div className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-3">
        <div>
          <div className="text-2xl font-semibold tabular-nums text-text-primary">{N_PHASES}</div>
          <p className="mt-1 text-xs text-text-secondary">
            Kill-chain phases, from Reconnaissance to Exfiltration — the project's own
            simplification of an attack lifecycle, ordered but not identical to any single
            published framework's stage list.
          </p>
        </div>
        <div>
          <div className="text-2xl font-semibold tabular-nums text-text-primary">{N_MICRO_STATES}</div>
          <p className="mt-1 text-xs text-text-secondary">
            Custom micro-states (5-6 per phase) — this project's own classification granularity,
            each carrying a reference MITRE technique ID for documentation. Those IDs are the
            project's own curation, not an independently verified ATT&CK mapping.
          </p>
        </div>
        <div>
          <div className="text-2xl font-semibold tabular-nums text-text-primary">{N_FEATURES}</div>
          <p className="mt-1 text-xs text-text-secondary">
            Input features across {FEATURE_GROUPS.length} groups (A-F) extracted per session —
            temporal, network, payload, semantic, threat-intel, and TLS/host signals.
          </p>
        </div>
      </div>

      <p className="mt-4 border-t border-base-borderMuted pt-3 text-xs text-text-muted">
        This page shows the project's custom 45-state taxonomy only. It does not render an
        official MITRE ATT&amp;CK matrix, and no technique ID here should be treated as an
        independently validated ATT&amp;CK classification.
      </p>
    </div>
  )
}
