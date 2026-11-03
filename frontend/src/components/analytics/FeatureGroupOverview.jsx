import { FEATURE_GROUPS, N_FEATURES } from '../../lib/schema'

// Fixed qualitative palette, one per feature group — same convention as
// lib/schema.js's PHASE_COLORS (intentionally not theme-tokenized).
const GROUP_COLORS = ['#3b82f6', '#8b5cf6', '#ec4899', '#f97316', '#eab308', '#22c55e']

// Visualizes the model's INPUT feature structure (6 groups, 128 features
// total) — not feature importance or any measured contribution. Group
// names/sizes/branches come straight from lib/schema.js (mirrors
// honeypot_dataset/configs/schema.py); nothing here is invented.
export default function FeatureGroupOverview() {
  return (
    <div>
      <div className="mb-3 flex h-3 w-full overflow-hidden rounded-full border border-border">
        {FEATURE_GROUPS.map((g, i) => (
          <div
            key={g.key}
            style={{ width: `${(g.size / N_FEATURES) * 100}%`, background: GROUP_COLORS[i] }}
            title={`${g.key} — ${g.size} features`}
          />
        ))}
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {FEATURE_GROUPS.map((g, i) => (
          <div key={g.key} className="rounded-md border border-border/60 p-3">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 font-mono text-xs text-foreground">
                <span className="h-2 w-2 rounded-full" style={{ background: GROUP_COLORS[i] }} />
                {g.key}
              </span>
              <span className="text-xs text-muted-foreground">{g.size} / {N_FEATURES}</span>
            </div>
            <p className="mt-1.5 text-xs text-foreground/80">{g.desc}</p>
            <p className="mt-1 text-[11px] text-muted-foreground">indices {g.range} &middot; {g.branch} branch</p>
          </div>
        ))}
      </div>

      <p className="mt-3 border-t border-border/60 pt-3 text-xs text-muted-foreground">
        This describes the model's input feature structure, not feature importance or a measured
        contribution to any prediction.
      </p>
    </div>
  )
}
