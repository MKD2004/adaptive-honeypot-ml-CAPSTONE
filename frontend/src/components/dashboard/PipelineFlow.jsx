import { ChevronRight } from 'lucide-react'

// The real end-to-end chain (CLAUDE.md "Live Pipeline / System"), and the
// module that implements each stage.
const STAGES = [
  { name: 'Gateway pre-filter', module: 'traffic_classifier.py' },
  { name: 'Cowrie honeypot', module: 'honeypot_dataset/cowrie' },
  { name: 'Session parser', module: 'cowrie_parser.py' },
  { name: '128 features', module: 'src/extractors' },
  { name: 'MT3 · 45 states', module: 'feature_bridge.py' },
  { name: 'Adaptive config', module: 'configurator.py' },
  { name: 'Auto-blacklist', module: 'post_session_pipeline.py' },
]

export default function PipelineFlow() {
  return (
    <div className="rounded-lg border border-base-border bg-base-surface px-4 py-3">
      <div className="flex flex-wrap items-center gap-y-2">
        {STAGES.map((s, i) => (
          <div key={s.name} className="flex items-center">
            <div className="px-2 py-1">
              <div className="text-xs font-medium text-text-primary">{s.name}</div>
              <div className="font-mono text-[10px] text-text-muted">{s.module}</div>
            </div>
            {i < STAGES.length - 1 && <ChevronRight className="h-3.5 w-3.5 shrink-0 text-text-muted" />}
          </div>
        ))}
      </div>
      <p className="mt-2 border-t border-base-borderMuted pt-2 text-[11px] text-text-muted">
        The gateway decides routing at connection time. MT3 classifies a session only once it
        closes (it needs the whole session), and the reconfigured honeypot applies to the{' '}
        <span className="font-medium text-text-secondary">next</span> session.
      </p>
    </div>
  )
}
