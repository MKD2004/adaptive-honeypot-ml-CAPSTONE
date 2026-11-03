import { BrainCircuit } from 'lucide-react'
import Panel from '../common/Panel'
import { PhaseBadge } from '../common/Badges'
import { microStateByLabel } from '../../lib/schema'
import { pct } from '../../lib/format'

function Stat({ label, children }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-text-muted">{label}</div>
      <div className="mt-1 text-sm font-medium text-text-primary">{children}</div>
    </div>
  )
}

// One session's MT3 output (record.mt3_prediction) plus the rule-based label
// the parser assigned. The rule label is a heuristic, not ground truth, so
// agreement is shown as agreement, never as "correct".
export default function PredictionCard({ record }) {
  const m = record.mt3_prediction || {}
  const ms = microStateByLabel(m.micro_state)
  const agrees = record.rule_label && record.rule_label === m.micro_state

  return (
    <Panel title="MT3 Classification" icon={BrainCircuit} className="border-accent/30">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="Micro-state">
          <span className="font-mono text-accent">{m.micro_state ?? '—'}</span>
        </Stat>
        <Stat label="MITRE technique">
          <span className="font-mono">{ms?.mitre ?? '—'}</span>
        </Stat>
        <Stat label="Kill-chain phase">
          <PhaseBadge phase={m.phase} />
        </Stat>
        <Stat label="Confidence">
          <span className="text-2xl font-semibold tabular-nums">{pct(m.confidence)}</span>
        </Stat>
      </div>

      {Array.isArray(m.top3) && m.top3.length > 0 && (
        <div className="mt-4 border-t border-base-borderMuted pt-3">
          <div className="mb-2 text-xs uppercase tracking-wide text-text-muted">Top-3 candidates</div>
          <ul className="space-y-1.5">
            {m.top3.map((t) => (
              <li key={t.micro_state} className="flex items-center gap-3 text-xs">
                <span className="w-48 shrink-0 font-mono text-text-secondary">{t.micro_state}</span>
                <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-base-raised">
                  <span className="block h-full bg-accent" style={{ width: `${Math.round((t.p ?? 0) * 100)}%` }} />
                </span>
                <span className="w-12 text-right tabular-nums text-text-muted">{pct(t.p)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="mt-4 grid grid-cols-1 gap-2 border-t border-base-borderMuted pt-3 text-xs sm:grid-cols-3">
        <div>
          <span className="text-text-muted">Rule-based label: </span>
          <span className="font-mono text-text-secondary">{record.rule_label || '—'}</span>
          {record.rule_label && (
            <span className={agrees ? 'ml-1.5 text-risk-low' : 'ml-1.5 text-risk-medium'}>
              {agrees ? '(agrees)' : '(differs)'}
            </span>
          )}
        </div>
        <div>
          <span className="text-text-muted">Kill-chain sequence valid (DAG): </span>
          <span className="text-text-secondary">
            {record.kcvr_valid === null || record.kcvr_valid === undefined ? 'n/a (too short)' : record.kcvr_valid ? 'yes' : 'no'}
          </span>
        </div>
        <div>
          <span className="text-text-muted">Semantic features (DistilBERT): </span>
          <span className={record.semantic_available ? 'text-text-secondary' : 'text-risk-medium'}>
            {record.semantic_available ? 'used' : 'zero-filled (no PCA)'}
          </span>
        </div>
      </div>
    </Panel>
  )
}
