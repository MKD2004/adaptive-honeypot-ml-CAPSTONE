import { BrainCircuit, Database, Table2, Layers, Info } from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import Panel from '../components/common/Panel'
import Resource from '../components/common/Resource'
import StatusBadge from '../components/common/StatusBadge'
import FeatureGroupOverview from '../components/analytics/FeatureGroupOverview'
import { useApiResource } from '../hooks/useApiResource'
import { getHealth } from '../services/api'
import { DATASET_SUMMARY, MODEL_RESULTS, MODEL_RESULTS_NOTE, MICRO_STATES } from '../lib/schema'
import { num } from '../lib/format'

function Row({ label, children, mono }) {
  return (
    <>
      <dt className="text-text-muted">{label}</dt>
      <dd className={`text-right text-text-primary ${mono ? 'break-all font-mono text-xs' : ''}`}>{children}</dd>
    </>
  )
}

function LiveModel({ health }) {
  return (
    <Panel title="Loaded Classifier" icon={BrainCircuit} subtitle="GET /api/health → the MT3 checkpoint the pipeline is running">
      <Resource resource={health}>
        {(h) =>
          h.mt3 ? (
            <dl className="grid grid-cols-2 gap-y-2 text-sm">
              <Row label="Status"><StatusBadge status="online" label="Loaded" /></Row>
              <Row label="Parameters">{num(h.mt3.n_params)}</Row>
              <Row label="Device">{h.mt3.device}</Row>
              <Row label="Best val macro-F1">
                {typeof h.mt3.best_val_macro_f1 === 'number' ? h.mt3.best_val_macro_f1.toFixed(4) : '—'}
              </Row>
              <Row label="Best epoch">{h.mt3.best_epoch ?? '—'}</Row>
              {Object.entries(h.mt3.model_kwargs || {}).map(([k, v]) => (
                <Row key={k} label={k} mono>{String(v)}</Row>
              ))}
              <Row label="Checkpoint" mono>{h.mt3.checkpoint}</Row>
            </dl>
          ) : (
            <div className="space-y-2 text-sm">
              <StatusBadge status="degraded" label="MT3 not loaded in this API process" />
              <p className="text-xs text-text-muted">
                The API was started without the post-session pipeline, or the checkpoint
                (ml_analytics/artifacts/mt3_full_d256/best.pt) is missing on this machine. Start{' '}
                <code className="font-mono">python -m traffic_gateway.run_pipeline</code>.
              </p>
            </div>
          )
        }
      </Resource>
    </Panel>
  )
}

function ResultsTable() {
  return (
    <Panel title="Offline Evaluation" icon={Table2} subtitle="Frozen splits, macro-F1 over the 21 classes present in test_real (STATUS.md, session 3)">
      <div className="overflow-x-auto scrollbar-thin">
        <table className="w-full min-w-[560px] border-collapse text-sm">
          <thead>
            <tr className="border-b border-base-border text-left text-xs uppercase tracking-wide text-text-muted">
              <th className="py-2 pr-4 font-medium">Model</th>
              <th className="py-2 pr-4 text-right font-medium">Params</th>
              <th className="py-2 pr-4 text-right font-medium">Val</th>
              <th className="py-2 pr-4 text-right font-medium">test_real (clean)</th>
              <th className="py-2 pr-4 text-right font-medium">test_synth</th>
            </tr>
          </thead>
          <tbody>
            {MODEL_RESULTS.map((m) => (
              <tr key={m.model} className="border-b border-base-borderMuted">
                <td className="py-2.5 pr-4 text-text-primary">{m.model}</td>
                <td className="py-2.5 pr-4 text-right tabular-nums text-text-secondary">{num(m.params)}</td>
                <td className="py-2.5 pr-4 text-right tabular-nums text-text-secondary">{m.valMacroF1.toFixed(4)}</td>
                <td className="py-2.5 pr-4 text-right tabular-nums font-medium text-text-primary">{m.testRealClean.toFixed(4)}</td>
                <td className="py-2.5 pr-4 text-right tabular-nums text-text-secondary">{m.testSynth.toFixed(4)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-3 border-t border-base-borderMuted pt-3 text-xs text-text-muted">{MODEL_RESULTS_NOTE}</p>
    </Panel>
  )
}

function DatasetCard() {
  const d = DATASET_SUMMARY
  const anchored = MICRO_STATES.filter((s) => s.realData)
  return (
    <Panel title={d.name} icon={Database} subtitle={`Training dataset, frozen ${d.frozenDate}`}>
      <dl className="grid grid-cols-2 gap-y-2 text-sm">
        <Row label="Train / val">{num(d.train)} / {num(d.val)}</Row>
        <Row label="test_real">{num(d.testReal)} ({d.testRealClasses} classes)</Row>
        <Row label="test_synth">{num(d.testSynth)} ({d.totalClasses} classes)</Row>
        <Row label="Real-anchored classes">{d.realAnchoredClasses} of {d.totalClasses}</Row>
      </dl>
      <p className="mt-3 text-xs text-text-secondary">{d.note}</p>
      <div className="mt-3 flex flex-wrap gap-1.5">
        {anchored.map((s) => (
          <span key={s.id} className="rounded border border-risk-low/30 px-1.5 py-0.5 font-mono text-[10px] text-risk-low">
            {s.label}
          </span>
        ))}
      </div>
    </Panel>
  )
}

function KnownLimits() {
  return (
    <Panel title="Known Limitations" icon={Info} subtitle="DECISIONS.md / ROADMAP.md: stated plainly rather than hidden">
      <ul className="list-disc space-y-1.5 pl-4 text-xs text-text-secondary">
        <li>MT3 and the CNN-LSTM baseline tie on test_real (McNemar p = 0.617); MT3 is not claimed to be better.</li>
        <li>29.74% of test_real rows duplicate training rows; only the clean subset (41,785 rows) is quoted.</li>
        <li>MT3 has no CRF, and KILL_CHAIN_DAG is not used in training; kill-chain validity is only measured.</li>
        <li>The honeypot-command classes are synthetic; there is no real honeypot data in training yet.</li>
        <li>MT3 classifies a session when it closes, so adaptation applies to the next session.</li>
      </ul>
    </Panel>
  )
}

export default function ModelPage() {
  const health = useApiResource(getHealth, { intervalMs: 15000 })

  return (
    <div>
      <PageHeader
        title="Model & Dataset"
        subtitle="The classifier inside the loop, how it was evaluated, and what it was trained on"
      />
      <div className="mb-6 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <LiveModel health={health} />
        <ResultsTable />
      </div>
      <div className="mb-6 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <DatasetCard />
        <KnownLimits />
      </div>
      <Panel title="128-Feature Input Layout" icon={Layers} subtitle="Six groups, each feeding its own MT3 branch encoder">
        <FeatureGroupOverview />
      </Panel>
    </div>
  )
}
