import { ShieldHalf, AlertTriangle } from 'lucide-react'
import Panel from '../common/Panel'
import StatusBadge from '../common/StatusBadge'
import { LevelBadge, PhaseBadge } from '../common/Badges'
import { fmtDateTime, pct } from '../../lib/format'
import { cn } from '../../lib/cn'

function Flag({ on, onLabel, offLabel }) {
  return (
    <span className={cn('text-xs font-medium', on ? 'text-risk-critical' : 'text-text-muted')}>
      {on ? onLabel : offLabel}
    </span>
  )
}

function Row({ label, children }) {
  return (
    <>
      <dt className="text-text-muted">{label}</dt>
      <dd className="text-right text-text-primary">{children}</dd>
    </>
  )
}

// The honeypot's current configuration — adaptive_honeypot/active_config.json
// via GET /api/active-config. `compact` hides the bait/behaviour details for
// the Overview page.
export default function ActiveConfigCard({ config, compact = false }) {
  const isDefault = !config.micro_state

  return (
    <Panel
      title="Active Honeypot Config"
      icon={ShieldHalf}
      subtitle={config.updated_at ? `Updated ${fmtDateTime(config.updated_at)}` : 'Never updated'}
      actions={<LevelBadge level={config.interaction_level} />}
    >
      {config.alert && (
        <div className="mb-3 flex items-center gap-2 rounded-md border border-risk-critical/40 bg-risk-critical/10 px-3 py-2 text-xs font-medium text-risk-critical">
          <AlertTriangle className="h-4 w-4" />
          Maximum interaction: phase {config.phase} ({config.phase_name}) detected, external alert armed
        </div>
      )}
      {isDefault && (
        <div className="mb-3">
          <StatusBadge status="unknown" label="Default posture: no session observed yet" />
        </div>
      )}

      <dl className="grid grid-cols-2 gap-y-2 text-sm">
        <Row label="Kill-chain phase">
          <PhaseBadge phase={config.phase} />
        </Row>
        <Row label="Triggering micro-state">
          <span className="font-mono text-xs text-accent">{config.micro_state ?? '—'}</span>
          {typeof config.confidence === 'number' && (
            <span className="ml-1.5 text-xs text-text-muted">{pct(config.confidence)}</span>
          )}
        </Row>
        <Row label="Honeypot target">
          <span className="font-mono text-xs">{config.honeypot_target}</span>
        </Row>
        <Row label="Fake service banner">
          <span className="font-mono text-xs text-text-secondary">{config.banner}</span>
        </Row>
        {!compact && (
          <>
            <Row label="Filesystem">{config.filesystem}</Row>
            <Row label="Response delay">{config.response_delay_ms} ms</Row>
            <Row label="Fake credentials">
              <Flag on={config.fake_credentials_visible} onLabel="VISIBLE" offLabel="hidden" />
            </Row>
            <Row label="Fake /etc/shadow">
              <Flag on={config.fake_sensitive_files} onLabel="PLANTED" offLabel="absent" />
            </Row>
            <Row label="Stealable SSH key">
              <Flag on={config.fake_ssh_keys} onLabel="PLANTED" offLabel="absent" />
            </Row>
            <Row label="Downloads / uploads">
              <span className="text-xs">
                {config.allow_download ? 'allowed' : 'blocked'} / {config.capture_uploads ? 'captured' : 'off'}
              </span>
            </Row>
            <Row label="External alert">
              <Flag on={config.alert} onLabel="ARMED" offLabel="off" />
            </Row>
            {config.last_session?.src_ip && (
              <Row label="Last session">
                <span className="font-mono text-xs">{config.last_session.src_ip}</span>
              </Row>
            )}
          </>
        )}
      </dl>

      {!compact && config.cve_profile && (
        <div className="mt-3 rounded-md border border-base-borderMuted p-3 text-xs">
          <div className="mb-1 font-medium text-text-secondary">Trending-CVE overlay</div>
          <div className="font-mono text-accent">{config.cve_profile.cve_id}</div>
          <div className="mt-0.5 text-text-muted">
            {config.cve_profile.attack_type} · {config.cve_profile.service} · CVSS{' '}
            {config.cve_profile.cvss_score ?? '—'} · EPSS {config.cve_profile.epss_score ?? '—'}
            {config.cve_profile.is_kev ? ' · CISA KEV' : ''}
          </div>
          <div className="mt-0.5 text-[11px] text-text-muted">
            {config.cve_profile.intel_source === 'live'
              ? 'from live NVD / KEV / EPSS intel'
              : 'from the offline snapshot (not live intel)'}
          </div>
        </div>
      )}

      {config.purpose && !compact && (
        <p className="mt-3 text-xs text-text-secondary">
          <span className="font-medium">Goal at this level: </span>
          {config.purpose}
        </p>
      )}
      <p className="mt-3 border-t border-base-borderMuted pt-3 text-xs text-text-muted">{config.reason}</p>
    </Panel>
  )
}
