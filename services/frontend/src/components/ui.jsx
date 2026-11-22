import React from 'react'

export const SEV_COLOR = { High: '#FF3B30', Medium: '#FF9500', Low: '#007AFF' }
export const CAT_LABEL = {
  reverse_shell: 'Reverse shell', dropper: 'Dropper / payload', crypto_miner: 'Crypto miner',
  privilege_escalation: 'Privilege escalation', container_escape: 'Container escape',
  credential_access: 'Credential access', discovery: 'Discovery', defense_evasion: 'Defense evasion',
  lateral_movement: 'Lateral movement', benign: 'Benign',
}

export function Card({ title, right, children, className = '' }) {
  return (
    <div className={`card ${className}`}>
      {(title || right) && (
        <div className="mb-4 flex min-w-0 items-center justify-between gap-2">
          <h3 className="min-w-0 text-[15px] font-semibold text-[#1D1D1F]">{title}</h3>
          {right}
        </div>
      )}
      {children}
    </div>
  )
}

export function Stat({ label, value, sub, icon: Icon, tone = 'text-[#1D1D1F]' }) {
  return (
    <div className="card p-4 md:p-5">
      <div className="flex items-start justify-between gap-3">
        <p className="min-w-0 text-[11px] font-medium uppercase tracking-[0.12em] text-[#86868B]">{label}</p>
        {Icon && <Icon className="h-4 w-4 shrink-0 text-[#007AFF]" />}
      </div>
      <p className={`mt-3 text-[28px] font-semibold leading-none tracking-[-0.03em] ${tone}`}>{value ?? '—'}</p>
      {sub && <p className="mt-2 text-xs text-[#86868B]">{sub}</p>}
    </div>
  )
}

export function SeverityBadge({ severity }) {
  if (!severity) return <span className="text-[#86868B]">—</span>
  const cls = {
    High: 'border-[#FF3B30]/20 bg-[#FFE5E3] text-[#FF3B30]',
    Medium: 'border-[#FF9500]/20 bg-[#FFF1E0] text-[#FF9500]',
    Low: 'border-[#007AFF]/20 bg-[#EAF3FF] text-[#007AFF]',
  }[severity]
  return <span className={`inline-block rounded-full border px-2 py-0.5 text-[11px] font-semibold ${cls}`}>{severity}</span>
}

export function StatusBadge({ status }) {
  const cls = {
    open: 'bg-[#FFE5E3] text-[#FF3B30]',
    acknowledged: 'bg-[#FFF1E0] text-[#FF9500]',
    resolved: 'bg-[#EAF3FF] text-[#007AFF]',
  }[status] || 'bg-[#F5F5F7] text-[#86868B]'
  return <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${cls}`}>{status}</span>
}

export function LabelBadge({ event }) {
  const p = event.prediction || {}
  if (!event.k8s_context) return <span className="rounded-full bg-[#F5F5F7] px-2 py-0.5 text-[11px] text-[#86868B]">raw</span>
  if (p.label === 'suspicious') return <span className="rounded-full bg-[#FFE5E3] px-2 py-0.5 text-[11px] text-[#FF3B30]">suspicious</span>
  return <span className="rounded-full bg-[#EAF3FF] px-2 py-0.5 text-[11px] text-[#007AFF]">normal</span>
}

export function RiskBar({ score }) {
  const s = Math.round(score || 0)
  const color = s >= 80 ? 'bg-[#FF3B30]' : s >= 60 ? 'bg-[#FF9500]' : 'bg-[#007AFF]'
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-[#E5E5EA]">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${s}%` }} />
      </div>
      <span className="mono text-[11px] text-[#86868B]">{s}</span>
    </div>
  )
}

export function timeAgo(iso) {
  if (!iso) return ''
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return `${Math.floor(s)}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

export function fmtTime(iso) {
  return iso ? new Date(iso).toLocaleTimeString() : ''
}

export function pct(v, digits = 1) {
  return v == null ? '—' : `${(v * 100).toFixed(digits)}%`
}

export function subject(ev) {
  if (!ev) return ''
  if (ev.event_type === 'exec') return ev.cmdline || ev.path
  if (ev.event_type === 'connect') return ev.daddr ? `${ev.daddr}:${ev.dport}` : ev.path
  if (ev.event_type === 'mount') return `${ev.cmdline || ''} → ${ev.path}`
  return ev.path || ev.cmdline || `flags=${ev.flags}`
}

export function Empty({ children = 'No data yet' }) {
  return <div className="flex h-full min-h-24 items-center justify-center text-sm text-[#86868B]">{children}</div>
}

export function ErrorNote({ error }) {
  return error ? <div className="mb-4 rounded-xl border border-[#FF3B30]/20 bg-[#FFE5E3] px-3 py-2 text-sm text-[#B21D18]">{String(error)}</div> : null
}

export const tooltipStyle = {
  contentStyle: {
    background: '#FFFFFF',
    border: '1px solid #E5E5EA',
    borderRadius: 12,
    fontSize: 12,
    boxShadow: '0 8px 20px rgba(29,29,31,0.08)',
  },
  labelStyle: { color: '#1D1D1F' },
  itemStyle: { color: '#1D1D1F' },
}
