import React from 'react'

export const SEV_COLOR = { High: '#ef4444', Medium: '#f59e0b', Low: '#38bdf8' }
export const CAT_LABEL = {
  reverse_shell: 'Reverse shell', dropper: 'Dropper / payload', crypto_miner: 'Crypto miner',
  privilege_escalation: 'Privilege escalation', container_escape: 'Container escape',
  credential_access: 'Credential access', discovery: 'Discovery', defense_evasion: 'Defense evasion',
  lateral_movement: 'Lateral movement', benign: 'Benign',
}

export function Card({ title, right, children, className = '' }) {
  return (
    <div className={`card p-4 ${className}`}>
      {(title || right) && (
        <div className="mb-3 flex items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-slate-300">{title}</h3>
          {right}
        </div>
      )}
      {children}
    </div>
  )
}

export function Stat({ label, value, sub, icon: Icon, tone = 'text-slate-100' }) {
  return (
    <div className="card p-4">
      <div className="flex items-start justify-between">
        <p className="text-xs uppercase tracking-wider text-slate-500">{label}</p>
        {Icon && <Icon className="h-4 w-4 text-slate-500" />}
      </div>
      <p className={`mt-2 text-2xl font-bold ${tone}`}>{value ?? '—'}</p>
      {sub && <p className="mt-1 text-xs text-slate-500">{sub}</p>}
    </div>
  )
}

export function SeverityBadge({ severity }) {
  if (!severity) return <span className="text-slate-600">—</span>
  const cls = {
    High: 'bg-red-500/15 text-red-400 border-red-500/30',
    Medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    Low: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
  }[severity]
  return <span className={`inline-block rounded border px-2 py-0.5 text-xs font-semibold ${cls}`}>{severity}</span>
}

export function StatusBadge({ status }) {
  const cls = {
    open: 'bg-red-500/10 text-red-300', acknowledged: 'bg-amber-500/10 text-amber-300',
    resolved: 'bg-emerald-500/10 text-emerald-300',
  }[status] || 'bg-slate-800 text-slate-400'
  return <span className={`rounded px-2 py-0.5 text-xs ${cls}`}>{status}</span>
}

export function LabelBadge({ event }) {
  const p = event.prediction || {}
  if (!event.k8s_context) return <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-400">raw</span>
  if (p.label === 'suspicious') return <span className="rounded bg-red-500/15 px-2 py-0.5 text-xs text-red-300">suspicious</span>
  return <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-xs text-emerald-300">normal</span>
}

export function RiskBar({ score }) {
  const s = Math.round(score || 0)
  const color = s >= 80 ? 'bg-red-500' : s >= 60 ? 'bg-amber-500' : 'bg-sky-500'
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 rounded bg-slate-800"><div className={`h-1.5 rounded ${color}`} style={{ width: `${s}%` }} /></div>
      <span className="mono text-xs text-slate-400">{s}</span>
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
  return <div className="flex h-full min-h-24 items-center justify-center text-sm text-slate-500">{children}</div>
}

export function ErrorNote({ error }) {
  return error ? <div className="mb-3 rounded border border-red-900 bg-red-950/40 px-3 py-2 text-sm text-red-300">{String(error)}</div> : null
}

export const tooltipStyle = {
  contentStyle: { background: '#0f172a', border: '1px solid #334155', borderRadius: 8, fontSize: 12 },
  labelStyle: { color: '#cbd5e1' },
}
