import React, { useState } from 'react'
import { Pause, Play, Search } from 'lucide-react'
import { usePoll } from '../api'
import { Empty, ErrorNote, LabelBadge, SeverityBadge, fmtTime, pct, subject } from '../components/ui'

const TYPES = ['exec', 'open', 'connect', 'ptrace', 'setuid', 'mount', 'unshare', 'chmod', 'module', 'memfd', 'setns']
const PAGE = 100

export default function Events() {
  const [f, setF] = useState({ type: '', label: '', namespace: '', q: '' })
  const [page, setPage] = useState(0)
  const [live, setLive] = useState(true)
  const [open, setOpen] = useState(null)
  const params = Object.fromEntries(Object.entries({ ...f, limit: PAGE, skip: page * PAGE }).filter(([, v]) => v !== ''))
  const { data, error } = usePoll('/api/events', params, live ? 3000 : 0)
  const { data: namespaces } = usePoll('/api/namespaces', {}, 30000)
  const set = (k) => (e) => { setPage(0); setF({ ...f, [k]: e.target.value }) }

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="mb-1 text-[30px] font-semibold tracking-[-0.04em] text-[#1D1D1F]">Runtime Events</h1>
          <p className="text-sm text-[#86868B]">Every kernel event captured by eBPF, enriched with Kubernetes context and scored by the model. Events without pod context are stored raw.</p>
        </div>
        <button className="btn-ghost" onClick={() => setLive(!live)}>{live ? <><Pause className="h-4 w-4" />Pause live</> : <><Play className="h-4 w-4" />Resume live</>}</button>
      </div>
      <div className="mb-4 flex flex-wrap gap-2">
        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-[#86868B]" />
          <input className="input w-64 pl-8" placeholder="Search command, path, IP, pod…" value={f.q} onChange={set('q')} />
        </div>
        <select className="input" value={f.type} onChange={set('type')}><option value="">All event types</option>{TYPES.map((t) => <option key={t}>{t}</option>)}</select>
        <select className="input" value={f.label} onChange={set('label')}>
          <option value="">All verdicts</option><option value="suspicious">Suspicious</option><option value="normal">Normal</option><option value="raw">Raw (no k8s context)</option>
        </select>
        <select className="input" value={f.namespace} onChange={set('namespace')}><option value="">All namespaces</option>{(namespaces || []).map((n) => <option key={n}>{n}</option>)}</select>
      </div>
      <ErrorNote error={error} />
      <div className="card overflow-x-auto">
        <table className="w-full">
          <thead className="border-b border-[#E5E5EA]">
            <tr><th className="th">Time</th><th className="th">Type</th><th className="th">Verdict</th><th className="th">Namespace / pod</th>
              <th className="th">Process</th><th className="th">Detail</th><th className="th">P(malicious)</th></tr>
          </thead>
          <tbody>
            {(data?.items || []).map((e) => (
              <React.Fragment key={e.id}>
                <tr onClick={() => setOpen(open === e.id ? null : e.id)} className="cursor-pointer border-t border-[#E5E5EA] hover:bg-[#F5F5F7]">
                  <td className="td mono whitespace-nowrap text-xs text-[#86868B]">{fmtTime(e.ts)}</td>
                  <td className="td"><span className="mono rounded-full bg-[#F5F5F7] px-1.5 py-0.5 text-[11px] text-[#1D1D1F]">{e.event_type}</span></td>
                  <td className="td"><div className="flex items-center gap-1"><LabelBadge event={e} />{e.prediction?.severity && <SeverityBadge severity={e.prediction.severity} />}</div></td>
                  <td className="td text-xs">{e.k8s_context ? <><p className="text-[#1D1D1F]">{e.k8s?.pod}</p><p className="text-[#86868B]">{e.k8s?.namespace}</p></> : <span className="text-[#86868B]">node: {e.node}</span>}</td>
                  <td className="td mono text-xs text-[#1D1D1F]">{e.comm} <span className="text-[#86868B]">← {e.parent_comm}</span></td>
                  <td className="td mono max-w-lg truncate text-xs text-[#86868B]" title={subject(e)}>{subject(e)}</td>
                  <td className="td mono text-xs text-[#1D1D1F]">{e.prediction?.scored ? pct(e.prediction.probability) : '—'}</td>
                </tr>
                {open === e.id && (
                  <tr className="bg-[#F5F5F7]"><td colSpan={7} className="p-3"><pre className="mono max-h-80 overflow-auto text-xs text-[#1D1D1F]">{JSON.stringify(e, null, 2)}</pre></td></tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
        {!data?.items?.length && <Empty>No events match the filters</Empty>}
      </div>
      <div className="mt-3 flex items-center justify-between text-xs text-[#86868B]">
        <span>{data?.total >= 10000 ? '10,000+' : data?.total ?? 0} events (kept {24} h)</span>
        <div className="flex gap-2">
          <button className="btn-ghost" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <button className="btn-ghost" disabled={(page + 1) * PAGE >= (data?.total || 0)} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      </div>
    </div>
  )
}
