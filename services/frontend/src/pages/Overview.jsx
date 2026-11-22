import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Area, Bar, BarChart, CartesianGrid, Cell, ComposedChart, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { Activity, Boxes, Cpu, ShieldAlert, Siren, Timer } from 'lucide-react'
import { usePoll } from '../api'
import {
  CAT_LABEL, Card, Empty, ErrorNote, RiskBar, SEV_COLOR, SeverityBadge, Stat, subject, timeAgo, tooltipStyle,
} from '../components/ui'

const WINDOWS = [[15, '15m'], [60, '1h'], [360, '6h'], [1440, '24h']]

export default function Overview() {
  const [minutes, setMinutes] = useState(60)
  const { data: s, error } = usePoll('/api/stats', { minutes }, 5000)
  const { data: agents } = usePoll('/api/agents', { history_minutes: 15 }, 10000)
  const { data: recent } = usePoll('/api/alerts', { limit: 8, status: 'open,acknowledged' }, 5000)

  const agent = agents?.[0]?.latest
  const online = agents?.filter((a) => a.online).length ?? 0
  const timeline = (s?.timeline || []).map((t) => ({ ...t, label: new Date(t.t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }))
  const sevData = s ? Object.entries(s.alerts_by_severity).map(([name, value]) => ({ name, value })).filter((d) => d.value) : []
  const catData = s ? Object.entries(s.alerts_by_category).map(([k, v]) => ({ name: CAT_LABEL[k] || k, value: v })) : []
  const typeData = s ? Object.entries(s.events_by_type).map(([k, v]) => ({ name: k, value: v })).sort((a, b) => b.value - a.value) : []

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-[30px] font-semibold tracking-[-0.04em] text-[#1D1D1F]">Runtime Security Overview</h1>
          <p className="mt-1 text-sm text-[#86868B]">Monitor Kubernetes runtime activity, detect threats, and evaluate system security in real time.</p>
        </div>
        <div className="inline-flex rounded-full border border-[#E5E5EA] bg-white p-1">
          {WINDOWS.map(([m, l]) => (
            <button
              key={m}
              onClick={() => setMinutes(m)}
              className={`rounded-full px-3 py-1.5 text-xs font-medium transition ${minutes === m ? 'bg-[#EAF3FF] text-[#007AFF]' : 'text-[#86868B] hover:text-[#1D1D1F]'}`}
            >
              {l}
            </button>
          ))}
        </div>
      </div>
      <ErrorNote error={error} />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
        <Stat label="Kernel Events" value={s?.events_total?.toLocaleString()} sub={`${s?.events_by_label?.raw ?? 0} without k8s context`} icon={Activity} />
        <Stat label="Open Alerts" value={s?.alerts_open} sub={`${s?.alert_occurrences ?? 0} occurrences in window`} icon={Siren} tone={s?.alerts_open ? 'text-[#FF3B30]' : 'text-[#1D1D1F]'} />
        <Stat label="High Severity" value={s?.alerts_by_severity?.High} sub={`Medium ${s?.alerts_by_severity?.Medium ?? 0} · Low ${s?.alerts_by_severity?.Low ?? 0}`} icon={ShieldAlert} tone="text-[#FF3B30]" />
        <Stat label="Pods Monitored" value={s?.pods_monitored} sub={`${s?.events_by_namespace?.length ?? 0} namespaces active`} icon={Boxes} />
        <Stat label="Agent Overhead" value={agent ? `${agent.cpu_percent}% CPU` : '—'} sub={agent ? `${agent.rss_mb} MB RSS · ${online} node(s) online` : 'no heartbeat'} icon={Cpu} tone={online ? 'text-[#34C759]' : 'text-[#86868B]'} />
        <Stat label="Detection Latency" value={agent?.latency_p50_ms != null ? `${agent.latency_p50_ms} ms` : '—'} sub={agent ? `p95 ${agent.latency_p95_ms ?? '—'} ms · ${agent.events_per_sec} ev/s` : ''} icon={Timer} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Events & Alerts Over Time" className="lg:col-span-2 p-4 md:p-5">
          <div className="h-64">
            {timeline.length ? (
              <ResponsiveContainer>
                <ComposedChart data={timeline}>
                  <CartesianGrid stroke="#E5E5EA" strokeDasharray="3 3" />
                  <XAxis dataKey="label" stroke="#86868B" fontSize={11} />
                  <YAxis yAxisId="e" stroke="#86868B" fontSize={11} />
                  <YAxis yAxisId="a" orientation="right" stroke="#86868B" fontSize={11} allowDecimals={false} />
                  <Tooltip {...tooltipStyle} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Area yAxisId="e" dataKey="events" name="Events" stroke="#007AFF" fill="#007AFF22" type="monotone" />
                  <Bar yAxisId="a" dataKey="High" stackId="a" fill={SEV_COLOR.High} />
                  <Bar yAxisId="a" dataKey="Medium" stackId="a" fill={SEV_COLOR.Medium} />
                  <Bar yAxisId="a" dataKey="Low" stackId="a" fill={SEV_COLOR.Low} />
                </ComposedChart>
              </ResponsiveContainer>
            ) : <Empty />}
          </div>
        </Card>

        <Card title="Alerts by Severity" className="p-4 md:p-5">
          <div className="h-64">
            {sevData.length ? (
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={3}>
                    {sevData.map((d) => <Cell key={d.name} fill={SEV_COLOR[d.name]} />)}
                  </Pie>
                  <Tooltip {...tooltipStyle} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            ) : <Empty>No alerts in this window</Empty>}
          </div>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Attack Categories" className="p-4 md:p-5">
          <div className="h-56">
            {catData.length ? (
              <ResponsiveContainer>
                <BarChart data={catData} layout="vertical" margin={{ left: 30 }}>
                  <XAxis type="number" stroke="#86868B" fontSize={11} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" stroke="#86868B" fontSize={11} width={110} />
                  <Tooltip {...tooltipStyle} />
                  <Bar dataKey="value" fill="#007AFF" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : <Empty>No alerts in this window</Empty>}
          </div>
        </Card>

        <Card title="Kernel Events by Type" className="p-4 md:p-5">
          <div className="h-56">
            {typeData.length ? (
              <ResponsiveContainer>
                <BarChart data={typeData}>
                  <XAxis dataKey="name" stroke="#86868B" fontSize={11} />
                  <YAxis stroke="#86868B" fontSize={11} />
                  <Tooltip {...tooltipStyle} />
                  <Bar dataKey="value" fill="#007AFF" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : <Empty />}
          </div>
        </Card>

        <Card title="Riskiest Pods" className="p-4 md:p-5">
          {s?.top_pods?.length ? (
            <table className="w-full">
              <tbody>
                {s.top_pods.map((p) => (
                  <tr key={`${p.namespace}/${p.pod}`} className="border-t border-[#E5E5EA] first:border-t-0">
                    <td className="td py-3">
                      <p className="font-medium text-[#1D1D1F]">{p.pod}</p>
                      <p className="text-xs text-[#86868B]">{p.namespace}</p>
                    </td>
                    <td className="td py-3 text-right text-xs text-[#86868B]">{p.alerts} alerts</td>
                    <td className="td py-3"><RiskBar score={p.max_risk} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <Empty>No risky pods</Empty>}
          {s?.top_mitre?.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {s.top_mitre.map((m) => (
                <a key={m.technique} target="_blank" rel="noreferrer" href={`https://attack.mitre.org/techniques/${m.technique.replace('.', '/')}/`} className="mono rounded-full border border-[#E5E5EA] bg-[#F5F5F7] px-2 py-1 text-[10px] text-[#1D1D1F] hover:border-[#007AFF]">{m.technique} ×{m.alerts}</a>
              ))}
            </div>
          )}
        </Card>
      </div>

      <Card title="Latest Open Alerts" right={<Link to="/alerts" className="text-xs font-medium text-[#007AFF] hover:underline">View all →</Link>} className="p-4 md:p-5">
        {recent?.items?.length ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead><tr><th className="th">Seen</th><th className="th">Severity</th><th className="th">Alert</th><th className="th">Pod</th><th className="th">Activity</th><th className="th">Risk</th></tr></thead>
              <tbody>
                {recent.items.map((a) => (
                  <tr key={a.id} className="border-t border-[#E5E5EA]">
                    <td className="td whitespace-nowrap text-xs text-[#86868B]">{timeAgo(a.last_seen)}</td>
                    <td className="td"><SeverityBadge severity={a.severity} /></td>
                    <td className="td"><p className="font-medium text-[#1D1D1F]">{a.title}</p><p className="text-xs text-[#86868B]">{CAT_LABEL[a.category] || a.category} · {(a.mitre || []).join(', ')}</p></td>
                    <td className="td"><p className="text-[#1D1D1F]">{a.k8s?.pod}</p><p className="text-xs text-[#86868B]">{a.k8s?.namespace}</p></td>
                    <td className="td mono max-w-md truncate text-xs text-[#86868B]" title={subject(a.last_event || a.event)}>{subject(a.last_event || a.event)}</td>
                    <td className="td"><RiskBar score={a.risk_score} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty>No open alerts — all quiet</Empty>}
      </Card>
    </div>
  )
}
