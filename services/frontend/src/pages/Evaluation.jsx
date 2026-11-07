import React from 'react'
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { CheckCircle2, XCircle } from 'lucide-react'
import { usePoll } from '../api'
import { CAT_LABEL, Card, Empty, ErrorNote, SeverityBadge, Stat, pct, tooltipStyle } from '../components/ui'

function MetricRow({ name, m, note }) {
  if (!m) return null
  return (
    <tr className="border-t border-slate-800/60">
      <td className="td text-slate-300">{name}{note && <p className="text-xs text-slate-500">{note}</p>}</td>
      <td className="td mono">{m.samples?.toLocaleString?.() ?? '—'}</td>
      <td className="td mono">{pct(m.detection_rate)}</td>
      <td className="td mono">{pct(m.false_positive_rate, 2)}</td>
      <td className="td mono">{pct(m.precision)}</td>
      <td className="td mono">{m.f1 ?? '—'}</td>
      <td className="td mono">{m.roc_auc ?? '—'}</td>
    </tr>
  )
}

export default function Evaluation() {
  const { data, error } = usePoll('/api/evaluation', {}, 15000)
  const { data: agents } = usePoll('/api/agents', { history_minutes: 30 }, 10000)
  const r = data?.offline
  const rt = data?.runtime_15m || {}
  const live = data?.live?.[0]
  const hist = (agents?.[0]?.history || []).map((h) => ({ ...h, label: new Date(h.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }))
  const perCat = r ? Object.entries(r.per_category).filter(([k]) => k !== 'benign').map(([k, v]) => ({ name: CAT_LABEL[k] || k, detection: +(v.detection_rate * 100).toFixed(1), classification: +(v.category_accuracy * 100).toFixed(1) })) : []
  const imp = (r?.feature_importance || []).slice(0, 15).map((f) => ({ ...f, importance: +(f.importance * 100).toFixed(2) }))
  const cm = r?.holdout?.confusion_matrix

  return (
    <div>
      <h1 className="mb-1 text-xl font-bold text-slate-100">Evaluation</h1>
      <p className="mb-5 text-sm text-slate-500">Detection rate, false positives, latency and resource overhead — offline (model) and online (live cluster).</p>
      <ErrorNote error={error} />

      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Live cluster</h2>
      <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-6">
        <Stat label="Agent CPU (avg 15m)" value={rt.cpu_avg != null ? `${rt.cpu_avg.toFixed(2)}%` : '—'} sub={rt.cpu_max != null ? `max ${rt.cpu_max.toFixed(1)}% of one core` : ''} />
        <Stat label="Agent memory" value={rt.rss_avg != null ? `${rt.rss_avg.toFixed(0)} MB` : '—'} sub={rt.rss_max != null ? `max ${rt.rss_max.toFixed(0)} MB (agent + loader)` : ''} />
        <Stat label="Event → verdict" value={rt.lat_avg != null ? `${rt.lat_avg.toFixed(0)} ms` : '—'} sub={rt.lat_p95 != null ? `p95 ${rt.lat_p95.toFixed(0)} ms` : ''} />
        <Stat label="ML inference" value={rt.infer != null ? `${rt.infer.toFixed(3)} ms` : '—'} sub="per event (batched RF)" />
        <Stat label="Throughput" value={rt.eps != null ? `${rt.eps.toFixed(1)} ev/s` : '—'} sub={`${rt.emitted?.toLocaleString?.() ?? 0} kernel events`} />
        <Stat label="Kernel drops" value={rt.drops ?? '—'} sub="ring buffer full" tone={rt.drops ? 'text-amber-400' : 'text-emerald-400'} />
      </div>
      <div className="mb-6 grid gap-4 lg:grid-cols-2">
        <Card title="Agent overhead (last 30 min)">
          <div className="h-56">
            {hist.length ? (
              <ResponsiveContainer>
                <LineChart data={hist}>
                  <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                  <XAxis dataKey="label" stroke="#64748b" fontSize={11} />
                  <YAxis yAxisId="c" stroke="#64748b" fontSize={11} unit="%" />
                  <YAxis yAxisId="m" orientation="right" stroke="#64748b" fontSize={11} unit="MB" />
                  <Tooltip {...tooltipStyle} /><Legend wrapperStyle={{ fontSize: 12 }} />
                  <Line yAxisId="c" dataKey="cpu_percent" name="CPU %" stroke="#38bdf8" dot={false} />
                  <Line yAxisId="m" dataKey="rss_mb" name="RSS MB" stroke="#a78bfa" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            ) : <Empty>Waiting for agent heartbeats</Empty>}
          </div>
        </Card>
        <Card title="Detection latency & event rate">
          <div className="h-56">
            {hist.length ? (
              <ResponsiveContainer>
                <LineChart data={hist}>
                  <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                  <XAxis dataKey="label" stroke="#64748b" fontSize={11} />
                  <YAxis yAxisId="l" stroke="#64748b" fontSize={11} unit="ms" />
                  <YAxis yAxisId="e" orientation="right" stroke="#64748b" fontSize={11} />
                  <Tooltip {...tooltipStyle} /><Legend wrapperStyle={{ fontSize: 12 }} />
                  <Line yAxisId="l" dataKey="latency_avg_ms" name="avg latency ms" stroke="#f59e0b" dot={false} />
                  <Line yAxisId="l" dataKey="latency_p95_ms" name="p95 latency ms" stroke="#ef4444" dot={false} />
                  <Line yAxisId="e" dataKey="events_per_sec" name="events/s" stroke="#34d399" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            ) : <Empty>Waiting for agent heartbeats</Empty>}
          </div>
        </Card>
      </div>

      <Card title={live ? `Attack simulation · ${new Date(live.created_at).toLocaleString()}` : 'Attack simulation'} className="mb-6"
        right={live && <span className="text-xs text-slate-500">evaluation/run_live_eval.py</span>}>
        {live ? (
          <>
            <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-5">
              <Stat label="Detection rate" value={pct(live.attacks?.detection_rate)} sub={`${live.attacks?.detected}/${live.attacks?.total} attack scenarios`} tone="text-emerald-400" />
              <Stat label="False positive rate" value={pct(live.benign?.false_positive_rate)} sub={`${live.benign?.false_positives}/${live.benign?.total} benign scenarios`} />
              <Stat label="Mean detection latency" value={live.latency_ms?.avg != null ? `${live.latency_ms.avg} ms` : '—'} sub={live.latency_ms?.p95 != null ? `p95 ${live.latency_ms.p95} ms` : ''} />
              <Stat label="Exec overhead" value={live.overhead?.overhead_percent != null ? `${live.overhead.overhead_percent}%` : '—'} sub={live.overhead ? `${live.overhead.iterations} execs, ${live.overhead.with_agent_seconds}s vs ${live.overhead.baseline_seconds}s` : 'not measured'} />
              <Stat label="Workload" value={live.target || '—'} sub={live.notes} />
            </div>
            <div className="max-h-[420px] overflow-auto">
              <table className="w-full">
                <thead><tr><th className="th">Scenario</th><th className="th">Kind</th><th className="th">Result</th><th className="th">Severity</th><th className="th">Latency</th><th className="th">Alerts raised</th></tr></thead>
                <tbody>
                  {(live.results || []).map((x) => {
                    const ok = x.kind === 'attack' ? x.detected : !x.detected
                    return (
                      <tr key={x.name} className="border-t border-slate-800/60">
                        <td className="td"><p className="text-slate-200">{x.name}</p><p className="mono text-xs text-slate-500">{x.command}</p></td>
                        <td className="td text-xs">{x.kind === 'attack' ? <span className="text-red-300">attack · {CAT_LABEL[x.category] || x.category}</span> : <span className="text-emerald-300">benign</span>}</td>
                        <td className="td">{ok ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : <XCircle className="h-4 w-4 text-red-400" />}</td>
                        <td className="td"><SeverityBadge severity={x.severity} /></td>
                        <td className="td mono text-xs">{x.latency_ms != null ? `${x.latency_ms} ms` : '—'}</td>
                        <td className="td text-xs text-slate-400">{(x.titles || []).join('; ')}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </>
        ) : <Empty>Run <span className="mono mx-1 text-slate-300">python evaluation/run_live_eval.py</span> to execute the attack simulation in the cluster</Empty>}
      </Card>

      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Model (offline)</h2>
      {!r ? <Card><Empty>The agent publishes the model report on start-up</Empty></Card> : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-5">
            <Stat label="Detection rate" value={pct(r.holdout.detection_rate, 2)} sub="hold-out 20%" tone="text-emerald-400" />
            <Stat label="False positive rate" value={pct(r.holdout.false_positive_rate, 2)} sub="benign events flagged" />
            <Stat label="Precision / F1" value={`${pct(r.holdout.precision, 1)} / ${r.holdout.f1}`} sub={`ROC-AUC ${r.holdout.roc_auc}`} />
            <Stat label="5-fold CV F1" value={`${r.cross_validation.f1_mean} ± ${r.cross_validation.f1_std}`} sub={`det ${pct(r.cross_validation.detection_rate_mean)} · fpr ${pct(r.cross_validation.false_positive_rate_mean, 2)}`} />
            <Stat label="Model" value={r.model_version} sub={`RandomForest · ${r.params.n_estimators} trees · ${r.dataset.features} features`} />
          </div>
          <div className="mb-4 grid gap-4 lg:grid-cols-3">
            <Card title="Benchmarks" className="lg:col-span-2">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead><tr><th className="th">Test set</th><th className="th">Samples</th><th className="th">Detection</th><th className="th">FPR</th><th className="th">Precision</th><th className="th">F1</th><th className="th">AUC</th></tr></thead>
                  <tbody>
                    <MetricRow name="Hold-out (stratified 20%)" m={r.holdout} />
                    <MetricRow name="Edge cases only" m={r.edge_cases} note="look-alike benign / evasive attacks" />
                    <MetricRow name="Non-edge cases" m={r.non_edge_cases} />
                    <MetricRow name="Unseen template families" m={r.unseen_templates} note="whole attack/benign families never seen in training" />
                    <MetricRow name="Baseline: Isolation Forest" m={r.baseline_isolation_forest} note="unsupervised v0 approach, same features" />
                  </tbody>
                </table>
              </div>
              <p className="mt-3 text-xs text-slate-500">Dataset: {r.dataset.rows.toLocaleString()} labelled events ({r.dataset.malicious.toLocaleString()} malicious, {r.dataset.edge_case_rows.toLocaleString()} edge cases) from {r.dataset.templates} template families · inference {r.inference_latency_ms.per_event_in_batch_of_256} ms/event batched, {r.inference_latency_ms.single_event} ms single.</p>
            </Card>
            <Card title="Confusion matrix (hold-out)">
              {cm && (
                <div className="grid grid-cols-3 gap-1 text-center text-sm">
                  <div /><div className="text-xs text-slate-500">pred. benign</div><div className="text-xs text-slate-500">pred. malicious</div>
                  <div className="self-center text-xs text-slate-500">benign</div>
                  <div className="rounded bg-emerald-500/15 py-4 font-bold text-emerald-300">{cm.tn}</div>
                  <div className="rounded bg-red-500/10 py-4 font-bold text-red-300">{cm.fp}</div>
                  <div className="self-center text-xs text-slate-500">malicious</div>
                  <div className="rounded bg-red-500/10 py-4 font-bold text-red-300">{cm.fn}</div>
                  <div className="rounded bg-emerald-500/15 py-4 font-bold text-emerald-300">{cm.tp}</div>
                </div>
              )}
            </Card>
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Per attack category (hold-out)">
              <div className="h-72">
                <ResponsiveContainer>
                  <BarChart data={perCat} layout="vertical" margin={{ left: 40 }}>
                    <XAxis type="number" domain={[0, 100]} stroke="#64748b" fontSize={11} unit="%" />
                    <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={11} width={120} />
                    <Tooltip {...tooltipStyle} /><Legend wrapperStyle={{ fontSize: 12 }} />
                    <Bar dataKey="detection" name="detected" fill="#34d399" />
                    <Bar dataKey="classification" name="correct category" fill="#38bdf8" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
            <Card title="Top features (Random Forest importance)">
              <div className="h-72">
                <ResponsiveContainer>
                  <BarChart data={imp} layout="vertical" margin={{ left: 40 }}>
                    <XAxis type="number" stroke="#64748b" fontSize={11} unit="%" />
                    <YAxis type="category" dataKey="feature" stroke="#64748b" fontSize={10} width={140} />
                    <Tooltip {...tooltipStyle} />
                    <Bar dataKey="importance" fill="#a78bfa" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
          </div>
        </>
      )}
    </div>
  )
}
