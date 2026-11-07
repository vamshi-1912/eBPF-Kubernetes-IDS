import React, { useState } from 'react'
import { ShieldCheck } from 'lucide-react'
import { api } from '../api'

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const r = await api.post('/api/auth/login', { username, password })
      onLogin({ token: r.data.access_token, username: r.data.username, role: r.data.role })
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <form onSubmit={submit} className="card w-full max-w-sm p-8">
        <div className="mb-6 flex flex-col items-center text-center">
          <ShieldCheck className="mb-3 h-10 w-10 text-sky-400" />
          <h1 className="text-lg font-bold text-slate-100">eBPF Intrusion Detection</h1>
          <p className="text-xs text-slate-500">Observe Runtime · Detect Anomalies · Secure Kubernetes</p>
        </div>
        {error && <p className="mb-4 rounded bg-red-950/50 px-3 py-2 text-sm text-red-300">{error}</p>}
        <label className="mb-1 block text-xs text-slate-400">Username</label>
        <input className="input mb-4 w-full" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
        <label className="mb-1 block text-xs text-slate-400">Password</label>
        <input className="input mb-6 w-full" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
        <button className="btn-primary w-full justify-center" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
    </div>
  )
}
