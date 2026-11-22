import React, { useState } from 'react'
import { ShieldCheck } from 'lucide-react'
import { api } from '../api'

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('Admin@123')
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
    <div className="flex min-h-screen items-center justify-center bg-[#F5F5F7] p-4">
      <form onSubmit={submit} className="card w-full max-w-sm p-8 shadow-[0_18px_48px_rgba(29,29,31,0.06)]">
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-[#EAF3FF] text-[#007AFF]">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <h1 className="text-xl font-semibold text-[#1D1D1F]">eBPF Intrusion Detection</h1>
          <p className="mt-1 text-xs text-[#86868B]">Observe Runtime · Detect Anomalies · Secure Kubernetes</p>
        </div>
        {error && <p className="mb-4 rounded-xl border border-[#FF3B30]/20 bg-[#FFE5E3] px-3 py-2 text-sm text-[#B21D18]">{error}</p>}
        <label className="mb-1 block text-xs font-medium text-[#86868B]">Username</label>
        <input className="input mb-4 w-full" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
        <label className="mb-1 block text-xs font-medium text-[#86868B]">Password</label>
        <input className="input mb-6 w-full" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
        <button className="btn-primary w-full justify-center" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
    </div>
  )
}
