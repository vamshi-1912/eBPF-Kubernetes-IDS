import React, { useEffect, useState } from 'react'
import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { Activity, BarChart3, FlaskConical, LogOut, ShieldAlert, ShieldCheck } from 'lucide-react'
import { setToken, setUnauthorizedHandler } from './api'
import Login from './pages/Login'
import Overview from './pages/Overview'
import Alerts from './pages/Alerts'
import Events from './pages/Events'
import Evaluation from './pages/Evaluation'

function loadSession() {
  try { return JSON.parse(localStorage.getItem('ids_session')) } catch { return null }
}

export default function App() {
  const [session, setSession] = useState(() => {
    const s = loadSession()
    if (s?.token) setToken(s.token)
    return s
  })

  const logout = () => {
    localStorage.removeItem('ids_session')
    setToken(null)
    setSession(null)
  }
  useEffect(() => { setUnauthorizedHandler(logout) }, [])

  const onLogin = (s) => {
    localStorage.setItem('ids_session', JSON.stringify(s))
    setToken(s.token)
    setSession(s)
  }

  if (!session?.token) return <Login onLogin={onLogin} />

  const nav = [
    { to: '/', label: 'Overview', icon: BarChart3 },
    { to: '/alerts', label: 'Alerts', icon: ShieldAlert },
    { to: '/events', label: 'Events', icon: Activity },
    { to: '/evaluation', label: 'Evaluation', icon: FlaskConical },
  ]
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col border-r border-slate-800 bg-slate-950 p-4 md:flex">
        <div className="mb-8 flex items-center gap-2">
          <ShieldCheck className="h-7 w-7 text-sky-400" />
          <div>
            <p className="text-sm font-bold leading-tight text-slate-100">eBPF IDS</p>
            <p className="text-[11px] text-slate-500">Kubernetes runtime security</p>
          </div>
        </div>
        <nav className="flex flex-1 flex-col gap-1">
          {nav.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} end={to === '/'}
              className={({ isActive }) => `flex items-center gap-2 rounded-md px-3 py-2 text-sm ${isActive ? 'bg-sky-500/10 text-sky-300' : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'}`}>
              <Icon className="h-4 w-4" />{label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-slate-800 pt-3 text-xs text-slate-500">
          <p className="mb-2">Signed in as <span className="text-slate-300">{session.username}</span> ({session.role})</p>
          <button onClick={logout} className="btn-ghost w-full justify-center"><LogOut className="h-3.5 w-3.5" />Sign out</button>
        </div>
      </aside>
      <div className="flex-1 overflow-x-hidden">
        <div className="flex gap-1 border-b border-slate-800 p-2 md:hidden">
          {nav.map(({ to, label }) => (
            <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => `rounded px-3 py-1.5 text-xs ${isActive ? 'bg-sky-500/10 text-sky-300' : 'text-slate-400'}`}>{label}</NavLink>
          ))}
          <button onClick={logout} className="ml-auto text-xs text-slate-400">Sign out</button>
        </div>
        <main className="mx-auto max-w-[1500px] p-4 md:p-6">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/events" element={<Events />} />
            <Route path="/evaluation" element={<Evaluation />} />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}
