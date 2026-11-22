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
    <div className="flex min-h-screen bg-[#F5F5F7] text-[#1D1D1F]">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-[#E5E5EA] bg-white p-5 md:flex">
        <div className="mb-8 flex items-center gap-3 border-b border-[#F2F2F7] pb-4">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[#EAF3FF] text-[#007AFF]">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <p className="text-sm font-semibold leading-tight text-[#1D1D1F]">eBPF IDS</p>
            <p className="text-[11px] text-[#86868B]">Runtime Security</p>
          </div>
        </div>

        <nav className="flex flex-1 flex-col gap-1">
          {nav.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => `flex min-w-0 items-center gap-2 rounded-xl px-3 py-2.5 text-sm transition-colors ${isActive ? 'bg-[#EAF3FF] text-[#007AFF]' : 'text-[#1D1D1F]/80 hover:bg-[#F5F5F7] hover:text-[#1D1D1F]'}`}
            >
              <Icon className="h-4 w-4 shrink-0" />
              <span className="whitespace-nowrap">{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-[#E5E5EA] pt-3">
          <div className="mb-3 text-xs text-[#86868B]">
            <span className="block text-[10px] uppercase tracking-[0.12em] text-[#86868B]">Signed in</span>
            <span className="mt-1 block font-medium text-[#1D1D1F]">{session.username}</span>
            <span className="text-[#86868B]">{session.role}</span>
          </div>
          <button onClick={logout} className="btn-ghost w-full justify-center">
            <LogOut className="h-3.5 w-3.5" />
            Sign out
          </button>
        </div>
      </aside>

      <div className="flex-1 overflow-x-hidden">
        <div className="flex gap-1 border-b border-[#E5E5EA] bg-white p-2 md:hidden">
          {nav.map(({ to, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => `rounded-lg px-3 py-1.5 text-xs transition ${isActive ? 'bg-[#EAF3FF] text-[#007AFF]' : 'text-[#86868B]'}`}
            >
              {label}
            </NavLink>
          ))}
          <button onClick={logout} className="ml-auto text-xs text-[#86868B]">Sign out</button>
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
