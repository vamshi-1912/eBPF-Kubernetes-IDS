import axios from 'axios'
import { useCallback, useEffect, useRef, useState } from 'react'

// Same-origin by default: nginx (in-cluster) or the Vite dev server proxies /api to FastAPI.
export const api = axios.create({ baseURL: import.meta.env.VITE_API_URL || '' })

export function setToken(token) {
  if (token) api.defaults.headers.common.Authorization = `Bearer ${token}`
  else delete api.defaults.headers.common.Authorization
}

let onUnauthorized = () => {}
export function setUnauthorizedHandler(fn) { onUnauthorized = fn }

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401 && !err.config.url.includes('/auth/login')) onUnauthorized()
    return Promise.reject(err)
  },
)

/** Fetch `url` with `params` and refresh every `interval` ms (real-time view). */
export function usePoll(url, params = {}, interval = 5000) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const key = JSON.stringify(params)
  const timer = useRef(null)

  const load = useCallback(async () => {
    try {
      const r = await api.get(url, { params: JSON.parse(key) })
      setData(r.data)
      setError(null)
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }, [url, key])

  useEffect(() => {
    setLoading(true)
    load()
    if (interval) timer.current = setInterval(load, interval)
    return () => clearInterval(timer.current)
  }, [load, interval])

  return { data, error, loading, reload: load }
}
