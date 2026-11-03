// Client for the real backend: traffic_gateway/api.py (Flask, port 5000).
// Every function here maps to an endpoint that exists in that file.
//
// Base URL: empty by default, so requests go to this app's own origin and
// Vite's dev/preview proxy (vite.config.js) forwards /api/* to the gateway
// API. That keeps the dashboard working when it's opened from another
// laptop on the LAN. Set VITE_API_BASE_URL to bypass the proxy and call the
// API directly (it is CORS-enabled).
export const API_BASE_URL =
  (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE_URL) || ''

// What to show in "is it running?" messages when the base URL is the proxy.
export const API_DISPLAY_URL = API_BASE_URL || 'the gateway API (proxied to :5000)'

export const START_HINT =
  'Start it with: python -m traffic_gateway.run_pipeline (or python -m traffic_gateway.api --port 5000).'

const DEFAULT_TIMEOUT_MS = 6000

// Distinguishes *why* a request failed so callers (useApiResource) can show
// a different UI for "gateway isn't running" vs "gateway returned a 500" vs
// "gateway sent something that isn't JSON".
export class ApiError extends Error {
  constructor(message, { kind, httpStatus } = {}) {
    super(message)
    this.name = 'ApiError'
    this.kind = kind // 'unreachable' | 'timeout' | 'http' | 'parse'
    this.httpStatus = httpStatus
  }
}

function withQuery(path, params = {}) {
  const qs = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&')
  return qs ? `${path}?${qs}` : path
}

async function request(path, { method = 'GET', body, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  let res
  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      method,
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
  } catch (err) {
    if (err?.name === 'AbortError') {
      throw new ApiError(`Request to ${path} timed out after ${timeoutMs}ms`, { kind: 'timeout' })
    }
    throw new ApiError(`Could not reach ${API_DISPLAY_URL}${path}. ${START_HINT}`, {
      kind: 'unreachable',
    })
  } finally {
    clearTimeout(timer)
  }

  const text = await res.text()
  let data = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      // The Vite proxy answers 5xx with an HTML/plain body when the gateway
      // API is down; treat that as "unreachable", not as a parse bug.
      if (res.status >= 500) {
        throw new ApiError(`Could not reach ${API_DISPLAY_URL}${path}. ${START_HINT}`, {
          kind: 'unreachable',
          httpStatus: res.status,
        })
      }
      throw new ApiError(`${path} returned a response that isn't valid JSON`, { kind: 'parse' })
    }
  }

  // vite.config.js's proxy marks "the API process isn't running" this way.
  if (data?.proxy_error) {
    throw new ApiError(`Could not reach ${API_DISPLAY_URL}${path}. ${START_HINT}`, {
      kind: 'unreachable',
      httpStatus: res.status,
    })
  }

  if (!res.ok) {
    throw new ApiError(data?.error || `${path} responded with HTTP ${res.status}`, {
      kind: 'http',
      httpStatus: res.status,
    })
  }
  return data
}

// -- Reads -------------------------------------------------------------------
export const getHealth = () => request('/api/health')
export const getStats = () => request('/api/stats')
export const getLiveFeed = ({ limit } = {}) => request(withQuery('/api/live-feed', { limit }))
export const getMt3Results = ({ limit } = {}) => request(withQuery('/api/mt3-results', { limit }))
export const getActiveConfig = () => request('/api/active-config')
export const getConfigChanges = ({ limit } = {}) => request(withQuery('/api/config-changes', { limit }))
export const getLiveAccess = ({ limit } = {}) => request(withQuery('/api/live-access', { limit }))
export const getFootprints = ({ limit, ip } = {}) => request(withQuery('/api/footprints', { limit, ip }))
export const getThreatIntel = ({ limit } = {}) => request(withQuery('/api/threat-intel', { limit }))
export const refreshThreatIntel = () => request('/api/threat-intel/refresh', { method: 'POST' })
export const getBlacklist = () => request('/api/blacklist')
export const getWhitelist = () => request('/api/whitelist')

// -- Writes (access control) ----------------------------------------------------
export const blacklistIp = (ip, reason) =>
  request('/api/blacklist', { method: 'POST', body: { ip, reason: reason || undefined } })
export const whitelistIp = (ip, reason) =>
  request('/api/whitelist', { method: 'POST', body: { ip, reason: reason || undefined } })
export const unblacklistIp = (ip) =>
  request(`/api/blacklist/${encodeURIComponent(ip)}`, { method: 'DELETE' })
export const unwhitelistIp = (ip) =>
  request(`/api/whitelist/${encodeURIComponent(ip)}`, { method: 'DELETE' })

// RESET = drop the IP from both lists so the classifier decides afresh on its
// next connection (same as live.html's RESET button). A 404 just means it
// wasn't on that list, which is fine.
export async function resetIp(ip) {
  for (const fn of [unblacklistIp, unwhitelistIp]) {
    try {
      await fn(ip)
    } catch (err) {
      if (err?.httpStatus !== 404) throw err
    }
  }
}
