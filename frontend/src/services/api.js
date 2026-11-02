// Read-only client for the real backend: traffic_gateway/api.py (Flask,
// CORS-open by default — see Stage 4 inspection report section I). Every
// function here is a GET against an endpoint that verifiably exists in that
// file; nothing here calls an endpoint that doesn't exist (e.g. there is no
// cve_intelligence endpoint, so no function for it appears below).
//
// Base URL is configurable via VITE_API_BASE_URL (frontend/.env.example),
// falling back to the gateway's documented default port.
export const API_BASE_URL =
  (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE_URL) ||
  'http://localhost:5000'

const DEFAULT_TIMEOUT_MS = 6000

// Distinguishes *why* a request failed so callers (useApiResource) can show
// a different UI for "gateway isn't running" vs "gateway returned a 500" vs
// "gateway sent something that isn't JSON" — collapsing these into one
// generic error would hide real backend problems behind a vague message.
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

async function getJSON(path, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  let res
  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      method: 'GET',
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    })
  } catch (err) {
    if (err?.name === 'AbortError') {
      throw new ApiError(`Request to ${path} timed out after ${timeoutMs}ms`, { kind: 'timeout' })
    }
    throw new ApiError(
      `Could not reach ${API_BASE_URL}${path} — is traffic_gateway/api.py running?`,
      { kind: 'unreachable' },
    )
  } finally {
    clearTimeout(timer)
  }

  if (!res.ok) {
    throw new ApiError(`${path} responded with HTTP ${res.status}`, {
      kind: 'http',
      httpStatus: res.status,
    })
  }

  const text = await res.text()
  if (!text) return null // a genuinely empty 200 body — not an error

  try {
    return JSON.parse(text)
  } catch {
    throw new ApiError(`${path} returned a response that isn't valid JSON`, { kind: 'parse' })
  }
}

// -- Read-only endpoint wrappers, matching traffic_gateway/api.py exactly --
// (see Stage 4 report section B for the line numbers each of these maps to)
export const getHealth = () => getJSON('/api/health')
export const getActiveConfig = () => getJSON('/api/active-config')
export const getConfigChanges = ({ limit } = {}) => getJSON(withQuery('/api/config-changes', { limit }))
export const getLiveAccess = ({ limit } = {}) => getJSON(withQuery('/api/live-access', { limit }))
export const getFootprints = ({ limit, ip } = {}) => getJSON(withQuery('/api/footprints', { limit, ip }))
export const getStats = () => getJSON('/api/stats')

// Defined per Stage 5A Part 5, but deliberately NOT called from
// LiveSessionsPage/SessionDetailsPage yet — the MT3 checkpoint/scaler/PCA
// are missing on this machine (Stage 4 report, Part 1), so those pages stay
// on mock data until the live pipeline is verified working.
export const getMt3Results = ({ limit } = {}) => getJSON(withQuery('/api/mt3-results', { limit }))
export const getLiveFeed = ({ limit } = {}) => getJSON(withQuery('/api/live-feed', { limit }))
