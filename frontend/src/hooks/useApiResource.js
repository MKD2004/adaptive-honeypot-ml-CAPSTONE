import { useCallback, useEffect, useRef, useState } from 'react'

export const API_STATUS = {
  LOADING: 'loading',
  SUCCESS: 'success',
  EMPTY: 'empty',
  ERROR: 'error',
  UNREACHABLE: 'unreachable',
}

// Wraps one services/api.js call with distinguishable loading / success /
// empty / error / unreachable states, so a page never has to guess why data
// isn't showing.
//
//   fetcher     - () => Promise<data>, one of the functions in services/api.js
//   isEmpty     - optional (data) => boolean; default treats null/undefined as empty
//   deps        - dependency array to re-fetch on (e.g. a limit or ip filter)
//   intervalMs  - optional polling interval. Background refreshes keep the
//                 current data on screen (no spinner flash) and never overlap.
export function useApiResource(fetcher, { isEmpty, deps = [], intervalMs } = {}) {
  const [state, setState] = useState({ status: API_STATUS.LOADING, data: null, error: null })
  const mountedRef = useRef(true)
  const inFlightRef = useRef(false)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  const load = useCallback(
    async ({ background = false } = {}) => {
      if (inFlightRef.current) return
      inFlightRef.current = true
      if (!background) setState((s) => ({ ...s, status: API_STATUS.LOADING }))
      try {
        const data = await fetcher()
        if (!mountedRef.current) return
        const empty = isEmpty ? isEmpty(data) : data === null || data === undefined
        setState({ status: empty ? API_STATUS.EMPTY : API_STATUS.SUCCESS, data, error: null })
      } catch (err) {
        if (!mountedRef.current) return
        const unreachable = err?.kind === 'unreachable' || err?.kind === 'timeout'
        setState({
          status: unreachable ? API_STATUS.UNREACHABLE : API_STATUS.ERROR,
          data: null,
          error: err,
        })
      } finally {
        inFlightRef.current = false
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    deps,
  )

  useEffect(() => {
    load()
    if (!intervalMs) return undefined
    const t = setInterval(() => load({ background: true }), intervalMs)
    return () => clearInterval(t)
  }, [load, intervalMs])

  // Manual reloads (e.g. after a BLOCK click) refresh in place too.
  const reload = useCallback(() => load({ background: true }), [load])

  return { ...state, reload }
}

export const hasData = (r) => r.status === API_STATUS.SUCCESS || r.status === API_STATUS.EMPTY
