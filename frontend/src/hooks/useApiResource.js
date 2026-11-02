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
// isn't showing — it renders a different UI for each case instead of
// collapsing them into a single "no data" fallback.
//
//   fetcher   - () => Promise<data>, one of the functions in services/api.js
//   isEmpty   - optional (data) => boolean; default treats null/undefined as empty
//   deps      - dependency array to re-fetch on (e.g. a limit or ip filter)
export function useApiResource(fetcher, { isEmpty, deps = [] } = {}) {
  const [state, setState] = useState({ status: API_STATUS.LOADING, data: null, error: null })
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  const load = useCallback(async () => {
    setState((s) => ({ ...s, status: API_STATUS.LOADING }))
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
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  useEffect(() => {
    load()
  }, [load])

  return { ...state, reload: load }
}
