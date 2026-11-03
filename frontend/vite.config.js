import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// The dashboard calls /api/* on its own origin and this proxy forwards it to
// traffic_gateway/api.py. Same-origin requests mean no CORS and no hardcoded
// "localhost" — so the dashboard also works when opened from another laptop
// on the LAN (npm run dev -- --host). Change the target with
// VITE_API_PROXY_TARGET in .env.local if the API runs elsewhere.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const target = env.VITE_API_PROXY_TARGET || 'http://localhost:5000'

  const proxy = {
    '/api': {
      target,
      changeOrigin: true,
      configure: (p) => {
        // When the API isn't running, answer with a JSON marker instead of an
        // empty 500 so services/api.js can show "unreachable", not "error".
        p.on('error', (_err, _req, res) => {
          if (res.headersSent || typeof res.writeHead !== 'function') return
          res.writeHead(502, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: `gateway API unreachable at ${target}`, proxy_error: true }))
        })
      },
    },
  }

  return {
    plugins: [react()],
    server: { port: 5173, proxy },
    preview: { port: 4173, proxy },
    build: {
      rollupOptions: {
        output: {
          // Charts are the bulk of the bundle; keep them in their own chunk.
          manualChunks: {
            react: ['react', 'react-dom', 'react-router-dom'],
            charts: ['recharts'],
          },
        },
      },
    },
  }
})
