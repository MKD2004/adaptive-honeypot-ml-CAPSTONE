import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Stage 1: no backend proxy yet. The gateway API lives at http://localhost:5000
// (traffic_gateway/api.py) and will be wired in via frontend/src/services once
// the visual layer is approved.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
})
