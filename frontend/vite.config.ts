import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Fail instead of silently moving to another port, so the page is
    // always at the documented address http://localhost:5173.
    strictPort: true,
    // The browser only talks to our backend: /api/... is forwarded to
    // FastAPI. The trailing slash keeps paths like /api-docs out.
    proxy: {
      '/api/': 'http://127.0.0.1:8000',
    },
  },
})
