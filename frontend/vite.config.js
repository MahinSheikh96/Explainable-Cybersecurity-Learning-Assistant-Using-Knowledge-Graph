import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Fixed port so it always matches the CORS origin configured in the
// FastAPI backend (main.py allows http://localhost:5173 explicitly).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.js',
    globals: true,
  },
})