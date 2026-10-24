import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/health': 'http://127.0.0.1:8080',
      '/auth': 'http://127.0.0.1:8080',
      '/sites': 'http://127.0.0.1:8080',
      '/users': 'http://127.0.0.1:8080',
      '/kyc': 'http://127.0.0.1:8080',
      '/snapshots': 'http://127.0.0.1:8080',
      '/forensics': 'http://127.0.0.1:8080',
      '/events': { target: 'ws://127.0.0.1:8080', ws: true },
      '/audit': 'http://127.0.0.1:8080',
      '/admin': 'http://127.0.0.1:8080',
      '/my': 'http://127.0.0.1:8080',
      '/stats': 'http://127.0.0.1:8080',
    },
  },
})
