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
    },
  },
})
