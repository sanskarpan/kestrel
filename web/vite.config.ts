import path from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  server: {
    proxy: {
      '/containers': 'http://localhost:7777',
      '/images': 'http://localhost:7777',
      '/system': 'http://localhost:7777',
      '/events': {
        target: 'http://localhost:7777',
        ws: false,
      },
    },
  },
})
