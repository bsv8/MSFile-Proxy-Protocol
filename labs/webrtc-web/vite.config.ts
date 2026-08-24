import { defineConfig } from 'vitest/config'

export default defineConfig({
  build: {
    target: 'es2022',
    sourcemap: false,
    chunkSizeWarningLimit: 4096
  },
  server: {
    port: 5173,
    strictPort: false,
    host: '127.0.0.1'
  },
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 30_000
  }
})
