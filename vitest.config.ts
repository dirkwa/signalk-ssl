import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx'],
    coverage: {
      provider: 'v8',
      include: ['src/plugin/**/*.ts'],
      exclude: ['src/plugin/**/*.d.ts', 'src/plugin/types.ts'],
      reporter: ['text', 'html']
    }
  }
})
