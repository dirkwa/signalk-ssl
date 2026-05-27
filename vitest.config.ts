import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx'],
    // @peculiar/x509 v2 uses tsyringe which requires reflect-metadata
    // to be loaded before any peculiar/x509 import is resolved. Setup files
    // are imported before the test modules, so this guarantees the polyfill
    // is in place no matter which test imports crypto.ts first.
    setupFiles: ['reflect-metadata'],
    coverage: {
      provider: 'v8',
      include: ['src/plugin/**/*.ts'],
      exclude: ['src/plugin/**/*.d.ts', 'src/plugin/types.ts'],
      reporter: ['text', 'html']
    }
  }
})
