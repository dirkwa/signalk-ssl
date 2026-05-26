import { defineConfig } from 'vite'

export default defineConfig({
  root: 'src/webapp',
  base: '/plugins/signalk-ssl/',
  build: {
    outDir: '../../public',
    emptyOutDir: true,
    sourcemap: true
  }
})
