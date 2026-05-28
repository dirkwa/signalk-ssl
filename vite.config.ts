import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  root: 'src/webapp',
  // signalk-server serves a `signalk-webapp` package's static files at
  // /<module-name>/ (interfaces/webapps.ts), i.e. /signalk-ssl/ — NOT
  // /plugins/<id>/ (that mount is the plugin's API router). The asset base must
  // match the static mount or the built HTML 404s its own JS/CSS.
  base: '/signalk-ssl/',
  plugins: [react(), tailwindcss()],
  build: {
    outDir: '../../public',
    emptyOutDir: true,
    sourcemap: false
  }
})
