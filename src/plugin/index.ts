import type { Plugin, PluginConstructor, ServerAPI } from '@signalk/server-api'

const PLUGIN_ID = 'signalk-ssl'
const PLUGIN_NAME = 'SignalK SSL'
const PLUGIN_DESCRIPTION =
  'Generate a local CA and issue trusted HTTPS certificates for your SignalK server.'

const pluginConstructor: PluginConstructor = (app: ServerAPI): Plugin => {
  const plugin: Plugin = {
    id: PLUGIN_ID,
    name: PLUGIN_NAME,
    description: PLUGIN_DESCRIPTION,
    schema: {
      type: 'object',
      properties: {}
    },
    start(_config: object, _restart: (newConfiguration: object) => void): void {
      app.debug(`${PLUGIN_ID} started (skeleton — Phase 1)`)
    },
    stop(): void {
      app.debug(`${PLUGIN_ID} stopped`)
    }
  }

  return plugin
}

export default pluginConstructor
