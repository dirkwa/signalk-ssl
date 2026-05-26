// `@peculiar/x509` v2 (transitively imported via ./service -> ./crypto)
// requires reflect-metadata to be loaded before any peculiar/x509 import
// resolves. Side-effect import placed first to satisfy the polyfill order
// at module-graph resolution time.
import 'reflect-metadata'
import type { Plugin, PluginConstructor, ServerAPI } from '@signalk/server-api'
import type { IRouter } from 'express'
import { CertStore } from './storage.js'
import { PassphraseSource } from './passphrase-source.js'
import { SslService } from './service.js'
import { startRenewalScheduler, type SchedulerHandle } from './scheduler.js'
import { buildPublicRoutes, registerAdminRoutes } from './api.js'
import { ConfigSchema, DEFAULT_CONFIG, type SignalkSslConfig } from './schema.js'

const PLUGIN_ID = 'signalk-ssl'
const PLUGIN_NAME = 'SignalK SSL'
const PLUGIN_DESCRIPTION =
  'Generate a local CA and issue trusted HTTPS certificates for your SignalK server.'

interface ExtendedServerAPI extends ServerAPI {
  readonly config?: {
    readonly configPath?: string
  }
}

const resolveConfig = (raw: object): SignalkSslConfig => {
  return { ...DEFAULT_CONFIG, ...(raw as Partial<SignalkSslConfig>) }
}

const resolveConfigPath = (app: ExtendedServerAPI, fallback: string): string => {
  return app.config?.configPath ?? fallback
}

const pluginConstructor: PluginConstructor = (app: ServerAPI): Plugin => {
  const extended = app as ExtendedServerAPI
  let scheduler: SchedulerHandle | null = null
  let service: SslService | null = null
  let store: CertStore | null = null
  let passphrase: PassphraseSource | null = null
  let config: SignalkSslConfig = DEFAULT_CONFIG

  const plugin: Plugin = {
    id: PLUGIN_ID,
    name: PLUGIN_NAME,
    description: PLUGIN_DESCRIPTION,
    schema: () => ConfigSchema,

    start(rawConfig: object, _restart: (newConfiguration: object) => void): void {
      config = resolveConfig(rawConfig)

      const dataDir = app.getDataDirPath()
      const configPath = resolveConfigPath(extended, dataDir)
      store = new CertStore(dataDir)
      passphrase = new PassphraseSource(config.passphraseMode, store)
      service = new SslService({ store, passphrase, config, configPath })

      const svcLocal = service
      const logSchedulerError = (err: unknown): void => {
        app.error(`${PLUGIN_ID} scheduled renewal failed: ${String(err)}`)
      }
      void store.init().then(async () => {
        try {
          const outcome = await svcLocal.issueIfNeeded()
          app.debug(`${PLUGIN_ID} initial issueIfNeeded: ${JSON.stringify(outcome)}`)
        } catch (e: unknown) {
          app.error(`${PLUGIN_ID} initial issue failed: ${String(e)}`)
        }
        // Start the scheduler only after init + initial issue have completed,
        // so a short test interval can't race against an uninitialised store.
        scheduler = startRenewalScheduler(svcLocal, logSchedulerError)
      })

      app.debug(`${PLUGIN_ID} started; data dir=${dataDir}; configPath=${configPath}`)
    },

    stop(): void {
      scheduler?.stop()
      scheduler = null
      passphrase?.lock()
      app.debug(`${PLUGIN_ID} stopped`)
    },

    registerWithRouter(router: IRouter): void {
      if (service === null || store === null || passphrase === null) {
        return
      }
      registerAdminRoutes(router, { service, store, passphrase, config })
    },

    signalKApiRoutes(router: IRouter): IRouter {
      if (service === null || store === null || passphrase === null) {
        return router
      }
      return buildPublicRoutes(router, { service, store, passphrase, config })
    },

    statusMessage(): string {
      if (service === null) {
        return 'starting'
      }
      // statusMessage must be synchronous; just describe the cached config.
      return `mode=${config.mode}, sans=${(
        config.sans.dnsNames.length + config.sans.ipAddresses.length
      ).toString()}`
    }
  }

  return plugin
}

export default pluginConstructor
