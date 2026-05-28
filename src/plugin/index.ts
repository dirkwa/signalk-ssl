// `@peculiar/x509` v2 (transitively imported via ./service -> ./crypto)
// requires reflect-metadata to be loaded before any peculiar/x509 import
// resolves. Side-effect import placed first to satisfy the polyfill order
// at module-graph resolution time.
import 'reflect-metadata'
import type { Plugin, PluginConstructor, ServerAPI } from '@signalk/server-api'
import type { IRouter } from 'express'
import { CertStore } from './storage.js'
import { PassphraseSource } from './passphrase-source.js'
import { SslService, discoverAdvertisedHostname } from './service.js'
import { startRenewalScheduler, type SchedulerHandle } from './scheduler.js'
import { buildPublicRoutes, registerAdminRoutes } from './api.js'
import { buildConfigSchema, DEFAULT_CONFIG, type SignalkSslConfig } from './schema.js'

const PLUGIN_ID = 'signalk-ssl'
const PLUGIN_NAME = 'SignalK SSL'
const PLUGIN_DESCRIPTION =
  'Generate a local CA and issue trusted HTTPS certificates for your SignalK server.'

interface ExtendedServerAPI extends ServerAPI {
  readonly config?: {
    readonly configPath?: string
    // signalk-server resolves this through EXTERNALHOST → settings.proxy_host →
    // settings.hostname → os.hostname(). It is the exact source used by
    // src/mdns.js to advertise on the LAN, so it's the right thing to suggest
    // as a DNS SAN. Not in @signalk/server-api's typed surface.
    readonly getExternalHostname?: () => string
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
  // The raw hostname signalk-server uses for mDNS (EXTERNALHOST → proxy_host →
  // settings.hostname → os.hostname()), '' when unavailable.
  const rawHostname = (): string => extended.config?.getExternalHostname?.() ?? ''
  let scheduler: SchedulerHandle | null = null
  let service: SslService | null = null
  let store: CertStore | null = null
  let passphrase: PassphraseSource | null = null
  let config: SignalkSslConfig = DEFAULT_CONFIG

  const plugin: Plugin = {
    id: PLUGIN_ID,
    name: PLUGIN_NAME,
    description: PLUGIN_DESCRIPTION,
    // Re-evaluated by signalk-server on every config-screen load, so the
    // discovered hostname is injected as the dnsNames default and shows up
    // pre-filled in the form *before* the plugin is enabled.
    schema: () => buildConfigSchema(discoverAdvertisedHostname(rawHostname())),

    start(rawConfig: object, _restart: (newConfiguration: object) => void): void {
      config = resolveConfig(rawConfig)

      const dataDir = app.getDataDirPath()
      const configPath = resolveConfigPath(extended, dataDir)
      store = new CertStore(dataDir)
      passphrase = new PassphraseSource(config.passphraseMode, store)
      service = new SslService({ store, passphrase, config, configPath })

      const svcLocal = service
      const storeLocal = store
      const logSchedulerError = (err: unknown): void => {
        app.error(`${PLUGIN_ID} scheduled renewal failed: ${String(err)}`)
      }
      void storeLocal
        .init()
        .then(async () => {
          try {
            const warning = await svcLocal.checkWritePermissions()
            if (warning !== null) {
              app.error(`${PLUGIN_ID} permission warning: ${warning}`)
            }
          } catch (e: unknown) {
            app.error(`${PLUGIN_ID} permission probe failed: ${String(e)}`)
          }
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
        // Terminal guard: store.init() (mkdir on a read-only / UID-shifted data
        // dir) or a throw from startRenewalScheduler would otherwise surface as
        // an unhandled rejection. The per-block try/catch above keep the issue
        // flow going; this only catches what they can't. scheduler is left null
        // on failure (the assignment is the last statement), so stop() is safe.
        .catch((e: unknown) => {
          app.error(`${PLUGIN_ID} startup failed: ${String(e)}`)
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
      registerAdminRoutes(router, {
        service,
        store,
        passphrase,
        config,
        getRawHostname: rawHostname
      })
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
