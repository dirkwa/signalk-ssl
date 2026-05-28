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
import { ConfigSchema, DEFAULT_CONFIG, type SignalkSslConfig } from './schema.js'

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

const sansAreEmpty = (config: SignalkSslConfig): boolean =>
  config.sans.dnsNames.length === 0 && config.sans.ipAddresses.length === 0

/**
 * One-shot seed: on first run with an empty SAN list, pre-populate dnsNames
 * with the name the server advertises on mDNS so the user sees a sensible,
 * server-specific default in the plugin config screen instead of a blank field.
 *
 * Guarded by a persistent marker so it runs at most once per install: a user
 * who deletes the seeded name will not see it re-added on the next restart
 * (the SAN-provenance rule from AGENTS.md). Returns true when it triggered a
 * restart, in which case the caller must stop — the plugin is being restarted
 * with the new config.
 */
const maybeSeedHostname = async (
  store: CertStore,
  config: SignalkSslConfig,
  rawHostname: string,
  restart: (newConfiguration: object) => void,
  log: (msg: string) => void
): Promise<boolean> => {
  if (!sansAreEmpty(config) || (await store.hasSeededHostname())) {
    return false
  }
  const hostname = discoverAdvertisedHostname(rawHostname)
  if (hostname === null) {
    // No useful suggestion (container ID, localhost, etc.). Don't write the
    // marker — if the host gets a real name later, we still want to seed then.
    return false
  }
  await store.markHostnameSeeded(hostname)
  const newConfig: SignalkSslConfig = {
    ...config,
    sans: { ...config.sans, dnsNames: [hostname] }
  }
  log(`${PLUGIN_ID} seeding empty SANs with discovered hostname ${hostname}`)
  restart(newConfig)
  return true
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

    start(rawConfig: object, restart: (newConfiguration: object) => void): void {
      config = resolveConfig(rawConfig)

      const dataDir = app.getDataDirPath()
      const configPath = resolveConfigPath(extended, dataDir)
      store = new CertStore(dataDir)
      passphrase = new PassphraseSource(config.passphraseMode, store)
      service = new SslService({ store, passphrase, config, configPath })

      const svcLocal = service
      const storeLocal = store
      const cfgLocal = config
      const logSchedulerError = (err: unknown): void => {
        app.error(`${PLUGIN_ID} scheduled renewal failed: ${String(err)}`)
      }
      void storeLocal
        .init()
        .then(async () => {
          // First-run SAN seed must run before the issue flow: if it triggers a
          // restart, start() runs again with the seeded config and the issue
          // happens then. Bail out here so we don't issue against empty SANs and
          // immediately get restarted out from under it.
          try {
            const rawHostname = extended.config?.getExternalHostname?.() ?? ''
            const restarted = await maybeSeedHostname(
              storeLocal,
              cfgLocal,
              rawHostname,
              restart,
              (msg) => {
                app.debug(msg)
              }
            )
            if (restarted) {
              return
            }
          } catch (e: unknown) {
            // A seed failure must never block cert issuance — log and continue.
            app.error(`${PLUGIN_ID} hostname seed failed: ${String(e)}`)
          }
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
        getRawHostname: () => extended.config?.getExternalHostname?.() ?? ''
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
