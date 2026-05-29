// `@peculiar/x509` v2 (transitively imported via ./service -> ./crypto)
// requires reflect-metadata to be loaded before any peculiar/x509 import
// resolves. Side-effect import placed first to satisfy the polyfill order
// at module-graph resolution time.
import 'reflect-metadata'
import type { Plugin, PluginConstructor, ServerAPI } from '@signalk/server-api'
import type { IRouter, RequestHandler } from 'express'
import { CertStore } from './storage.js'
import { PassphraseSource } from './passphrase-source.js'
import {
  SslService,
  discoverAdvertisedHostname,
  discoverPrivateLanIps,
  type ServiceStatus
} from './service.js'
import { startRenewalScheduler, type SchedulerHandle } from './scheduler.js'
import { buildPublicRoutes, registerAdminRoutes, registerPublicCaRoutes } from './api.js'
import { buildConfigSchema, DEFAULT_CONFIG, type SignalkSslConfig } from './schema.js'

const PLUGIN_ID = 'signalk-ssl'
const PLUGIN_NAME = 'SignalK SSL'
const PLUGIN_DESCRIPTION =
  'Generate a local CA and issue trusted HTTPS certificates for your SignalK server.'

// Raw Express routes accumulate across plugin restarts; mount the public CA
// download only once per process.
let publicCaMounted = false

interface ExtendedServerAPI extends ServerAPI {
  readonly config?: {
    readonly configPath?: string
    // signalk-server resolves this through EXTERNALHOST → settings.proxy_host →
    // settings.hostname → os.hostname(). It is the exact source used by
    // src/mdns.js to advertise on the LAN, so it's the right thing to suggest
    // as a DNS SAN. Not in @signalk/server-api's typed surface.
    readonly getExternalHostname?: () => string
    // signalk-server only binds HTTPS when settings.ssl is true. The plugin
    // can issue and install a cert, but the server still serves plain HTTP
    // until this flag is flipped — so the webapp surfaces a help panel for
    // that case. Both fields are runtime-only, not in @signalk/server-api.
    readonly settings?: {
      readonly ssl?: boolean
      readonly port?: number
      readonly sslport?: number
    }
  }
  // At runtime the plugin's `app` is the Express application, so we can mount a
  // raw route at a public path (outside the auth-guarded /signalk/v1/api/*).
  // Not in @signalk/server-api's typed surface.
  readonly get?: (path: string, handler: RequestHandler) => unknown
}

const resolveConfig = (raw: object): SignalkSslConfig => {
  return { ...DEFAULT_CONFIG, ...(raw as Partial<SignalkSslConfig>) }
}

const resolveConfigPath = (app: ExtendedServerAPI, fallback: string): string => {
  return app.config?.configPath ?? fallback
}

/**
 * One-line status for the admin plugin list. statusMessage() must be
 * synchronous, so this formats a cached {@link ServiceStatus} snapshot rather
 * than reading the cert state from disk. Describes issuance state — not config —
 * so an operator can tell "issued and healthy" from "no cert yet" or "error" at
 * a glance. `null` snapshot means startup hasn't produced one yet.
 */
export const formatStatusMessage = (status: ServiceStatus | null): string => {
  if (status === null) {
    return 'starting'
  }
  if (status.permissionWarning !== null) {
    return `error: ${status.permissionWarning}`
  }
  if (!status.hasCa) {
    return 'no CA yet — enable and save config'
  }
  if (!status.hasLeaf) {
    return 'CA ready, no certificate issued yet'
  }
  const name = status.leafSansDns[0] ?? status.leafSansIp[0] ?? 'certificate'
  const days = status.leafDaysRemaining
  const expiry = days === null ? '' : ` · ${days.toString()}d left`
  const restart = status.restartRequired ? ' · restart to apply' : ''
  return `${name}${expiry}${restart}`
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
  // Cached snapshot for the synchronous statusMessage(); refreshed after each
  // issue attempt. Approximate between refreshes (the webapp /status is live).
  let lastStatus: ServiceStatus | null = null

  const refreshStatus = async (svc: SslService): Promise<void> => {
    try {
      lastStatus = await svc.status()
    } catch (e: unknown) {
      app.error(`${PLUGIN_ID} status refresh failed: ${String(e)}`)
    }
  }

  const plugin: Plugin = {
    id: PLUGIN_ID,
    name: PLUGIN_NAME,
    description: PLUGIN_DESCRIPTION,
    // Re-evaluated by signalk-server on every config-screen load, so the
    // discovered hostname and private-LAN IPs are injected as SAN defaults and
    // show up pre-filled in the form *before* the plugin is enabled.
    schema: () =>
      buildConfigSchema({
        dnsName: discoverAdvertisedHostname(rawHostname()),
        ipAddresses: discoverPrivateLanIps()
      }),

    start(rawConfig: object, _restart: (newConfiguration: object) => void): void {
      config = resolveConfig(rawConfig)

      const dataDir = app.getDataDirPath()
      const configPath = resolveConfigPath(extended, dataDir)
      store = new CertStore(dataDir)
      passphrase = new PassphraseSource(config.passphraseMode, store)
      service = new SslService({
        store,
        passphrase,
        config,
        configPath,
        // Evaluated per /status call so an `ssl: true` flip + restart is
        // reflected immediately (the webapp polls /status). Preserves null when
        // the server doesn't expose settings.ssl — collapsing that to false
        // would falsely trigger the enable-HTTPS panel on older servers.
        getServerNetState: () => {
          const settings = extended.config?.settings
          return {
            sslEnabled: typeof settings?.ssl === 'boolean' ? settings.ssl : null,
            httpPort: typeof settings?.port === 'number' ? settings.port : null,
            sslPort: typeof settings?.sslport === 'number' ? settings.sslport : null
          }
        }
      })

      // Mount the public CA download on the raw Express app (outside the
      // auth-guarded /signalk/v1/api/*), so a phone scanning the QR can fetch
      // the CA without a SignalK login even when allow_readonly is off. Once per
      // process — Express keeps handlers across plugin restarts. The handlers
      // read deps via an accessor so they pick up the current config/store after
      // a restart instead of capturing the first start's objects.
      if (!publicCaMounted && typeof extended.get === 'function') {
        registerPublicCaRoutes({ get: extended.get.bind(extended) }, () => {
          // start() always sets these before the routes can be hit; the closure
          // reads them live so a restart's fresh objects are picked up.
          if (service === null || store === null || passphrase === null) {
            throw new Error(`${PLUGIN_ID} public CA route hit before start completed`)
          }
          return { service, store, passphrase, config }
        })
        publicCaMounted = true
      }

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
          await refreshStatus(svcLocal)
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
        getRawHostname: rawHostname,
        onStatus: (s) => {
          lastStatus = s
        }
      })
    },

    signalKApiRoutes(router: IRouter): IRouter {
      if (service === null || store === null || passphrase === null) {
        return router
      }
      return buildPublicRoutes(router, { service, store, passphrase, config })
    },

    statusMessage(): string {
      return formatStatusMessage(lastStatus)
    }
  }

  return plugin
}

export default pluginConstructor
