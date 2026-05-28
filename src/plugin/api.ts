import type { IRouter, Request, Response, NextFunction } from 'express'
import { buildMobileconfig } from './mobileconfig.js'
import type { SslService, ServiceStatus } from './service.js'
import { discoverAdvertisedHostname, discoverLocalIps } from './service.js'
import type { SignalkSslConfig } from './schema.js'
import type { PassphraseSource } from './passphrase-source.js'
import type { CertStore } from './storage.js'

export interface ApiDeps {
  readonly service: SslService
  readonly store: CertStore
  readonly passphrase: PassphraseSource
  readonly config: SignalkSslConfig
}

export interface AdminApiDeps extends ApiDeps {
  /** Returns the raw hostname signalk-server uses for mDNS advertisement,
   * or '' if unavailable. See ExtendedServerAPI in src/plugin/index.ts. */
  readonly getRawHostname: () => string
  /** Called with each fresh status the admin routes compute, so the plugin can
   * keep its synchronous statusMessage() cache current (the webapp polls
   * /status, and /renew recomputes it). Optional. */
  readonly onStatus?: (status: ServiceStatus) => void
}

const sendJson = (res: Response, status: number, body: unknown): void => {
  res.status(status).type('application/json').send(JSON.stringify(body))
}

const asyncRoute =
  (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => {
    fn(req, res).catch((err: unknown) => {
      next(err)
    })
  }

/** Mounted by the server at /plugins/signalk-ssl/* — admin auth applied. */
export const registerAdminRoutes = (router: IRouter, deps: AdminApiDeps): void => {
  router.get(
    '/status',
    asyncRoute(async (_req, res) => {
      const s: ServiceStatus = await deps.service.status()
      deps.onStatus?.(s)
      sendJson(res, 200, s)
    })
  )

  router.get('/api/local-ips', (_req, res) => {
    sendJson(res, 200, {
      ipAddresses: discoverLocalIps(),
      dnsName: discoverAdvertisedHostname(deps.getRawHostname())
    })
  })

  router.post(
    '/renew',
    asyncRoute(async (_req, res) => {
      const out = await deps.service.issueIfNeeded()
      if (deps.onStatus) {
        deps.onStatus(await deps.service.status())
      }
      sendJson(res, 200, out)
    })
  )

  router.post(
    '/unlock',
    asyncRoute(async (req, res) => {
      const body = (req.body ?? {}) as { passphrase?: unknown }
      if (typeof body.passphrase !== 'string' || body.passphrase.length === 0) {
        sendJson(res, 400, { error: 'passphrase required' })
        return
      }
      deps.passphrase.unlockWith(body.passphrase)
      const out = await deps.service.issueIfNeeded()
      sendJson(res, 200, out)
    })
  )

  router.post('/lock', (_req, res) => {
    deps.passphrase.lock()
    deps.service.acknowledgeRestart()
    sendJson(res, 200, { kind: 'locked' })
  })

  router.post(
    '/rotate',
    asyncRoute(async (req, res) => {
      const body = (req.body ?? {}) as { oldPassphrase?: unknown; newPassphrase?: unknown }
      if (typeof body.oldPassphrase !== 'string' || body.oldPassphrase.length === 0) {
        sendJson(res, 400, { error: 'oldPassphrase required' })
        return
      }
      if (typeof body.newPassphrase !== 'string' || body.newPassphrase.length === 0) {
        sendJson(res, 400, { error: 'newPassphrase required' })
        return
      }
      const out = await deps.service.rotatePassphrase(body.oldPassphrase, body.newPassphrase)
      // Map the outcome to a status: a wrong old passphrase is a client error,
      // a missing CA is a 409 (nothing to rotate yet), an internal failure 500.
      const status =
        out.kind === 'rotated'
          ? 200
          : out.kind === 'wrong-passphrase'
            ? 403
            : out.kind === 'no-ca'
              ? 409
              : 500
      sendJson(res, status, out)
    })
  )
}

/** Mounted by the server at /signalk/v1/api/* via signalKApiRoutes — read-only public. */
export const buildPublicRoutes = (router: IRouter, deps: ApiDeps): IRouter => {
  router.get(
    '/ssl/ca.crt',
    asyncRoute(async (_req, res) => {
      const ca = await deps.store.readCaState()
      if (ca === null) {
        sendJson(res, 404, { error: 'no CA configured' })
        return
      }
      res.type('application/x-x509-ca-cert').send(ca.certificatePem)
    })
  )

  router.get(
    '/ssl/ca.mobileconfig',
    asyncRoute(async (_req, res) => {
      const ca = await deps.store.readCaState()
      if (ca === null) {
        sendJson(res, 404, { error: 'no CA configured' })
        return
      }
      const xml = buildMobileconfig(ca.certificatePem, {
        caName: deps.config.commonName,
        organization: deps.config.organization
      })
      res.type('application/x-apple-aspen-config').send(xml)
    })
  )

  return router
}
