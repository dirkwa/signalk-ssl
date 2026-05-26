import type { IRouter, Request, Response, NextFunction } from 'express'
import { buildMobileconfig } from './mobileconfig.js'
import type { SslService, ServiceStatus } from './service.js'
import { discoverLocalIps } from './service.js'
import type { SignalkSslConfig } from './schema.js'
import type { PassphraseSource } from './passphrase-source.js'
import type { CertStore } from './storage.js'

export interface ApiDeps {
  readonly service: SslService
  readonly store: CertStore
  readonly passphrase: PassphraseSource
  readonly config: SignalkSslConfig
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
export const registerAdminRoutes = (router: IRouter, deps: ApiDeps): void => {
  router.get(
    '/status',
    asyncRoute(async (_req, res) => {
      const s: ServiceStatus = await deps.service.status()
      sendJson(res, 200, s)
    })
  )

  router.get('/api/local-ips', (_req, res) => {
    sendJson(res, 200, { ipAddresses: discoverLocalIps() })
  })

  router.post(
    '/renew',
    asyncRoute(async (_req, res) => {
      const out = await deps.service.issueIfNeeded()
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
