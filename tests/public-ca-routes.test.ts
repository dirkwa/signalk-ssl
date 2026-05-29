import { describe, it, expect, vi } from 'vitest'
import type { Request, Response, RequestHandler } from 'express'
import { registerPublicCaRoutes, type ApiDeps } from '../src/plugin/api.js'
import type { CertStore } from '../src/plugin/storage.js'

// Minimal fake mounter: records path -> handler so we can invoke them directly.
const makeMounter = () => {
  const routes = new Map<string, RequestHandler>()
  return {
    routes,
    get: (path: string, handler: RequestHandler): void => {
      routes.set(path, handler)
    }
  }
}

const makeRes = () => {
  const res: Partial<Response> & { _status: number; _body: unknown; _type: string } = {
    _status: 200,
    _body: undefined,
    _type: ''
  }
  res.status = vi.fn((c: number) => {
    res._status = c
    return res as Response
  })
  res.type = vi.fn((t: string) => {
    res._type = t
    return res as Response
  })
  res.send = vi.fn((b: unknown) => {
    res._body = b
    return res as Response
  })
  return res as Response & { _status: number; _body: unknown; _type: string }
}

const depsWithCa = (caPem: string | null): ApiDeps =>
  ({
    store: {
      readCaState: () => Promise.resolve(caPem === null ? null : { certificatePem: caPem })
    } as unknown as CertStore,
    config: { commonName: 'SignalK Local CA', organization: 'SignalK' }
  }) as unknown as ApiDeps

const invoke = async (handler: RequestHandler, res: Response): Promise<void> => {
  await new Promise<void>((resolve, reject) => {
    let settled = false
    const done = (err?: unknown): void => {
      if (settled) return
      settled = true
      if (err !== undefined) {
        reject(err instanceof Error ? err : new Error(JSON.stringify(err)))
      } else {
        resolve()
      }
    }
    // asyncRoute calls next(err) on a thrown/rejected handler — surface it as a
    // test failure instead of resolving silently.
    handler({} as Request, res, (err?: unknown) => {
      done(err)
    })
    // Handlers are async via asyncRoute; give the microtask queue a tick for
    // handlers that complete by writing the response without calling next().
    setTimeout(() => {
      done()
    }, 10)
  })
}

const routeOf = (m: ReturnType<typeof makeMounter>, path: string): RequestHandler => {
  const h = m.routes.get(path)
  if (h === undefined) {
    throw new Error(`route not registered: ${path}`)
  }
  return h
}

describe('registerPublicCaRoutes', () => {
  it('mounts the CA download at the public /signalk-ssl/ prefix', () => {
    const m = makeMounter()
    registerPublicCaRoutes(m, () => depsWithCa('PEM'))
    expect([...m.routes.keys()].sort()).toEqual([
      '/signalk-ssl/ca.crt',
      '/signalk-ssl/ca.mobileconfig'
    ])
  })

  it('serves the CA cert with the x509 MIME type', async () => {
    const m = makeMounter()
    registerPublicCaRoutes(m, () => depsWithCa('CERT-PEM'))
    const res = makeRes()
    await invoke(routeOf(m, '/signalk-ssl/ca.crt'), res)
    expect(res._type).toBe('application/x-x509-ca-cert')
    expect(res._body).toBe('CERT-PEM')
  })

  it('serves a .mobileconfig with the Apple MIME type', async () => {
    const m = makeMounter()
    registerPublicCaRoutes(m, () => depsWithCa('CERT-PEM'))
    const res = makeRes()
    await invoke(routeOf(m, '/signalk-ssl/ca.mobileconfig'), res)
    expect(res._type).toBe('application/x-apple-aspen-config')
    expect(typeof res._body).toBe('string')
    expect(res._body as string).toContain('PayloadType')
  })

  it('404s when no CA exists yet', async () => {
    const m = makeMounter()
    registerPublicCaRoutes(m, () => depsWithCa(null))
    const res = makeRes()
    await invoke(routeOf(m, '/signalk-ssl/ca.crt'), res)
    expect(res._status).toBe(404)
  })

  it('reads deps fresh per request, so a config swap is reflected without remount', async () => {
    // Simulate the once-per-process mount whose deps change on plugin restart:
    // the accessor returns whatever `current` points at now.
    let current = depsWithCa(null)
    const m = makeMounter()
    registerPublicCaRoutes(m, () => current)

    const before = makeRes()
    await invoke(routeOf(m, '/signalk-ssl/ca.crt'), before)
    expect(before._status).toBe(404)

    // A later start() would assign a new deps object with a CA present.
    current = depsWithCa('CERT-PEM')
    const after = makeRes()
    await invoke(routeOf(m, '/signalk-ssl/ca.crt'), after)
    expect(after._type).toBe('application/x-x509-ca-cert')
    expect(after._body).toBe('CERT-PEM')
  })
})
