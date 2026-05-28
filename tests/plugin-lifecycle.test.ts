import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { ServerAPI } from '@signalk/server-api'
import pluginConstructor, { formatStatusMessage } from '../src/plugin/index.js'
import type { ServiceStatus } from '../src/plugin/service.js'

let dataDir: string

const makeMockApp = (overrides: Record<string, unknown> = {}): ServerAPI => {
  const base = {
    debug: vi.fn(),
    error: vi.fn(),
    getDataDirPath: () => dataDir
  }
  return { ...base, ...overrides } as unknown as ServerAPI
}

const makeMockAppWithHostname = (hostname: string): ServerAPI =>
  makeMockApp({ config: { getExternalHostname: () => hostname } })

beforeEach(async () => {
  dataDir = await mkdtemp(join(tmpdir(), 'signalk-ssl-life-'))
})

afterEach(async () => {
  await rm(dataDir, { recursive: true, force: true })
})

describe('signalk-ssl plugin lifecycle', () => {
  it('exposes the expected plugin metadata', () => {
    const plugin = pluginConstructor(makeMockApp())
    expect(plugin.id).toBe('signalk-ssl')
    expect(plugin.name).toBe('SignalK SSL')
    expect(typeof plugin.description).toBe('string')
    expect(typeof plugin.start).toBe('function')
    expect(typeof plugin.stop).toBe('function')
    expect(typeof plugin.schema).toBe('function')
    expect(typeof plugin.registerWithRouter).toBe('function')
    expect(typeof plugin.signalKApiRoutes).toBe('function')
  })

  it('start() with empty SAN config reports the error outcome via debug log', async () => {
    const app = makeMockApp()
    const plugin = pluginConstructor(app)
    expect(() => {
      plugin.start({}, () => undefined)
    }).not.toThrow()

    const debugSpy = app.debug as unknown as ReturnType<typeof vi.fn>
    // The empty-SAN path returns { kind: 'error', ... } from issueIfNeeded,
    // which index.ts logs via app.debug with the JSON-stringified outcome.
    // Poll for the call instead of sleeping a fixed window: cheap on a hot
    // CI runner, robust on a slow one.
    const seen = await waitFor(
      () =>
        debugSpy.mock.calls.find((args: unknown[]) => {
          const msg = args[0]
          return typeof msg === 'string' && msg.includes('"kind":"error"')
        }) !== undefined
    )
    expect(seen).toBe(true)
    await plugin.stop()
  })

  it('schema() injects the discovered hostname as the dnsNames default', () => {
    const plugin = pluginConstructor(makeMockAppWithHostname('pi5radar'))
    const schema = plugin.schema as () => {
      properties: { sans: { properties: { dnsNames: { default: string[] } } } }
    }
    expect(schema().properties.sans.properties.dnsNames.default).toEqual(['pi5radar.local'])
  })

  it('schema() falls back to an empty dnsNames default when no hostname is available', () => {
    // makeMockApp has no config.getExternalHostname, so rawHostname() is ''.
    const plugin = pluginConstructor(makeMockApp())
    const schema = plugin.schema as () => {
      properties: { sans: { properties: { dnsNames: { default: string[] } } } }
    }
    expect(schema().properties.sans.properties.dnsNames.default).toEqual([])
  })

  it('schema() does not inject a default for an undiscoverable hostname', () => {
    // A bare container-ID hostname yields no useful suggestion.
    const plugin = pluginConstructor(makeMockAppWithHostname('f65aaa23e9ff'))
    const schema = plugin.schema as () => {
      properties: { sans: { properties: { dnsNames: { default: string[] } } } }
    }
    expect(schema().properties.sans.properties.dnsNames.default).toEqual([])
  })

  it('logs via app.error when store.init() fails instead of rejecting unhandled', async () => {
    // Point the data dir at a child of a regular file so mkdir() fails with
    // ENOTDIR — store.init() rejects, exercising the terminal .catch.
    const filePath = join(dataDir, 'not-a-dir')
    await writeFile(filePath, 'x')
    const app = makeMockApp({ getDataDirPath: () => join(filePath, 'child') })

    const unhandled = vi.fn()
    process.on('unhandledRejection', unhandled)
    try {
      const plugin = pluginConstructor(app)
      plugin.start({}, () => undefined)

      const errorSpy = app.error as unknown as ReturnType<typeof vi.fn>
      const logged = await waitFor(() =>
        errorSpy.mock.calls.some(
          (args: unknown[]) => typeof args[0] === 'string' && args[0].includes('startup failed')
        )
      )
      expect(logged).toBe(true)
      // Let any stray microtasks flush, then assert nothing went unhandled.
      await new Promise<void>((resolve) => setTimeout(resolve, 20))
      expect(unhandled).not.toHaveBeenCalled()
      await plugin.stop()
    } finally {
      process.off('unhandledRejection', unhandled)
    }
  })
})

describe('formatStatusMessage', () => {
  const base: ServiceStatus = {
    hasCa: true,
    caFingerprint: 'AA:BB',
    caCreatedAt: '2026-01-01T00:00:00.000Z',
    hasLeaf: true,
    leafExpiresAt: '2027-01-01T00:00:00.000Z',
    leafDaysRemaining: 397,
    leafSansDns: ['pi5radar.local'],
    leafSansIp: [],
    restartRequired: false,
    permissionWarning: null
  }

  it('reports "starting" before the first status snapshot', () => {
    expect(formatStatusMessage(null)).toBe('starting')
  })

  it('reports the cert name and days remaining when issued', () => {
    expect(formatStatusMessage(base)).toBe('pi5radar.local · 397d left')
  })

  it('flags a pending restart', () => {
    expect(formatStatusMessage({ ...base, restartRequired: true })).toBe(
      'pi5radar.local · 397d left · restart to apply'
    )
  })

  it('falls back to an IP SAN when there is no DNS SAN', () => {
    expect(formatStatusMessage({ ...base, leafSansDns: [], leafSansIp: ['10.0.0.5'] })).toBe(
      '10.0.0.5 · 397d left'
    )
  })

  it('surfaces a permission warning as an error', () => {
    expect(formatStatusMessage({ ...base, permissionWarning: 'cannot write certs' })).toBe(
      'error: cannot write certs'
    )
  })

  it('reports no CA before anything is generated', () => {
    expect(formatStatusMessage({ ...base, hasCa: false, hasLeaf: false })).toBe(
      'no CA yet — enable and save config'
    )
  })

  it('reports CA-but-no-leaf', () => {
    expect(formatStatusMessage({ ...base, hasLeaf: false, leafDaysRemaining: null })).toBe(
      'CA ready, no certificate issued yet'
    )
  })
})

const waitFor = async (
  predicate: () => boolean,
  timeoutMs = 5_000,
  intervalMs = 10
): Promise<boolean> => {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) {
      return true
    }
    await new Promise<void>((resolve) => {
      setTimeout(resolve, intervalMs)
    })
  }
  return predicate()
}
