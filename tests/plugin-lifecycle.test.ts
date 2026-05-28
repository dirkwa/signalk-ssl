import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { ServerAPI } from '@signalk/server-api'
import pluginConstructor from '../src/plugin/index.js'

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

  it('seeds empty dnsNames with the discovered hostname on first run', async () => {
    const app = makeMockAppWithHostname('pi5radar')
    const plugin = pluginConstructor(app)
    const restart = vi.fn()
    plugin.start({}, restart)

    const called = await waitFor(() => restart.mock.calls.length > 0)
    expect(called).toBe(true)
    const newConfig = restart.mock.calls[0]?.[0] as { sans: { dnsNames: string[] } }
    expect(newConfig.sans.dnsNames).toEqual(['pi5radar.local'])
    await plugin.stop()
  })

  it('does not re-seed after the marker is written (user may have deleted it)', async () => {
    // First run seeds and restarts.
    const app1 = makeMockAppWithHostname('pi5radar')
    const plugin1 = pluginConstructor(app1)
    const restart1 = vi.fn()
    plugin1.start({}, restart1)
    expect(await waitFor(() => restart1.mock.calls.length > 0)).toBe(true)
    await plugin1.stop()

    // Second run: marker exists. Even with still-empty SANs (simulating a user
    // who deleted the seeded name), the plugin must not seed again.
    const app2 = makeMockAppWithHostname('pi5radar')
    const plugin2 = pluginConstructor(app2)
    const restart2 = vi.fn()
    plugin2.start({}, restart2)

    const debugSpy = app2.debug as unknown as ReturnType<typeof vi.fn>
    // Wait for the issue flow to run (proves start() got past the seed check).
    await waitFor(() =>
      debugSpy.mock.calls.some(
        (args: unknown[]) => typeof args[0] === 'string' && args[0].includes('issueIfNeeded')
      )
    )
    expect(restart2).not.toHaveBeenCalled()
    await plugin2.stop()
  })

  it('does not seed when the user already configured SANs', async () => {
    const app = makeMockAppWithHostname('pi5radar')
    const plugin = pluginConstructor(app)
    const restart = vi.fn()
    plugin.start({ sans: { dnsNames: ['boat.local'], ipAddresses: [] } }, restart)

    const debugSpy = app.debug as unknown as ReturnType<typeof vi.fn>
    await waitFor(() =>
      debugSpy.mock.calls.some(
        (args: unknown[]) => typeof args[0] === 'string' && args[0].includes('issueIfNeeded')
      )
    )
    expect(restart).not.toHaveBeenCalled()
    await plugin.stop()
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
