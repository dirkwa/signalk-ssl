import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { ServerAPI } from '@signalk/server-api'
import pluginConstructor from '../src/plugin/index.js'

let dataDir: string

const makeMockApp = (overrides: Partial<ServerAPI> = {}): ServerAPI => {
  const base = {
    debug: vi.fn(),
    error: vi.fn(),
    getDataDirPath: () => dataDir
  }
  return { ...base, ...overrides } as unknown as ServerAPI
}

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
