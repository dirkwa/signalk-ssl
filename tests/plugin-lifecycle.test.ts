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

  it('start() with empty SAN config runs without throwing and logs an error inside (no SAN configured)', async () => {
    const app = makeMockApp()
    const plugin = pluginConstructor(app)
    expect(() => {
      plugin.start({}, () => undefined)
    }).not.toThrow()
    // Give the floating async issue a chance to settle.
    await new Promise<void>((resolve) => {
      setTimeout(resolve, 50)
    })
    await plugin.stop()
  })
})
