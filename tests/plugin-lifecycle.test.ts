import { describe, it, expect, vi } from 'vitest'
import type { ServerAPI } from '@signalk/server-api'
import pluginConstructor from '../src/plugin/index.js'

const makeMockApp = (): ServerAPI => {
  const debug = vi.fn()
  const error = vi.fn()
  // The full ServerAPI surface is large and most of it isn't exercised by Phase 1;
  // cast through unknown so the test focuses on what start/stop actually touch.
  return { debug, error } as unknown as ServerAPI
}

describe('signalk-ssl plugin lifecycle (Phase 1)', () => {
  it('exposes the expected plugin metadata', () => {
    const app = makeMockApp()
    const plugin = pluginConstructor(app)

    expect(plugin.id).toBe('signalk-ssl')
    expect(plugin.name).toBe('SignalK SSL')
    expect(typeof plugin.description).toBe('string')
    expect(typeof plugin.start).toBe('function')
    expect(typeof plugin.stop).toBe('function')
    expect(plugin.schema).toEqual({ type: 'object', properties: {} })
  })

  it('start() and stop() run without throwing and call app.debug', () => {
    const app = makeMockApp()
    const debugSpy = app.debug as unknown as ReturnType<typeof vi.fn>

    const plugin = pluginConstructor(app)

    expect(() => {
      plugin.start({}, () => undefined)
    }).not.toThrow()
    expect(debugSpy).toHaveBeenCalledWith(expect.stringContaining('signalk-ssl started'))

    expect(() => plugin.stop()).not.toThrow()
    expect(debugSpy).toHaveBeenCalledWith(expect.stringContaining('signalk-ssl stopped'))
  })
})
