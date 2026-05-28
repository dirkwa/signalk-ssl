import { describe, it, expect } from 'vitest'
import { buildConfigSchema, ConfigSchema } from '../src/plugin/schema.js'

interface SansDefaults {
  properties: {
    sans: {
      properties: {
        dnsNames: { default: string[] }
        ipAddresses: { default: string[] }
      }
    }
  }
}

const sans = (schema: unknown): SansDefaults['properties']['sans']['properties'] =>
  (schema as SansDefaults).properties.sans.properties

describe('buildConfigSchema', () => {
  it('returns the static schema when nothing is discovered', () => {
    expect(buildConfigSchema({ dnsName: null, ipAddresses: [] })).toBe(ConfigSchema)
  })

  it('injects the hostname as the dnsNames default', () => {
    const s = sans(buildConfigSchema({ dnsName: 'pi5radar.local', ipAddresses: [] }))
    expect(s.dnsNames.default).toEqual(['pi5radar.local'])
    expect(s.ipAddresses.default).toEqual([])
  })

  it('injects discovered IPs as the ipAddresses default', () => {
    const s = sans(
      buildConfigSchema({ dnsName: null, ipAddresses: ['192.168.0.148', '10.211.0.2'] })
    )
    expect(s.dnsNames.default).toEqual([])
    expect(s.ipAddresses.default).toEqual(['192.168.0.148', '10.211.0.2'])
  })

  it('injects both hostname and IPs together', () => {
    const s = sans(buildConfigSchema({ dnsName: 'pi5radar.local', ipAddresses: ['192.168.0.148'] }))
    expect(s.dnsNames.default).toEqual(['pi5radar.local'])
    expect(s.ipAddresses.default).toEqual(['192.168.0.148'])
  })

  it('seeds IPs even when no hostname is available', () => {
    const s = sans(buildConfigSchema({ dnsName: null, ipAddresses: ['192.168.0.148'] }))
    expect(s.ipAddresses.default).toEqual(['192.168.0.148'])
  })

  it('does not mutate the shared static ConfigSchema', () => {
    buildConfigSchema({ dnsName: 'pi5radar.local', ipAddresses: ['192.168.0.148'] })
    const staticSans = sans(ConfigSchema)
    expect(staticSans.dnsNames.default).toEqual([])
    expect(staticSans.ipAddresses.default).toEqual([])
  })
})
