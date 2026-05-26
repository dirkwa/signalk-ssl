import { describe, it, expect } from 'vitest'
import { parseSans, sanitizeHostname } from '../src/plugin/sans.js'

describe('sanitizeHostname', () => {
  it('replaces smart quotes and em-dashes with ASCII', () => {
    expect(sanitizeHostname('Boat’s—Server')).toBe("Boat's-Server")
    expect(sanitizeHostname('left‘right’')).toBe("left'right'")
    expect(sanitizeHostname('hello“world”')).toBe('hello"world"')
  })

  it('strips remaining non-ASCII', () => {
    expect(sanitizeHostname('boatätest')).toBe('boattest')
  })
})

describe('parseSans', () => {
  it('classifies DNS names and IPs separately, deduplicates, ignores empties', () => {
    const out = parseSans([
      'boat.local',
      'BOAT.LOCAL',
      'localhost',
      '192.168.1.10',
      '192.168.1.10',
      '   ',
      ''
    ])
    expect(out.dnsNames).toEqual(['boat.local', 'localhost'])
    expect(out.ipAddresses).toEqual(['192.168.1.10'])
  })

  it('normalises IPv6 lowercase + strip leading zeros', () => {
    const out = parseSans(['2001:0DB8:0000:0000:0000:0000:0000:0001'])
    expect(out.ipAddresses[0]).toBe('2001:db8:0:0:0:0:0:1')
  })

  it('rejects invalid DNS names', () => {
    expect(() => parseSans(['not_a_valid_dns'])).toThrow()
    expect(() => parseSans(['has spaces.local'])).toThrow()
    expect(() => parseSans(['-leadingdash.local'])).toThrow()
  })

  it('accepts hyphenated multi-label DNS', () => {
    const out = parseSans(['my-boat.signalk.local'])
    expect(out.dnsNames).toEqual(['my-boat.signalk.local'])
  })
})
