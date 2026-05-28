import { describe, it, expect } from 'vitest'
import { discoverAdvertisedHostname } from '../src/plugin/service.js'

describe('discoverAdvertisedHostname', () => {
  it('appends .local to a bare hostname', () => {
    expect(discoverAdvertisedHostname('pi5radar')).toBe('pi5radar.local')
  })

  it('strips an existing .local suffix before re-appending', () => {
    expect(discoverAdvertisedHostname('pi5radar.local')).toBe('pi5radar.local')
  })

  it('strips a .local suffix case-insensitively', () => {
    expect(discoverAdvertisedHostname('Pi5Radar.LOCAL')).toBe('Pi5Radar.local')
  })

  it('strips a trailing FQDN dot', () => {
    expect(discoverAdvertisedHostname('pi5radar.')).toBe('pi5radar.local')
  })

  it('returns null for a 12-hex-digit container ID', () => {
    expect(discoverAdvertisedHostname('f65aaa23e9ff')).toBeNull()
  })

  it('does not treat a 12-char non-hex hostname as a container ID', () => {
    expect(discoverAdvertisedHostname('signalk-boat')).toBe('signalk-boat.local')
  })

  it('returns null for localhost', () => {
    expect(discoverAdvertisedHostname('localhost')).toBeNull()
  })

  it("returns null for signalk-server's hostname-unavailable sentinel", () => {
    expect(discoverAdvertisedHostname('hostname_not_available')).toBeNull()
  })

  it('returns null for an empty string', () => {
    expect(discoverAdvertisedHostname('')).toBeNull()
  })

  it('returns null for a whitespace-only string', () => {
    expect(discoverAdvertisedHostname('   ')).toBeNull()
  })

  it('returns an FQDN unchanged (reverse-proxy case)', () => {
    expect(discoverAdvertisedHostname('signalk.example.com')).toBe('signalk.example.com')
  })
})
