import { describe, it, expect } from 'vitest'
import { buildMobileconfig } from '../src/plugin/mobileconfig.js'

const sampleCert = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQNzfkkpRl1JCFb+ay8pCWVjAKBggqhkjOPQQDAjAjMSEw
HwYDVQQDDBh0ZXN0LWNlcnQtZm9yLW1vYmlsZWNvbmZpZzAeFw0yMDAxMDEwMDAw
MDBaFw0zMDAxMDEwMDAwMDBaMCMxITAfBgNVBAMMGHRlc3QtY2VydC1mb3ItbW9i
aWxlY29uZmlnMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0c/MIN9eApYjT1is
fakefakefakefakefakefakefakefakefakefakefakefakeAAAA=
-----END CERTIFICATE-----`

describe('buildMobileconfig', () => {
  it('embeds the DER-encoded cert (base64 without PEM headers)', () => {
    const xml = buildMobileconfig(sampleCert, { caName: 'Boat CA', organization: 'Acme' })
    expect(xml).toContain('<key>PayloadContent</key>')
    expect(xml).toContain('<string>com.apple.security.root</string>')
    expect(xml).toContain('<string>Boat CA</string>')
    expect(xml).toContain('<string>Acme</string>')
    // Base64 body sandwiched in <data>…</data>
    expect(xml).toMatch(/<data>[A-Za-z0-9+/=]+<\/data>/)
    // No PEM headers leaked into the data block
    expect(xml).not.toContain('BEGIN CERTIFICATE')
  })

  it('escapes XML-special chars in caName and organization', () => {
    const xml = buildMobileconfig(sampleCert, {
      caName: 'Boat & "Sail" <CA>',
      organization: "O'Brien"
    })
    expect(xml).toContain('Boat &amp; &quot;Sail&quot; &lt;CA&gt;')
    expect(xml).toContain('O&apos;Brien')
  })

  it('generates fresh UUIDs each call', () => {
    const a = buildMobileconfig(sampleCert, { caName: 'A', organization: 'O' })
    const b = buildMobileconfig(sampleCert, { caName: 'A', organization: 'O' })
    const aUuids = a.match(/[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/g) ?? []
    const bUuids = b.match(/[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/g) ?? []
    expect(aUuids).toHaveLength(2)
    expect(bUuids).toHaveLength(2)
    expect(new Set([...aUuids, ...bUuids]).size).toBe(4)
  })

  it('includes all five language consent strings', () => {
    const xml = buildMobileconfig(sampleCert, { caName: 'Boat CA', organization: 'O' })
    for (const lang of ['en', 'de', 'fr', 'es', 'nl']) {
      expect(xml).toContain(`<key>${lang}</key>`)
    }
  })
})
