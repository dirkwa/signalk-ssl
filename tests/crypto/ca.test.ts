import { describe, it, expect } from 'vitest'
import {
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectKeyIdentifierExtension,
  X509Certificate
} from '@peculiar/x509'
import { computeSpkiFingerprint, generateCa } from '../../src/plugin/crypto.js'

describe('generateCa', () => {
  it('produces a self-signed CA with cA:true and keyCertSign+cRLSign', async () => {
    const { certificatePem } = await generateCa({
      commonName: 'Test Boat CA',
      organization: 'Tests',
      validityDays: 365
    })

    const cert = new X509Certificate(certificatePem)
    expect(cert.subject).toBe(cert.issuer)
    expect(cert.subject).toContain('CN=Test Boat CA')

    const bc = cert.getExtension(BasicConstraintsExtension)
    expect(bc).toBeDefined()
    expect(bc?.ca).toBe(true)
    expect(bc?.critical).toBe(true)

    const ku = cert.getExtension(KeyUsagesExtension)
    expect(ku).toBeDefined()
    const expected = KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign
    // Bitwise-AND to assert at least the flags we asked for are present.
    expect(((ku?.usages ?? 0) & expected) >>> 0).toBe(expected >>> 0)

    const ski = cert.getExtension(SubjectKeyIdentifierExtension)
    expect(ski).toBeDefined()
    // Self-signed: no AKI extension expected (we deliberately don't add one).
    expect(cert.getExtension(AuthorityKeyIdentifierExtension)).toBeNull()
  })

  it('honours the validityDays parameter (10y default-ish)', async () => {
    const before = Date.now()
    const { certificatePem } = await generateCa({
      commonName: 'Validity Test',
      organization: 'Tests',
      validityDays: 3650
    })
    const cert = new X509Certificate(certificatePem)
    const ms = cert.notAfter.getTime() - cert.notBefore.getTime()
    const days = ms / (24 * 60 * 60 * 1000)
    expect(days).toBeGreaterThan(3649.9)
    expect(days).toBeLessThan(3650.1)
    expect(cert.notBefore.getTime()).toBeGreaterThanOrEqual(before - 1000)
  })

  it('generates a unique serial number across runs', async () => {
    const a = await generateCa({ commonName: 'a', organization: 'o', validityDays: 1 })
    const b = await generateCa({ commonName: 'b', organization: 'o', validityDays: 1 })
    const certA = new X509Certificate(a.certificatePem)
    const certB = new X509Certificate(b.certificatePem)
    expect(certA.serialNumber).not.toBe(certB.serialNumber)
    // Hex, no leading 0x80+ byte (positive integer).
    expect(/^[0-9a-f]+$/i.test(certA.serialNumber)).toBe(true)
    expect(parseInt(certA.serialNumber.slice(0, 2), 16)).toBeLessThan(0x80)
  })

  it('computeSpkiFingerprint is stable for the same key', async () => {
    const ca = await generateCa({ commonName: 'fp', organization: 'o', validityDays: 1 })
    const fp1 = await computeSpkiFingerprint(ca.certificatePem, 'sha256')
    const fp2 = await computeSpkiFingerprint(ca.certificatePem, 'sha256')
    expect(fp1).toBe(fp2)
    // SHA-256 = 32 bytes = 32 hex pairs = 31 colons
    expect(fp1.split(':')).toHaveLength(32)
    expect(/^[0-9A-F:]+$/.test(fp1)).toBe(true)
  })
})
