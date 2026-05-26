import { describe, it, expect, beforeAll } from 'vitest'
import {
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  X509Certificate
} from '@peculiar/x509'
import { generateCa, signLeaf, verifyChain } from '../../src/plugin/crypto.js'
import { parseSans } from '../../src/plugin/sans.js'

let sharedCa: Awaited<ReturnType<typeof generateCa>>

beforeAll(async () => {
  sharedCa = await generateCa({
    commonName: 'Leaf Test CA',
    organization: 'Tests',
    validityDays: 3650
  })
})

describe('signLeaf', () => {
  it('produces a leaf signed by the CA, valid 397d, with correct extensions', async () => {
    const ca = sharedCa
    const sans = parseSans(['boat.local', 'localhost', '192.168.1.10'])

    const before = Date.now()
    const { certificatePem } = await signLeaf({
      issuer: { certificatePem: ca.certificatePem, privateKey: ca.privateKey },
      subjectCommonName: 'boat.local',
      organization: 'Tests',
      sans,
      validityDays: 397,
      clockSkewHours: 24
    })

    const leaf = new X509Certificate(certificatePem)
    expect(leaf.subject).toContain('CN=boat.local')
    expect(leaf.issuer).toBe(new X509Certificate(ca.certificatePem).subject)

    const bc = leaf.getExtension(BasicConstraintsExtension)
    expect(bc?.ca).toBe(false)

    const ku = leaf.getExtension(KeyUsagesExtension)
    expect(ku).toBeDefined()
    const expected = KeyUsageFlags.digitalSignature | KeyUsageFlags.keyEncipherment
    expect(((ku?.usages ?? 0) & expected) >>> 0).toBe(expected >>> 0)

    const eku = leaf.getExtension(ExtendedKeyUsageExtension)
    expect(eku?.usages).toContain(ExtendedKeyUsage.serverAuth)

    const sanExt = leaf.getExtension(SubjectAlternativeNameExtension)
    expect(sanExt).toBeDefined()
    const names = sanExt?.names.toJSON() ?? []
    const dns = names.filter((n) => n.type === 'dns').map((n) => n.value)
    const ips = names.filter((n) => n.type === 'ip').map((n) => n.value)
    expect(dns).toEqual(expect.arrayContaining(['boat.local', 'localhost']))
    expect(ips).toContain('192.168.1.10')

    const aki = leaf.getExtension(AuthorityKeyIdentifierExtension)
    expect(aki).toBeDefined()

    const validityDays =
      (leaf.notAfter.getTime() - leaf.notBefore.getTime()) / (24 * 60 * 60 * 1000)
    // 397d + 24h clock skew = 398d total span
    expect(validityDays).toBeGreaterThan(397.9)
    expect(validityDays).toBeLessThan(398.1)

    // notBefore is backdated 24h
    const skewMs = before - leaf.notBefore.getTime()
    expect(skewMs).toBeGreaterThan(24 * 60 * 60 * 1000 - 5_000)
    expect(skewMs).toBeLessThan(24 * 60 * 60 * 1000 + 5_000)
  })

  it('verifies the leaf chains to the CA public key', async () => {
    const ca = sharedCa
    const sans = parseSans(['signalk.local'])
    const leaf = await signLeaf({
      issuer: { certificatePem: ca.certificatePem, privateKey: ca.privateKey },
      subjectCommonName: 'signalk.local',
      organization: 'Tests',
      sans,
      validityDays: 397,
      clockSkewHours: 24
    })

    const ok = await verifyChain(leaf.certificatePem, ca.certificatePem)
    expect(ok).toBe(true)
  })

  it('rejects verification against a different CA', async () => {
    // This test specifically needs two distinct CAs, so we don't reuse sharedCa.
    const ca1 = sharedCa
    const ca2 = await generateCa({
      commonName: 'Different CA',
      organization: 'Tests',
      validityDays: 3650
    })
    const leaf = await signLeaf({
      issuer: { certificatePem: ca1.certificatePem, privateKey: ca1.privateKey },
      subjectCommonName: 'a.local',
      organization: 'T',
      sans: parseSans(['a.local']),
      validityDays: 30,
      clockSkewHours: 24
    })
    const ok = await verifyChain(leaf.certificatePem, ca2.certificatePem)
    expect(ok).toBe(false)
  })
})
