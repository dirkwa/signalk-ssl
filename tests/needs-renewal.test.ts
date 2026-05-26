import { describe, it, expect } from 'vitest'
import { generateCa, signLeaf } from '../src/plugin/crypto.js'
import { parseSans } from '../src/plugin/sans.js'
import { needsRenewal } from '../src/plugin/needs-renewal.js'

const buildLeaf = async (validityDays: number, sans: readonly string[]) => {
  const ca = await generateCa({ commonName: 'r', organization: 'o', validityDays: 3650 })
  return signLeaf({
    issuer: { certificatePem: ca.certificatePem, privateKey: ca.privateKey },
    subjectCommonName: 'r',
    organization: 'o',
    sans: parseSans(sans),
    validityDays,
    clockSkewHours: 24
  })
}

describe('needsRenewal', () => {
  it('returns ok when cert is fresh and SANs match', async () => {
    const leaf = await buildLeaf(397, ['a.local', '10.0.0.1'])
    const decision = needsRenewal(leaf.certificatePem, parseSans(['a.local', '10.0.0.1']), 30)
    expect(decision.needsRenewal).toBe(false)
    expect(decision.reason).toBe('ok')
  })

  it('returns expiring-soon within the threshold window', async () => {
    const leaf = await buildLeaf(20, ['a.local'])
    const decision = needsRenewal(leaf.certificatePem, parseSans(['a.local']), 30)
    expect(decision.needsRenewal).toBe(true)
    expect(decision.reason).toBe('expiring-soon')
  })

  it('returns expired when notAfter is in the past', async () => {
    const leaf = await buildLeaf(30, ['a.local'])
    // Use a `now` 60d into the future — past the 30d validity.
    const future = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000)
    const decision = needsRenewal(leaf.certificatePem, parseSans(['a.local']), 30, future)
    expect(decision.needsRenewal).toBe(true)
    expect(decision.reason).toBe('expired')
  })

  it('returns san-mismatch when a required SAN is missing', async () => {
    const leaf = await buildLeaf(397, ['a.local'])
    const decision = needsRenewal(
      leaf.certificatePem,
      parseSans(['a.local', 'b.local', '10.0.0.99']),
      30
    )
    expect(decision.needsRenewal).toBe(true)
    expect(decision.reason).toBe('san-mismatch')
    expect(decision.missingDnsNames).toEqual(['b.local'])
    expect(decision.missingIpAddresses).toEqual(['10.0.0.99'])
  })
})
