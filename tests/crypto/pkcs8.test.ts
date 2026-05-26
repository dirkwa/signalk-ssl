import { describe, it, expect } from 'vitest'
import { webcrypto } from 'node:crypto'
import { X509Certificate } from '@peculiar/x509'
import {
  decryptPrivateKeyPkcs8,
  derivePassphraseKey,
  encryptPrivateKeyPkcs8,
  generateCa
} from '../../src/plugin/crypto.js'

describe('encryptPrivateKeyPkcs8 / decryptPrivateKeyPkcs8', () => {
  it('round-trips a CA private key with the correct passphrase', async () => {
    const ca = await generateCa({ commonName: 't', organization: 't', validityDays: 1 })

    const pem = await encryptPrivateKeyPkcs8(ca.privateKey, 'correct horse battery staple')
    expect(pem).toContain('-----BEGIN ENCRYPTED PRIVATE KEY-----')
    expect(pem).toContain('-----END ENCRYPTED PRIVATE KEY-----')

    const restored = await decryptPrivateKeyPkcs8(pem, 'correct horse battery staple')

    // Sign the same payload with both keys and assert they verify against the
    // same public key (proves the restored key is the same secret).
    const data = new TextEncoder().encode('hello')
    const algo = { name: 'ECDSA', hash: 'SHA-256' } as const
    const sig1 = await webcrypto.subtle.sign(algo, ca.privateKey, data)
    const sig2 = await webcrypto.subtle.sign(algo, restored, data)

    const caCert = new X509Certificate(ca.certificatePem)
    const pubKey = await caCert.publicKey.export({ name: 'ECDSA', namedCurve: 'P-256' }, ['verify'])
    expect(await webcrypto.subtle.verify(algo, pubKey, sig1, data)).toBe(true)
    expect(await webcrypto.subtle.verify(algo, pubKey, sig2, data)).toBe(true)
  })

  it('throws when decrypted with a wrong passphrase', async () => {
    const ca = await generateCa({ commonName: 't', organization: 't', validityDays: 1 })
    const pem = await encryptPrivateKeyPkcs8(ca.privateKey, 'right')
    await expect(decryptPrivateKeyPkcs8(pem, 'wrong')).rejects.toThrow()
  })
})

describe('derivePassphraseKey', () => {
  it('derives a stable AES-GCM key for the same passphrase + salt', async () => {
    const salt = new TextEncoder().encode('static-salt-bytes')
    const k1 = await derivePassphraseKey('p', salt, 10_000)
    const k2 = await derivePassphraseKey('p', salt, 10_000)
    // CryptoKey objects aren't comparable directly; use them to encrypt + decrypt.
    const iv = new Uint8Array(12)
    const ct = await webcrypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      k1,
      new Uint8Array([1, 2, 3])
    )
    const pt = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, k2, ct)
    expect(new Uint8Array(pt)).toEqual(new Uint8Array([1, 2, 3]))
  })

  it('produces different keys for different passphrases', async () => {
    const salt = new TextEncoder().encode('s')
    const k1 = await derivePassphraseKey('a', salt, 10_000)
    const k2 = await derivePassphraseKey('b', salt, 10_000)
    const iv = new Uint8Array(12)
    const ct = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, k1, new Uint8Array([42]))
    await expect(webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, k2, ct)).rejects.toThrow()
  })
})
