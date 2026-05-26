import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtemp, readdir, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { CertStore } from '../src/plugin/storage.js'
import {
  encryptPrivateKeyPkcs8,
  decryptPrivateKeyPkcs8,
  generateCa,
  computeSpkiFingerprint
} from '../src/plugin/crypto.js'

let dir: string
let store: CertStore

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'signalk-ssl-store-'))
  store = new CertStore(dir)
})

afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
})

describe('CertStore round-trip', () => {
  it('persists and reads a CA state with permissions 0600 on the key', async () => {
    const ca = await generateCa({ commonName: 't', organization: 't', validityDays: 1 })
    const fingerprint = await computeSpkiFingerprint(ca.certificatePem, 'sha256')
    const encryptedKey = await encryptPrivateKeyPkcs8(ca.privateKey, 'pp')

    await store.writeCaState({
      certificatePem: ca.certificatePem,
      encryptedKeyPem: encryptedKey,
      fingerprintSha256: fingerprint,
      createdAt: new Date('2026-05-26').toISOString(),
      mode: 'generate'
    })

    const round = await store.readCaState()
    expect(round).not.toBeNull()
    expect(round?.certificatePem).toBe(ca.certificatePem)
    expect(round?.encryptedKeyPem).toBe(encryptedKey)
    expect(round?.fingerprintSha256).toBe(fingerprint)
    expect(round?.mode).toBe('generate')

    if (process.platform !== 'win32') {
      const st = await stat(join(dir, 'ca.key.enc.pem'))
      expect((st.mode & 0o777) >>> 0).toBe(0o600)
    }

    // And the round-tripped key decrypts back to a usable signing key.
    await expect(decryptPrivateKeyPkcs8(round?.encryptedKeyPem ?? '', 'pp')).resolves.toBeDefined()
  })

  it('returns null for missing files', async () => {
    expect(await store.readCaState()).toBeNull()
    expect(await store.readLeafState()).toBeNull()
    expect(await store.readSettings()).toBeNull()
    expect(await store.readConvenienceEnvelope()).toBeNull()
  })

  it('settings round-trip preserves schemaVersion = 1', async () => {
    await store.writeSettings({
      schemaVersion: 1,
      passphraseMode: 'convenience',
      lastRenewedAt: null
    })
    const back = await store.readSettings()
    expect(back?.schemaVersion).toBe(1)
    expect(back?.passphraseMode).toBe('convenience')
  })

  it('write does not leave a .tmp file behind', async () => {
    await store.writeSettings({
      schemaVersion: 1,
      passphraseMode: 'env',
      lastRenewedAt: null
    })
    // Atomic write-then-rename: no settings.json.*.tmp should remain in the dir.
    const entries = await readdir(dir)
    const tmpLeftovers = entries.filter((f) => f.includes('.tmp'))
    expect(tmpLeftovers).toEqual([])
    const raw = await readFile(join(dir, 'settings.json'), 'utf8')
    expect(raw).toContain('"passphraseMode"')
  })
})
