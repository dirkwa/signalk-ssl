import { describe, it, expect, afterEach } from 'vitest'
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { CertStore } from '../src/plugin/storage.js'
import { PassphraseSource } from '../src/plugin/passphrase-source.js'
import { SslService } from '../src/plugin/service.js'
import { DEFAULT_CONFIG, type SignalkSslConfig } from '../src/plugin/schema.js'

let dataDir: string
let configPath: string

const buildService = async (overrides: Partial<SignalkSslConfig> = {}) => {
  dataDir = await mkdtemp(join(tmpdir(), 'signalk-ssl-svc-'))
  configPath = await mkdtemp(join(tmpdir(), 'signalk-ssl-cfg-'))
  const store = new CertStore(dataDir)
  await store.init()
  const config: SignalkSslConfig = {
    ...DEFAULT_CONFIG,
    sans: { dnsNames: ['boat.local'], ipAddresses: [] },
    ...overrides
  }
  // Force env mode so we don't pay the convenience-mode SHA loop in tests.
  const passEnv = new PassphraseSource('env', store, {
    env: { SIGNALK_SSL_PASSPHRASE: 'test-pp' }
  })
  const svc = new SslService({ store, passphrase: passEnv, config, configPath })
  return { svc, store, configPath, dataDir, config }
}

afterEach(async () => {
  if (dataDir) {
    await rm(dataDir, { recursive: true, force: true })
  }
  if (configPath) {
    await rm(configPath, { recursive: true, force: true })
  }
})

describe('SslService.issueIfNeeded', () => {
  it('first-run: bootstraps CA, signs leaf, installs files', async () => {
    const { svc, configPath: cp } = await buildService()
    const out = await svc.issueIfNeeded()
    expect(out.kind).toBe('issued')
    if (out.kind === 'issued') {
      expect(out.reason).toBe('first-run')
    }
    const certBody = await readFile(join(cp, 'ssl-cert.pem'), 'utf8')
    expect(certBody).toContain('BEGIN CERTIFICATE')
    if (process.platform !== 'win32') {
      const st = await stat(join(cp, 'ssl-key.pem'))
      expect((st.mode & 0o777) >>> 0).toBe(0o600)
    }
  })

  it('second call is a no-op when nothing changed', async () => {
    const { svc } = await buildService()
    await svc.issueIfNeeded()
    const out = await svc.issueIfNeeded()
    expect(out.kind).toBe('no-op')
  })

  it('regenerates when SANs change', async () => {
    const { svc, store, configPath: cp } = await buildService()
    await svc.issueIfNeeded()

    // Patch config to require a new SAN.
    const svc2 = new SslService({
      store,
      passphrase: new PassphraseSource('env', store, {
        env: { SIGNALK_SSL_PASSPHRASE: 'test-pp' }
      }),
      config: {
        ...DEFAULT_CONFIG,
        sans: { dnsNames: ['boat.local', 'newhost.local'], ipAddresses: [] }
      },
      configPath: cp
    })
    const out = await svc2.issueIfNeeded()
    expect(out.kind).toBe('issued')
    if (out.kind === 'issued') {
      expect(out.reason).toBe('san-mismatch')
    }
  })

  it('errors when no SANs are configured', async () => {
    const { svc } = await buildService({ sans: { dnsNames: [], ipAddresses: [] } })
    const out = await svc.issueIfNeeded()
    expect(out.kind).toBe('error')
  })

  it('locked outcome when env-mode passphrase is missing', async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'signalk-ssl-svc-'))
    configPath = await mkdtemp(join(tmpdir(), 'signalk-ssl-cfg-'))
    const store = new CertStore(dataDir)
    await store.init()
    const svc = new SslService({
      store,
      passphrase: new PassphraseSource('env', store, { env: {} }),
      config: { ...DEFAULT_CONFIG, sans: { dnsNames: ['x.local'], ipAddresses: [] } },
      configPath
    })
    const out = await svc.issueIfNeeded()
    expect(out.kind).toBe('locked')
  })

  it('plugin stop/start: new SslService instance over the same store is a no-op (idempotency regression)', async () => {
    const { svc, store, configPath: cp, config } = await buildService()
    // Bootstrap CA + leaf via the first "plugin start".
    const out1 = await svc.issueIfNeeded()
    expect(out1.kind).toBe('issued')

    const caBefore = await store.readCaState()
    const leafBefore = await store.readLeafState()
    expect(caBefore).not.toBeNull()
    expect(leafBefore).not.toBeNull()

    // Simulate plugin stop -> start by constructing a fresh SslService over
    // the same store + configPath, then calling issueIfNeeded again. The
    // contract says no regeneration should happen, no re-issue, no change to
    // the persisted CA fingerprint or leaf cert PEM.
    const svc2 = new SslService({
      store,
      passphrase: new PassphraseSource('env', store, {
        env: { SIGNALK_SSL_PASSPHRASE: 'test-pp' }
      }),
      config,
      configPath: cp
    })
    const out2 = await svc2.issueIfNeeded()
    expect(out2.kind).toBe('no-op')

    const caAfter = await store.readCaState()
    const leafAfter = await store.readLeafState()
    expect(caAfter?.fingerprintSha256).toBe(caBefore?.fingerprintSha256)
    expect(caAfter?.certificatePem).toBe(caBefore?.certificatePem)
    expect(caAfter?.encryptedKeyPem).toBe(caBefore?.encryptedKeyPem)
    expect(leafAfter?.certificatePem).toBe(leafBefore?.certificatePem)
    expect(leafAfter?.privateKeyPem).toBe(leafBefore?.privateKeyPem)
  })

  it('status reflects no-CA before bootstrap and CA/leaf after', async () => {
    const { svc } = await buildService()
    const s1 = await svc.status()
    expect(s1.hasCa).toBe(false)
    expect(s1.hasLeaf).toBe(false)
    await svc.issueIfNeeded()
    const s2 = await svc.status()
    expect(s2.hasCa).toBe(true)
    expect(s2.hasLeaf).toBe(true)
    expect(s2.leafDaysRemaining).toBeGreaterThan(390)
    expect(s2.restartRequired).toBe(true)
    svc.acknowledgeRestart()
    expect((await svc.status()).restartRequired).toBe(false)
  })
})
