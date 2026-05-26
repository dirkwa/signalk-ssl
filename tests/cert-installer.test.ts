import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { defaultTargets, installCerts } from '../src/plugin/cert-installer.js'

let dir: string

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'signalk-ssl-installer-'))
})

afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
})

describe('installCerts', () => {
  it('writes ssl-cert.pem, ssl-key.pem, ssl-chain.pem with strict key perms', async () => {
    const targets = defaultTargets(dir)
    const cert = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'
    const key = '-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----'
    const ca = '-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----'

    await installCerts(targets, cert, key, ca)

    const certBody = await readFile(targets.certPath, 'utf8')
    const keyBody = await readFile(targets.keyPath, 'utf8')
    const chainBody = await readFile(targets.chainPath, 'utf8')

    expect(certBody).toBe(cert)
    expect(keyBody).toBe(key)
    expect(chainBody).toBe(`${cert.trimEnd()}\n${ca.trimEnd()}\n`)

    if (process.platform !== 'win32') {
      const keyStat = await stat(targets.keyPath)
      expect((keyStat.mode & 0o777) >>> 0).toBe(0o600)
      const certStat = await stat(targets.certPath)
      expect((certStat.mode & 0o777) >>> 0).toBe(0o644)
    }
  })

  it('overwrites existing files in place', async () => {
    const targets = defaultTargets(dir)
    await installCerts(targets, 'cert1', 'key1', 'ca1')
    await installCerts(targets, 'cert2', 'key2', 'ca2')
    expect(await readFile(targets.certPath, 'utf8')).toBe('cert2')
    expect(await readFile(targets.keyPath, 'utf8')).toBe('key2')
  })
})
