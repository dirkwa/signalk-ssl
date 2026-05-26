import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { CertStore } from '../src/plugin/storage.js'
import { PassphraseSource } from '../src/plugin/passphrase-source.js'

let dir: string
let store: CertStore

const TEST_ITERATIONS = 100

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'signalk-ssl-pp-'))
  store = new CertStore(dir)
  await store.init()
})

afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
})

describe('PassphraseSource', () => {
  it('env mode returns missing-env when the env var is unset', async () => {
    const src = new PassphraseSource('env', store, { env: {} })
    const r = await src.resolve()
    expect(r.kind).toBe('missing-env')
  })

  it('env mode returns ok when the env var is set', async () => {
    const src = new PassphraseSource('env', store, {
      env: { SIGNALK_SSL_PASSPHRASE: 'hunter2' }
    })
    const r = await src.resolve()
    expect(r.kind).toBe('ok')
    if (r.kind === 'ok') {
      expect(r.passphrase).toBe('hunter2')
    }
  })

  it('webapp mode starts locked and unlocks via unlockWith', async () => {
    const src = new PassphraseSource('webapp', store, { env: {} })
    expect((await src.resolve()).kind).toBe('unlock-required')
    src.unlockWith('pp')
    const r = await src.resolve()
    expect(r.kind).toBe('ok')
    if (r.kind === 'ok') {
      expect(r.passphrase).toBe('pp')
    }
    src.lock()
    expect((await src.resolve()).kind).toBe('unlock-required')
  })

  it('convenience mode derives a stable passphrase across resolves', async () => {
    const src1 = new PassphraseSource('convenience', store, {
      env: {},
      machineId: 'fixed-host',
      convenienceIterations: TEST_ITERATIONS
    })
    const r1 = await src1.resolve()
    const src2 = new PassphraseSource('convenience', store, {
      env: {},
      machineId: 'fixed-host',
      convenienceIterations: TEST_ITERATIONS
    })
    const r2 = await src2.resolve()
    expect(r1.kind).toBe('ok')
    expect(r2.kind).toBe('ok')
    if (r1.kind === 'ok' && r2.kind === 'ok') {
      expect(r1.passphrase).toBe(r2.passphrase)
      expect(r1.passphrase).toMatch(/^[0-9a-f]{64}$/)
    }
  })

  it('convenience passphrase differs across hosts', async () => {
    const a = new PassphraseSource('convenience', store, {
      env: {},
      machineId: 'host-a',
      convenienceIterations: TEST_ITERATIONS
    })
    const ra = await a.resolve()
    const dirB = await mkdtemp(join(tmpdir(), 'signalk-ssl-pp2-'))
    const storeB = new CertStore(dirB)
    await storeB.init()
    const b = new PassphraseSource('convenience', storeB, {
      env: {},
      machineId: 'host-b',
      convenienceIterations: TEST_ITERATIONS
    })
    const rb = await b.resolve()
    expect(ra.kind).toBe('ok')
    expect(rb.kind).toBe('ok')
    if (ra.kind === 'ok' && rb.kind === 'ok') {
      expect(ra.passphrase).not.toBe(rb.passphrase)
    }
    await rm(dirB, { recursive: true, force: true })
  })
})
