import { describe, it, expect, afterEach } from 'vitest'
import { mkdtemp, rm, chmod } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { detectContainer, probeWritable, checkPermissions } from '../src/plugin/container-env.js'

const dirs: string[] = []

const makeDir = async (): Promise<string> => {
  const d = await mkdtemp(join(tmpdir(), 'signalk-ssl-env-'))
  dirs.push(d)
  return d
}

afterEach(async () => {
  // Restore perms before rm so the cleanup itself doesn't EACCES.
  for (const d of dirs) {
    await chmod(d, 0o700).catch(() => undefined)
    await rm(d, { recursive: true, force: true }).catch(() => undefined)
  }
  dirs.length = 0
})

describe('detectContainer', () => {
  it('reports true when the `container` env var is set', () => {
    expect(detectContainer({ container: 'podman' })).toBe(true)
  })

  it('treats an empty `container` env var the same as unset', () => {
    // Environment-agnostic: an empty `container` must not be a positive signal
    // on its own. Comparing against detectContainer({}) keeps the assertion
    // valid even on a host where /.dockerenv or /run/.containerenv is present
    // (e.g. containerized CI), where a hardcoded `false` would be flaky.
    expect(detectContainer({ container: '' })).toBe(detectContainer({}))
  })
})

describe('probeWritable', () => {
  it('returns writable for a normal temp dir', async () => {
    const d = await makeDir()
    const p = await probeWritable(d)
    expect(p.writable).toBe(true)
    expect(p.error).toBeNull()
  })

  it('returns not-writable for a 0500 dir (no write bit)', async () => {
    if (process.platform === 'win32' || process.getuid?.() === 0) {
      // Root bypasses mode bits; skip where the assertion can't hold.
      return
    }
    const d = await makeDir()
    await chmod(d, 0o500)
    const p = await probeWritable(d)
    expect(p.writable).toBe(false)
    expect(p.error).not.toBeNull()
  })
})

describe('checkPermissions', () => {
  it('returns null when both dirs are writable', async () => {
    const dataDir = await makeDir()
    const configPath = await makeDir()
    const warning = await checkPermissions({ dataDir, configPath, containerized: true })
    expect(warning).toBeNull()
  })

  it('names the UID-shift failure mode when containerized and a dir is unwritable', async () => {
    if (process.platform === 'win32' || process.getuid?.() === 0) {
      return
    }
    const dataDir = await makeDir()
    const configPath = await makeDir()
    await chmod(configPath, 0o500)
    const warning = await checkPermissions({ dataDir, configPath, containerized: true })
    expect(warning).not.toBeNull()
    expect(warning).toContain('UID-shift')
    expect(warning).toContain(configPath)
  })

  it('gives a generic permission message when not containerized', async () => {
    if (process.platform === 'win32' || process.getuid?.() === 0) {
      return
    }
    const dataDir = await makeDir()
    const configPath = await makeDir()
    await chmod(dataDir, 0o500)
    const warning = await checkPermissions({ dataDir, configPath, containerized: false })
    expect(warning).not.toBeNull()
    expect(warning).not.toContain('UID-shift')
    expect(warning).toContain(dataDir)
  })

  it('creates the dirs if missing (mkdir recursive) and reports writable', async () => {
    const base = await makeDir()
    const dataDir = join(base, 'nested', 'data')
    const configPath = join(base, 'nested', 'cfg')
    const warning = await checkPermissions({ dataDir, configPath, containerized: true })
    expect(warning).toBeNull()
  })

  it('does not leave probe files behind', async () => {
    const dataDir = await makeDir()
    const configPath = await makeDir()
    await checkPermissions({ dataDir, configPath, containerized: true })
    const { readdir } = await import('node:fs/promises')
    const leftovers = (await readdir(dataDir)).filter((f) => f.includes('write-probe'))
    expect(leftovers).toEqual([])
  })
})
