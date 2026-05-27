import { chmod, mkdir, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'

export interface InstallTargets {
  readonly certPath: string
  readonly keyPath: string
  readonly chainPath: string
}

const PEM_KEY_MODE = 0o600
const PEM_CERT_MODE = 0o600

export const defaultTargets = (configPath: string): InstallTargets => ({
  certPath: join(configPath, 'ssl-cert.pem'),
  keyPath: join(configPath, 'ssl-key.pem'),
  chainPath: join(configPath, 'ssl-chain.pem')
})

const atomicWrite = async (
  path: string,
  data: string,
  mode: number,
  pid: number = process.pid
): Promise<void> => {
  const tmp = `${path}.${pid.toString()}.${Date.now().toString()}.tmp`
  await writeFile(tmp, data, { mode })
  await rename(tmp, path)
  // rename preserves mode on Linux; chmod is belt-and-braces for filesystems
  // where the inherited umask might widen it (some mounted volumes do).
  await chmod(path, mode)
}

/**
 * Atomically install the leaf certificate, key, and chain into the paths
 * signalk-server reads at boot (`${configPath}/ssl-cert.pem`,
 * `ssl-key.pem`, `ssl-chain.pem`). signalk-server enforces strict perms on
 * both files (refuses to start if either is group/world-readable; see
 * `hasStrictPermissions` in signalk-server's `src/security.ts`).
 */
export const installCerts = async (
  targets: InstallTargets,
  leafPem: string,
  leafKeyPem: string,
  caPem: string
): Promise<void> => {
  // mkdir every distinct parent directory. defaultTargets() puts all three
  // files under the same configPath, but the InstallTargets contract doesn't
  // require that, and a caller picking custom paths would otherwise ENOENT.
  const parents = new Set([
    dirname(targets.certPath),
    dirname(targets.keyPath),
    dirname(targets.chainPath)
  ])
  await Promise.all([...parents].map((d) => mkdir(d, { recursive: true })))
  await atomicWrite(targets.keyPath, leafKeyPem, PEM_KEY_MODE)
  await atomicWrite(targets.certPath, leafPem, PEM_CERT_MODE)
  // Chain file = leaf + CA, separated by newline. Caddy/Go's tls.X509KeyPair
  // expects the leaf first; Node's https.createServer doesn't strictly need
  // a chain file but signalk-server's interface exposes one, so we write it.
  const chain = `${leafPem.trimEnd()}\n${caPem.trimEnd()}\n`
  await atomicWrite(targets.chainPath, chain, PEM_CERT_MODE)
}
