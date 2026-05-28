import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

export type PassphraseMode = 'env' | 'webapp' | 'convenience'

export interface CaStateOnDisk {
  readonly certificatePem: string
  readonly encryptedKeyPem: string
  readonly fingerprintSha256: string
  readonly createdAt: string
  readonly mode: 'generate' | 'import'
}

export interface LeafStateOnDisk {
  readonly certificatePem: string
  readonly privateKeyPem: string
  readonly sansHash: string
  readonly issuedAt: string
}

export interface SettingsOnDisk {
  readonly schemaVersion: 1
  readonly passphraseMode: PassphraseMode
  readonly lastRenewedAt: string | null
}

export interface ConveniencePassphraseEnvelope {
  readonly salt: string
  readonly iterations: number
}

const SCHEMA_VERSION_DEFAULT = 1 as const

const FILES = {
  caCert: 'ca.cert.pem',
  caKey: 'ca.key.enc.pem',
  leafCert: 'leaf.cert.pem',
  leafKey: 'leaf.key.pem',
  state: 'state.json',
  leafState: 'leaf-state.json',
  settings: 'settings.json',
  convenience: 'passphrase.kdf.json'
} as const

const PEM_KEY_MODE = 0o600
const PEM_CERT_MODE = 0o644
const JSON_MODE = 0o600

const atomicWrite = async (
  path: string,
  data: string | Uint8Array,
  mode: number
): Promise<void> => {
  // tmp suffix is per-write so concurrent writers don't trample each other.
  const tmp = `${path}.${process.pid.toString()}.${Date.now().toString()}.tmp`
  await writeFile(tmp, data, { mode })
  try {
    await rename(tmp, path)
  } catch (err) {
    // If rename fails (cross-device, EACCES on the target, etc.), the tmp
    // file is orphaned. Best-effort cleanup so repeated failures don't pile
    // up garbage in the data dir; the original error is preserved.
    await rm(tmp, { force: true }).catch(() => undefined)
    throw err
  }
  // Belt-and-braces: rename preserves the source mode on Linux, but some
  // mounted volumes apply a widened umask on the rename target. Match the
  // explicit chmod in cert-installer.ts so the on-disk mode is guaranteed.
  await chmod(path, mode)
}

const readIfExists = async (path: string): Promise<string | null> => {
  try {
    return await readFile(path, 'utf8')
  } catch (err) {
    if (err instanceof Error && 'code' in err && (err as NodeJS.ErrnoException).code === 'ENOENT') {
      return null
    }
    throw err
  }
}

export class CertStore {
  readonly dataDir: string

  constructor(dataDir: string) {
    this.dataDir = dataDir
  }

  async init(): Promise<void> {
    await mkdir(this.dataDir, { recursive: true, mode: 0o700 })
  }

  private path(name: keyof typeof FILES): string {
    return join(this.dataDir, FILES[name])
  }

  async readCaState(): Promise<CaStateOnDisk | null> {
    const cert = await readIfExists(this.path('caCert'))
    const key = await readIfExists(this.path('caKey'))
    if (cert === null || key === null) {
      return null
    }
    const stateRaw = await readIfExists(this.path('state'))
    const parsed = stateRaw === null ? null : (JSON.parse(stateRaw) as Partial<CaStateOnDisk>)
    return {
      certificatePem: cert,
      encryptedKeyPem: key,
      fingerprintSha256: parsed?.fingerprintSha256 ?? '',
      createdAt: parsed?.createdAt ?? new Date(0).toISOString(),
      mode: parsed?.mode ?? 'generate'
    }
  }

  async writeCaState(state: CaStateOnDisk): Promise<void> {
    await this.init()
    await atomicWrite(this.path('caCert'), state.certificatePem, PEM_CERT_MODE)
    await atomicWrite(this.path('caKey'), state.encryptedKeyPem, PEM_KEY_MODE)
    const meta = {
      fingerprintSha256: state.fingerprintSha256,
      createdAt: state.createdAt,
      mode: state.mode
    }
    await atomicWrite(this.path('state'), JSON.stringify(meta, null, 2), JSON_MODE)
  }

  async readLeafState(): Promise<LeafStateOnDisk | null> {
    const cert = await readIfExists(this.path('leafCert'))
    const key = await readIfExists(this.path('leafKey'))
    if (cert === null || key === null) {
      return null
    }
    const metaRaw = await readIfExists(this.path('leafState'))
    const parsed = metaRaw === null ? null : (JSON.parse(metaRaw) as Partial<LeafStateOnDisk>)
    return {
      certificatePem: cert,
      privateKeyPem: key,
      sansHash: parsed?.sansHash ?? '',
      issuedAt: parsed?.issuedAt ?? new Date(0).toISOString()
    }
  }

  async writeLeafState(state: LeafStateOnDisk): Promise<void> {
    await this.init()
    await atomicWrite(this.path('leafCert'), state.certificatePem, PEM_CERT_MODE)
    await atomicWrite(this.path('leafKey'), state.privateKeyPem, PEM_KEY_MODE)
    const meta = {
      sansHash: state.sansHash,
      issuedAt: state.issuedAt
    }
    await atomicWrite(this.path('leafState'), JSON.stringify(meta, null, 2), JSON_MODE)
  }

  async readSettings(): Promise<SettingsOnDisk | null> {
    const raw = await readIfExists(this.path('settings'))
    if (raw === null) {
      return null
    }
    return JSON.parse(raw) as SettingsOnDisk
  }

  async writeSettings(settings: SettingsOnDisk): Promise<void> {
    await this.init()
    const out: SettingsOnDisk = { ...settings, schemaVersion: SCHEMA_VERSION_DEFAULT }
    await atomicWrite(this.path('settings'), JSON.stringify(out, null, 2), JSON_MODE)
  }

  async readConvenienceEnvelope(): Promise<ConveniencePassphraseEnvelope | null> {
    const raw = await readIfExists(this.path('convenience'))
    if (raw === null) {
      return null
    }
    return JSON.parse(raw) as ConveniencePassphraseEnvelope
  }

  async writeConvenienceEnvelope(env: ConveniencePassphraseEnvelope): Promise<void> {
    await this.init()
    await atomicWrite(this.path('convenience'), JSON.stringify(env, null, 2), JSON_MODE)
  }
}
