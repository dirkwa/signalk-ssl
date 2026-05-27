// API shapes mirrored from src/plugin/types and service. Kept locally to
// keep the webapp build self-contained (Vite would otherwise pull node
// types from src/plugin during build).

export interface Status {
  hasCa: boolean
  caFingerprint: string | null
  caCreatedAt: string | null
  hasLeaf: boolean
  leafExpiresAt: string | null
  leafDaysRemaining: number | null
  leafSansDns: string[]
  leafSansIp: string[]
  restartRequired: boolean
  permissionWarning: string | null
}

export interface LocalIps {
  ipAddresses: string[]
}

export type IssueOutcome =
  | { kind: 'no-op'; reason: 'still-valid' }
  | { kind: 'issued'; reason: string }
  | { kind: 'locked'; reason: 'passphrase-required' | 'env-missing' }
  | { kind: 'error'; message: string }

const ADMIN_BASE = '/plugins/signalk-ssl'
const PUBLIC_BASE = '/signalk/v1/api/ssl'

const json = async <T>(res: Response): Promise<T> => {
  if (!res.ok) {
    throw new Error(`${res.status.toString()} ${res.statusText}`)
  }
  return (await res.json()) as T
}

export const getStatus = async (): Promise<Status> =>
  json<Status>(await fetch(`${ADMIN_BASE}/status`, { credentials: 'include' }))

export const getLocalIps = async (): Promise<LocalIps> =>
  json<LocalIps>(await fetch(`${ADMIN_BASE}/api/local-ips`, { credentials: 'include' }))

export const renew = async (): Promise<IssueOutcome> =>
  json<IssueOutcome>(await fetch(`${ADMIN_BASE}/renew`, { method: 'POST', credentials: 'include' }))

export const unlock = async (passphrase: string): Promise<IssueOutcome> =>
  json<IssueOutcome>(
    await fetch(`${ADMIN_BASE}/unlock`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase })
    })
  )

export const lock = async (): Promise<{ kind: 'locked' }> =>
  json<{ kind: 'locked' }>(
    await fetch(`${ADMIN_BASE}/lock`, { method: 'POST', credentials: 'include' })
  )

export const caCrtUrl = (): string => `${PUBLIC_BASE}/ca.crt`
export const caMobileconfigUrl = (): string => `${PUBLIC_BASE}/ca.mobileconfig`

export const detectPlatform = (
  ua: string = navigator.userAgent
): 'ios' | 'ipados' | 'android' | 'macos' | 'windows' | 'linux' | 'other' => {
  if (/iPad|iPhone|iPod/.test(ua)) return /iPad/.test(ua) ? 'ipados' : 'ios'
  // Modern iPads identify as MacIntel with touch points.
  if (/Macintosh/.test(ua) && typeof navigator !== 'undefined' && navigator.maxTouchPoints > 1) {
    return 'ipados'
  }
  if (/Android/.test(ua)) return 'android'
  if (/Macintosh/.test(ua)) return 'macos'
  if (/Windows/.test(ua)) return 'windows'
  if (/Linux/.test(ua)) return 'linux'
  return 'other'
}
