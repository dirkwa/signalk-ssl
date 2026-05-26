import { isIP } from 'node:net'
import type { ParsedSans } from './types.js'

/**
 * Strip Unicode characters that break ASN.1 length math (macOS computer names
 * use smart quotes; ASN.1 length fields count bytes, not JS string chars).
 * Same set Keeper sanitises in `keeper/src/services/https-service.ts:53-64`.
 */
export const sanitizeHostname = (raw: string): string => {
  return raw
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[–—]/g, '-')
    .replace(/[^\x20-\x7E]/g, '')
    .trim()
}

const DNS_LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i

const isValidDnsName = (name: string): boolean => {
  if (name.length === 0 || name.length > 253) {
    return false
  }
  if (name === 'localhost') {
    return true
  }
  const labels = name.split('.')
  return labels.every((label) => DNS_LABEL_RE.test(label))
}

const normalizeIpv6 = (addr: string): string => {
  // Node's isIP() already validates; lowercase and strip leading zeros from
  // each hextet per RFC 5952. Keep zone IDs intact if present.
  const [base, zone] = addr.split('%', 2) as [string, string | undefined]
  const hextets = base
    .split(':')
    .map((h) => (h === '' ? '' : h.toLowerCase().replace(/^0+/, '') || '0'))
  return zone === undefined ? hextets.join(':') : `${hextets.join(':')}%${zone}`
}

export const parseSans = (input: readonly string[]): ParsedSans => {
  const dnsNames = new Set<string>()
  const ipAddresses = new Set<string>()

  for (const rawEntry of input) {
    const trimmed = rawEntry.trim()
    if (trimmed === '') {
      continue
    }
    const ipKind = isIP(trimmed)
    if (ipKind === 4) {
      ipAddresses.add(trimmed)
      continue
    }
    if (ipKind === 6) {
      ipAddresses.add(normalizeIpv6(trimmed))
      continue
    }
    const sanitized = sanitizeHostname(trimmed).toLowerCase()
    if (!isValidDnsName(sanitized)) {
      throw new Error(`Invalid SAN entry: ${rawEntry}`)
    }
    dnsNames.add(sanitized)
  }

  return {
    dnsNames: [...dnsNames],
    ipAddresses: [...ipAddresses]
  }
}
