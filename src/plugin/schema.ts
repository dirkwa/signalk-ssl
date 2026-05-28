import { Type, type Static, type TSchema } from '@sinclair/typebox'

export const SansSchema = Type.Object(
  {
    dnsNames: Type.Array(Type.String(), { default: [] }),
    ipAddresses: Type.Array(Type.String(), { default: [] })
  },
  { title: 'Subject Alternative Names' }
)

export const ImportSchema = Type.Object(
  {
    caCertPath: Type.Optional(
      Type.String({
        title: 'CA certificate file path',
        description: 'Only used when mode = import. Leave blank for generate mode.',
        default: ''
      })
    ),
    caKeyPath: Type.Optional(
      Type.String({
        title: 'CA private-key file path (encrypted PKCS#8)',
        description: 'Only used when mode = import. Leave blank for generate mode.',
        default: ''
      })
    )
  },
  {
    title: 'Import (only used when mode = import)',
    description:
      'Paths to an existing CA cert + encrypted private key on disk. Ignored in generate mode.'
  }
)

export const ConfigSchema = Type.Object(
  {
    mode: Type.Union([Type.Literal('generate'), Type.Literal('import')], {
      title: 'CA mode',
      description: '"generate" creates a fresh local CA; "import" loads an existing one from disk.',
      default: 'generate'
    }),
    commonName: Type.String({
      title: 'CA common name',
      default: 'SignalK Local CA',
      minLength: 1
    }),
    organization: Type.String({
      title: 'Organisation',
      default: 'SignalK',
      minLength: 1
    }),
    validityDaysCA: Type.Integer({
      title: 'CA validity (days)',
      default: 3650,
      minimum: 30,
      maximum: 7300
    }),
    validityDaysLeaf: Type.Integer({
      title: 'Leaf cert validity (days)',
      description: 'Apple/Chrome reject leaf certs > 398 days; 397 is the safe ceiling.',
      default: 397,
      minimum: 7,
      maximum: 397
    }),
    sans: SansSchema,
    passphraseMode: Type.Union(
      [Type.Literal('env'), Type.Literal('webapp'), Type.Literal('convenience')],
      {
        title: 'Passphrase mode',
        description:
          '"convenience" derives a key from host identity (no typing). "webapp" prompts in the UI on each restart. "env" reads SIGNALK_SSL_PASSPHRASE.',
        default: 'convenience'
      }
    ),
    import: Type.Optional(ImportSchema),
    renewalThresholdDays: Type.Integer({
      title: 'Auto-renew when fewer than N days remain',
      default: 30,
      minimum: 1,
      maximum: 90
    }),
    clockSkewHours: Type.Integer({
      title: 'Clock-skew backdate (hours)',
      description: 'notBefore = now - this. Defeats offline-boat phone clock drift.',
      default: 24,
      minimum: 0,
      maximum: 168
    })
  },
  {
    title: 'SignalK SSL',
    description: 'Manage a local Certificate Authority and HTTPS leaf certificates for this server.'
  }
)

export interface SchemaDefaults {
  /** Discovered mDNS hostname (e.g. `pi5radar.local`), or null if none. */
  readonly dnsName: string | null
  /** Discovered private-LAN IPv4 addresses to suggest as IP SANs. */
  readonly ipAddresses: readonly string[]
}

/**
 * Return the config schema with the SAN fields pre-filled with the discovered
 * mDNS hostname and private-LAN IPs, so the server-rendered config form shows
 * them as suggested defaults before the plugin is enabled. Falls back to the
 * static {@link ConfigSchema} when nothing useful was discovered.
 *
 * `schema()` is re-invoked by signalk-server on every config-screen load, so
 * this is evaluated fresh each time — no caching, picks up hostname/IP changes.
 * A default is a non-forcing suggestion: a user who clears a field gets an empty
 * list, so no provenance tracking is needed.
 */
export const buildConfigSchema = (defaults: SchemaDefaults): TSchema => {
  if (defaults.dnsName === null && defaults.ipAddresses.length === 0) {
    return ConfigSchema
  }
  // ConfigSchema is a plain JSON object at runtime; clone so we never mutate the
  // shared static schema, then swap in the discovered SAN defaults.
  const clone = structuredClone(ConfigSchema) as {
    properties: {
      sans: { properties: { dnsNames: { default: string[] }; ipAddresses: { default: string[] } } }
    }
  }
  clone.properties.sans.properties.dnsNames.default =
    defaults.dnsName === null ? [] : [defaults.dnsName]
  clone.properties.sans.properties.ipAddresses.default = [...defaults.ipAddresses]
  return clone as unknown as TSchema
}

export type SignalkSslConfig = Static<typeof ConfigSchema>

export const DEFAULT_CONFIG: SignalkSslConfig = {
  mode: 'generate',
  commonName: 'SignalK Local CA',
  organization: 'SignalK',
  validityDaysCA: 3650,
  validityDaysLeaf: 397,
  sans: { dnsNames: [], ipAddresses: [] },
  passphraseMode: 'convenience',
  renewalThresholdDays: 30,
  clockSkewHours: 24
}
