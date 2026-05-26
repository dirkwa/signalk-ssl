export interface ParsedSans {
  readonly dnsNames: readonly string[]
  readonly ipAddresses: readonly string[]
}

export interface GenerateCaInput {
  readonly commonName: string
  readonly organization: string
  readonly validityDays: number
}

export interface GeneratedCa {
  readonly certificatePem: string
  readonly privateKey: CryptoKey
}

export interface SignLeafInput {
  readonly issuer: {
    readonly certificatePem: string
    readonly privateKey: CryptoKey
  }
  readonly subjectCommonName: string
  readonly organization: string
  readonly sans: ParsedSans
  readonly validityDays: number
  readonly clockSkewHours: number
}

export interface SignedLeaf {
  readonly certificatePem: string
  readonly privateKey: CryptoKey
  readonly privateKeyPem: string
}

export type FingerprintAlgorithm = 'sha256'
