# signalk-ssl

SSL/TLS certificate management for [SignalK Node Server](https://signalk.org/).

Generates a local Certificate Authority, signs server certificates for your boat's hostnames and IP addresses, and provides a QR code so phones and tablets can install the CA root without SSH.

## Why

- Marina Wi-Fi has no public DNS name, so Let's Encrypt is out.
- Self-signed certs without a CA make every browser scream.
- Doing it by hand means SSH, `openssl`, and `update-ca-certificates` per device — for non-technical boaters that's not happening.

`signalk-ssl` collapses the whole flow into "open plugin → configure SANs → scan QR on each phone".

## Prerequisites

- Node.js ≥ 22.5.0 (matches the `engines.node` floor in `package.json`)
- SignalK Node Server ≥ 2.0 (uses the `@signalk/server-api` v2 plugin contract)

## Install

In the SignalK admin UI: **Appstore → Available → signalk-ssl → Install**.

The Appstore installs plugins with `npm install --ignore-scripts`, so this package ships with `dist/` and `public/` pre-built. No build step runs on your server.

## Configure

1. Enable the plugin in the SignalK admin UI.
2. Open the plugin configuration screen and fill in:
   - **SANs** — at least one DNS name (e.g. `signalk.local`, `boat.local`) and/or the boat's LAN IP. The webapp shows the discovered IPv4 addresses.
   - **Passphrase mode** — `convenience` is the default and just works.
   - Defaults for CA validity (10 years), leaf validity (397 days), renewal threshold (30 days), clock-skew backdate (24 hours) are fine for most boats.
3. Save the config. The plugin generates the CA, signs a leaf certificate, and writes both to SignalK's TLS path (`ssl-cert.pem`, `ssl-key.pem`, `ssl-chain.pem` in the configured config directory).
4. Open the plugin webapp at `/plugins/signalk-ssl/`.
5. Restart SignalK so the new certificate is picked up by the HTTPS listener. (The webapp shows a banner reminding you.)

## Distribute the CA to phones

In the webapp, the **Install on your devices** panel shows a QR code. The target URL is auto-selected by user-agent:

- iPhone / iPad → `.mobileconfig` profile (installs as a configuration profile; user enables full trust in Settings)
- Android / desktop → plain `.crt` with `application/x-x509-ca-cert` MIME

Scan with the device's camera, follow the OS prompts. The webapp includes step-by-step instructions for each platform.

Verify out-of-band by comparing the SHA-256 fingerprint shown on the boat against the one displayed on the device after install.

## Passphrase modes

The CA private key is always encrypted at rest with PBES2 / PBKDF2-SHA256 / AES-256-CBC PKCS#8.

| Mode                    | What it does                                                         | When to use                                                   |
| ----------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------- |
| `convenience` (default) | Derives the wrapping key from this host's identity. Nothing to type. | Single-purpose SignalK boxes where physical access ≈ root.    |
| `env`                   | Reads `SIGNALK_SSL_PASSPHRASE` from the environment at startup.      | Boxes where you set the env var via systemd / Compose.        |
| `webapp`                | Prompts in the webapp on each restart.                               | High-security setups where the passphrase lives in your head. |

### Changing the passphrase

The **Change passphrase** panel on the status dashboard re-encrypts the CA
private key under a new passphrase. The CA certificate itself is untouched, so
every device that already trusts your CA keeps working and no restart is
needed. Enter the current passphrase plus the new one; a wrong current
passphrase is rejected without changing anything on disk.

In `env` mode you must **also** update `SIGNALK_SSL_PASSPHRASE` to the new value
(systemd unit / Compose file), or the next restart won't be able to decrypt the
CA. In `convenience` mode the passphrase is machine-derived and not typeable, so
this flow doesn't apply — to re-key a convenience-mode install, switch to `env`
or `webapp` mode first.

## Mode of operation

- **Generate** (default) — fresh CA on first run.
- **Import** — load an existing CA cert + encrypted key from configured paths. Useful if you're moving from Keeper / the SignalK Universal Installer, or running multiple SignalK servers behind one CA.

## Routes

- `GET /plugins/signalk-ssl/` — webapp (admin auth required)
- `GET /plugins/signalk-ssl/status` — JSON status (admin auth required)
- `POST /plugins/signalk-ssl/renew` — issue / renew leaf (admin auth required)
- `POST /plugins/signalk-ssl/unlock` — supply passphrase (webapp mode, admin auth required)
- `POST /plugins/signalk-ssl/lock` — drop in-memory passphrase
- `POST /plugins/signalk-ssl/rotate` — re-encrypt the CA key under a new passphrase (admin auth required); body `{ oldPassphrase, newPassphrase }`
- `GET /signalk/v1/api/ssl/ca.crt` — **public** download of CA cert (PEM)
- `GET /signalk/v1/api/ssl/ca.mobileconfig` — **public** download of Apple profile

The two `/ssl/` paths are intentionally unauthenticated so phones without SignalK accounts can fetch the CA via the QR-coded URL. (`PUT`/`POST` on `/signalk/v1/api/*` is auto-protected by the server, so we can't accidentally expose a destructive endpoint here.)

## Container (Podman / Docker) notes

- The plugin uses `app.getDataDirPath()`, which means the per-plugin data lives under SignalK's data volume — survives container rebuilds.
- Certs land at `${app.config.configPath}/ssl-{cert,key,chain}.pem`, again on the data volume.
- mDNS `.local` resolution does **not** work through Podman's default bridge network. Either run with `--network=host` or use IP-based SANs and DNS on your router. The webapp can show the LAN IP URL as a fallback when it detects this case.
- For outbound trust **inside** the container (so the SignalK Node process trusts its own CA when calling itself or another boat service), set `NODE_EXTRA_CA_CERTS=/path/to/ca.crt` in the container env. Node reads this before plugins load, so the plugin can't set it on itself — the value must be in your Quadlet/Compose/run script.

## Troubleshooting

### "iOS Safari says the certificate is invalid"

Three usual causes:

1. The leaf cert doesn't list the hostname in the SAN. Check the SANs in the plugin config; re-issue if you added one after the fact.
2. The phone's clock is more than 24 hours behind. This plugin backdates `notBefore` by 24h to soften this; if it's still too far off, fix NTP on the boat.
3. The CA root isn't installed (or full trust isn't enabled in Settings → General → About → Certificate Trust Settings).

### "I changed the LAN IP and now nothing works"

The renewal scheduler runs daily and re-issues whenever the configured SANs no longer cover the leaf cert. To force an immediate refresh, click **Renew now** in the webapp.

### "Permission denied" on the cert key

SignalK refuses to start with a TLS key that isn't `0600`. The plugin writes `0600` and re-chmods on every install. If you see this error, check that no other process has rewritten the file.

### "I rotated the CA and now every phone is broken"

That's the cost of rotating a CA. Every device needs to re-install the new root. The webapp's "Regenerate CA" button shows this consequence before it lets you proceed.

## Out of scope

- ACME / Let's Encrypt (would live in a separate `signalk-acme` plugin)
- Revocation lists / OCSP
- Multi-CA / multi-tenant

## License

Apache-2.0
