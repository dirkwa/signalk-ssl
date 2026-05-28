# signalk-ssl

SSL/TLS certificate management for [SignalK Node Server](https://signalk.org/).

`signalk-ssl` turns HTTPS on your SignalK server from an SSH-and-`openssl` chore into a two-minute, point-and-click task — it runs a local Certificate Authority, issues and auto-renews trusted server certificates, and hands you a QR code to install the CA root on every phone and tablet aboard. Built to slot seamlessly into the [SignalK Universal Installer](https://github.com/dirkwa/signalk-universal-installer) stack, it also runs perfectly standalone on any vanilla SignalK Node Server.

## Features

- **Local CA + trusted certs, zero terminal** — generates an EC Certificate Authority and signs HTTPS certificates for your boat's hostname and IPs, so browsers show a green padlock instead of a scary warning.
- **One-scan device trust** — a built-in QR code installs the CA root on iOS (`.mobileconfig`) and Android / desktop (`.crt`); no SSH, no file copying, no per-device fiddling.
- **Set-and-forget renewal** — certificates auto-renew before expiry and re-issue automatically when your SANs change, with a 24-hour clock-skew backdate so an offline boat's lagging phone clock never breaks trust.
- **Smart, server-aware defaults** — pre-fills the certificate name with the exact `.local` hostname your server broadcasts on mDNS, and shows live certificate health (name + days remaining) right in the admin status line.
- **Encrypted at rest, your choice of key** — the CA private key is always stored as encrypted PKCS#8, with `convenience` (no typing), `env` (environment variable), or `webapp` (prompt-based) passphrase modes.
- **Runs anywhere SignalK runs** — pure-JS, no native modules; works identically on bare-metal, systemd, and Docker / Podman installs, and is tuned for drop-in use with the SignalK Universal Installer.

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
4. Open the plugin webapp at `/signalk-ssl/`.
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

- `GET /signalk-ssl/` — webapp static files (served by signalk-server at the module name, admin auth required)
- `GET /plugins/signalk-ssl/status` — JSON status (admin auth required)
- `POST /plugins/signalk-ssl/renew` — issue / renew leaf (admin auth required)
- `POST /plugins/signalk-ssl/unlock` — supply passphrase (webapp mode, admin auth required)
- `POST /plugins/signalk-ssl/lock` — drop in-memory passphrase
- `POST /plugins/signalk-ssl/rotate` — re-encrypt the CA key under a new passphrase (admin auth required)
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

### "Cannot write the CA / certificate files" (rootless Podman UID shift)

The plugin probes write access to its data dir and the cert path at startup. Inside **rootless Podman**, a bind-mounted host directory can look present but reject child creation when the directory is owned by a UID that doesn't match the container's effective UID — the classic UID-shift symptom. When this happens the plugin logs a warning and shows a red banner on the status dashboard instead of silently failing on the first cert write.

Fixes:

- Run the container with `--userns=keep-id` (Podman) so in-container writes land as the host owner. On hosts where the SignalK user isn't UID 1000, use the explicit form `--userns=keep-id:uid=<in-image-uid>,gid=<in-image-gid>`.
- Or `chown` the mounted directory to the UID the container process runs as.

### "I rotated the CA and now every phone is broken"

That's the cost of rotating a CA. Every device needs to re-install the new root. The webapp's "Regenerate CA" button shows this consequence before it lets you proceed.

## Out of scope

- ACME / Let's Encrypt (would live in a separate `signalk-acme` plugin)
- Revocation lists / OCSP
- Multi-CA / multi-tenant

## License

Apache-2.0
