import { access, constants, mkdir, rm, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Best-effort detection that we're running inside a container. None of these
 * signals is authoritative on its own, but any one of them is a strong hint:
 *   - `/.dockerenv` — Docker writes this into every container.
 *   - `/run/.containerenv` — Podman's equivalent.
 *   - `container` env var — set by systemd-nspawn and some Podman setups.
 */
export const detectContainer = (env: NodeJS.ProcessEnv = process.env): boolean => {
  return (
    existsSync('/.dockerenv') ||
    existsSync('/run/.containerenv') ||
    (env.container !== undefined && env.container !== '')
  )
}

export interface PermissionProbe {
  readonly dir: string
  readonly writable: boolean
  readonly error: string | null
}

/**
 * Verify the process can actually create + remove a file under `dir`. A bare
 * `access(dir, W_OK)` is not enough on bind-mounted volumes where the dir
 * looks writable but the effective UID can't create children (the classic
 * rootless-Podman UID-shift symptom). So we write a real probe file.
 */
export const probeWritable = async (dir: string): Promise<PermissionProbe> => {
  const probe = join(dir, `.signalk-ssl-write-probe.${process.pid.toString()}`)
  try {
    await mkdir(dir, { recursive: true })
    await access(dir, constants.W_OK)
    // The access() check passes on some UID-shifted mounts that still reject
    // child creation, so follow it with an actual create + remove.
    await rm(probe, { force: true })
    await writeFile(probe, '')
    await rm(probe, { force: true })
    return { dir, writable: true, error: null }
  } catch (e: unknown) {
    return { dir, writable: false, error: e instanceof Error ? e.message : String(e) }
  }
}

export interface PermissionCheckInput {
  readonly dataDir: string
  readonly configPath: string
  readonly containerized?: boolean
}

/**
 * Run write probes against the two directories the plugin must write to and,
 * if either fails while containerized, return an operator-facing warning that
 * names the rootless-Podman UID-shift failure mode explicitly. Returns null
 * when everything is writable.
 */
export const checkPermissions = async (input: PermissionCheckInput): Promise<string | null> => {
  const containerized = input.containerized ?? detectContainer()
  const probes = await Promise.all([probeWritable(input.dataDir), probeWritable(input.configPath)])
  const failed = probes.filter((p) => !p.writable)
  if (failed.length === 0) {
    return null
  }
  const dirs = failed.map((p) => p.dir).join(', ')
  if (containerized) {
    return (
      `Cannot write to ${dirs}. This is the classic rootless-Podman UID-shift ` +
      `symptom: the bind-mounted host directory is owned by a UID that doesn't ` +
      `match the container's effective UID. Run the container with ` +
      `--userns=keep-id (Podman) so in-container writes land as the host owner, ` +
      `or chown the mounted directory to the container UID. Until this is fixed ` +
      `the plugin can't persist the CA or install certificates.`
    )
  }
  return (
    `Cannot write to ${dirs}. Check directory ownership and permissions — the ` +
    `plugin needs to write the CA state and install ssl-*.pem there.`
  )
}
