/**
 * The host side of feed distribution: what a host agent runs to update its Guardian rule pack or
 * CVE index from the Guardian server (endpoints in routes/guardian.ts, format in
 * app/Guardian/feed-format.ts). It uses only `fetch` and the filesystem, no database.
 *
 * One update, in order, keeping the installed file untouched on any failure:
 *
 * 1. `GET /api/feeds/{kind}/manifest` with the last manifest ETag as `If-None-Match`; 304 means
 *    nothing changed.
 * 2. Verify the manifest signature against the key pinned at enrolment (`feedKey.publicKey` in
 *    the enrolment response). A key from any other source is never trusted.
 * 3. Refuse a version lower than or equal to the installed one, so an old authentic manifest
 *    cannot be replayed to roll the host back. The floor is the larger of the version recorded
 *    in the state file and the version in the installed file's own header. A manifest of the
 *    installed version whose SHA-256 is the installed file's is current (the state file is
 *    rewritten if it was lost), never a reason to download again.
 * 4. Download the blob with `If-Match` set to the manifest's digest (a blob replaced by a newer
 *    publish in between answers 412) into a temporary file beside the target, refusing more
 *    bytes than the manifest's size, then check the exact size and the SHA-256.
 * 5. Check the artifact whole: the header version must equal the manifest's; a rule bundle's own
 *    Ed25519 footer must verify with the pinned key; an index must be signed by the pinned key,
 *    and its body must hash to the signed BLAKE3 root (zav's open checks only the header).
 * 6. fsync, rename over the installed file, fsync the directory, then record the state.
 *
 * Limit: a manifest's `createdAt` is signed but not checked against the clock, so a server or
 * channel that keeps answering 304, or keeps replaying the current manifest, holds a host on
 * what it has; it can never move it backwards. An unchanged rebuild keeps the same version, so an
 * old version alone proves nothing; an agent that must detect a freeze needs a freshness signal it
 * trusts independently (docs/FEEDS.md, "Freshness").
 */
import { closeSync, existsSync, fstatSync, openSync, readFileSync } from 'node:fs'
import { commitFile, readHead, removeQuietly, sha256OfFd, tempPathBeside, writeStreamDurably } from './feed-files'
import type { FeedKind, FeedManifest } from './feed-format'
import {
  FeedError,
  inspectCveIndex,
  inspectRuleBundle,
  isFeedKind,
  keyIdOf,
  magicFor,
  parsePublicKey,
  verifySignedManifest,
} from './feed-format'

export interface FeedUpdateOptions {
  /** The Guardian server's origin, e.g. `https://guardian.example.test`. */
  server: string
  /** The host's `gdh_` credential. */
  credential: string
  kind: FeedKind
  /** The pinned feed public key (64 hex digits) from the enrolment response. */
  publicKey: string
  /** Where the artifact is installed, e.g. the path `zav compile --guardian-bundle` reads. */
  installPath: string
  /** Defaults to `<installPath>.state.json`. */
  statePath?: string
  /** Injectable for tests and for agents with their own HTTP stack. */
  fetch?: (input: string, init: RequestInit) => Promise<Response>
}

export interface FeedUpdateResult {
  status: 'current' | 'updated'
  version: number
  sha256: string | null
}

interface FeedState {
  kind: FeedKind
  version: number
  sha256: string
  manifestEtag: string
}

function readState(path: string, kind: FeedKind): FeedState | null {
  try {
    const raw = JSON.parse(readFileSync(path, 'utf8')) as Partial<FeedState>
    if (raw.kind !== kind || typeof raw.version !== 'number' || typeof raw.sha256 !== 'string' || typeof raw.manifestEtag !== 'string')
      return null
    return raw as FeedState
  }
  catch {
    return null
  }
}

/** The version in the installed file's header, or 0 when there is no readable installed file. */
function installedHeaderVersion(kind: FeedKind, path: string): number {
  if (!existsSync(path))
    return 0
  try {
    const head = readHead(path, 48)
    if (head.length < 48 || !head.subarray(0, 8).equals(magicFor(kind)))
      return 0
    return kind === 'rules' ? Number(head.readBigUInt64LE(16)) : Number(head.readBigUInt64LE(24))
  }
  catch {
    return 0
  }
}

/** Check a downloaded file's header against the manifest and the pinned key. */
function verifyArtifact(kind: FeedKind, path: string, manifest: FeedManifest, publicKey: Buffer): void {
  const facts = kind === 'rules'
    ? inspectRuleBundle(readFileSync(path), publicKey)
    : inspectCveIndex(path, publicKey, false)
  if (facts.version !== manifest.version)
    throw new FeedError('artifact', `blob header version ${facts.version} is not the manifest version ${manifest.version}`)
}

/** SHA-256 of the installed file, or null when there is none. */
function installedSha256(path: string): string | null {
  let fd: number
  try {
    fd = openSync(path, 'r')
  }
  catch {
    return null
  }
  try {
    return sha256OfFd(fd, fstatSync(fd).size)
  }
  finally {
    closeSync(fd)
  }
}

async function writeState(statePath: string, state: FeedState): Promise<void> {
  const temp = tempPathBeside(statePath)
  try {
    await writeStreamDurably(new Blob([JSON.stringify(state)]).stream(), temp, 4096)
    commitFile(temp, statePath)
  }
  catch (error) {
    removeQuietly(temp)
    throw error
  }
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text()
  if (text.length > 64 * 1024)
    throw new FeedError('manifest', 'manifest response is too large')
  try {
    return JSON.parse(text)
  }
  catch {
    throw new FeedError('manifest', 'manifest response is not JSON')
  }
}

/** Update one feed. Throws `FeedError` on any refusal; the installed file is then untouched. */
export async function updateFeed(options: FeedUpdateOptions): Promise<FeedUpdateResult> {
  if (!isFeedKind(options.kind))
    throw new FeedError('unknown-kind', `${String(options.kind)} is not a feed kind`)
  const kind = options.kind
  const publicKey = parsePublicKey(options.publicKey)
  const statePath = options.statePath ?? `${options.installPath}.state.json`
  const doFetch = options.fetch ?? ((input: string, init: RequestInit) => fetch(input, init))
  const base = options.server.replace(/\/+$/, '')
  const auth = { Authorization: `Bearer ${options.credential}` }

  const state = readState(statePath, kind)
  const floor = Math.max(state?.version ?? 0, installedHeaderVersion(kind, options.installPath))
  const installed = existsSync(options.installPath)

  const manifestResponse = await doFetch(`${base}/api/feeds/${kind}/manifest`, {
    headers: { ...auth, Accept: 'application/json', ...(state && installed ? { 'If-None-Match': state.manifestEtag } : {}) },
  })
  if (manifestResponse.status === 304 && state && installed)
    return { status: 'current', version: state.version, sha256: state.sha256 }
  if (manifestResponse.status !== 200)
    throw new FeedError('http', `manifest request answered ${manifestResponse.status}`)
  const manifestEtag = manifestResponse.headers.get('etag') ?? ''

  const manifest = verifySignedManifest(await readJson(manifestResponse), publicKey)
  if (manifest.kind !== kind)
    throw new FeedError('manifest', `asked for ${kind} and got a ${manifest.kind} manifest`)
  if (manifest.keyId !== keyIdOf(publicKey))
    throw new FeedError('wrong-key', 'manifest key is not the pinned key')
  if (manifest.version <= floor) {
    if (manifest.version === floor && installed) {
      if (state?.sha256 === manifest.sha256)
        return { status: 'current', version: floor, sha256: manifest.sha256 }
      // No usable state file, but the installed file may be exactly this blob: then it is
      // current, and the state is written again so the next check is a 304.
      if (installedSha256(options.installPath) === manifest.sha256) {
        await writeState(statePath, { kind, version: manifest.version, sha256: manifest.sha256, manifestEtag })
        return { status: 'current', version: floor, sha256: manifest.sha256 }
      }
    }
    throw new FeedError('downgrade', `server offers ${kind} version ${manifest.version}, not newer than the installed ${floor}`)
  }

  const blobResponse = await doFetch(`${base}/api/feeds/${kind}/blob`, {
    headers: { ...auth, 'Accept': 'application/octet-stream', 'If-Match': `"${manifest.sha256}"` },
  })
  if (blobResponse.status === 412)
    throw new FeedError('http', 'the blob changed after the manifest was read (a newer publish); the next update gets it')
  if (blobResponse.status !== 200 || !blobResponse.body)
    throw new FeedError('http', `blob request answered ${blobResponse.status}`)

  const temp = tempPathBeside(options.installPath)
  try {
    const written = await writeStreamDurably(blobResponse.body, temp, manifest.size)
    if (written.size !== manifest.size)
      throw new FeedError('size', `blob is ${written.size} bytes, the manifest says ${manifest.size}`)
    if (written.sha256 !== manifest.sha256)
      throw new FeedError('digest', 'blob SHA-256 does not match the signed manifest')
    verifyArtifact(kind, temp, manifest, publicKey)
    commitFile(temp, options.installPath)
  }
  catch (error) {
    removeQuietly(temp)
    throw error
  }

  await writeState(statePath, { kind, version: manifest.version, sha256: manifest.sha256, manifestEtag })
  return { status: 'updated', version: manifest.version, sha256: manifest.sha256 }
}
