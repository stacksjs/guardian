/**
 * Distribution of Guardian's own artifacts to enrolled hosts: the signed rule pack and the
 * compiled CVE index (formats in app/Guardian/feed-format.ts). Hosts update from this server
 * instead of every host pulling every upstream feed.
 *
 * - **Key.** One Ed25519 seed, at the path `GUARDIAN_FEED_SIGNING_KEY_FILE` names (32 raw bytes,
 *   zav's `--signing-key` format, mode 0600 or stricter), signs the manifests, the rule bundles
 *   and the index. Hosts pin its public key from the enrolment response, a token-authenticated
 *   channel, and never take a key from a feed response. `GET /api/feeds/key` repeats it so an
 *   agent notices a rotation; adopting a rotated key is an operator decision (re-enrol or re-pin),
 *   never automatic. A web process that only enrols hosts and serves feeds needs the public half
 *   alone: set `GUARDIAN_FEED_PUBLIC_KEY` there and give the seed only to the processes that publish.
 * - **Publish** (`publishFeed`) is the only writer, one at a time per kind under a lock file. It
 *   copies the blob into the feed directory (`GUARDIAN_FEED_DIR`, default `storage/guardian/feeds`)
 *   with a durable rename, checks the whole copy (a CVE index body against its signed root), and
 *   only then points the `SignatureFeed` row at it, so a reader never sees a manifest whose blob
 *   is missing or partial. Blob names carry the version and digest and are never rewritten.
 * - **Serve** reads only the file name the publish path recorded, opened without following
 *   symlinks, checks size, magic and SHA-256 on that same descriptor and streams from it, and
 *   answers conditional requests with 304 (and 412 for an `If-Match` naming another blob).
 *
 * ClamAV-derived databases are never served, by three independent checks: publish accepts only
 * the Guardian rule pack and the KEV/NVD/OSV index as sources; publish and serve both refuse any
 * blob whose magic is not `ZAVRULE` or `ZAVCVE` (a `.zavdb`, a ClamAV CVD/CLD/CUD, anything
 * else); and only the two published rows are reachable, by kind, never by a requested path.
 */
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, statSync } from 'node:fs'
import { join } from 'node:path'
import process from 'node:process'
import { HttpError } from '@stacksjs/error-handling'
import { log } from '@stacksjs/logging'
import { storagePath } from '@stacksjs/path'
import { acquireLock, commitFile, copyFileDurably, removeQuietly, sha256OfFd, tempPathBeside } from './feed-files'
import type { FeedKind, FeedManifest, FeedSigningKey, SignedManifest } from './feed-format'
import {
  assertMagic,
  FeedError,
  FILE_EXTENSION,
  ifMatchMatches,
  ifNoneMatchMatches,
  inspectCveIndex,
  inspectRuleBundle,
  isFeedKind,
  keyIdOf,
  MANIFEST_FORMAT,
  manifestSigningBytes,
  maxBytesFor,
  parseManifest,
  parsePublicKey,
  signingKeyFromSeed,
  signManifest,
  strongEtag,
} from './feed-format'

export const SIGNING_KEY_ENV = 'GUARDIAN_FEED_SIGNING_KEY_FILE'
/** The feed public key (64 hex digits), for processes that serve feeds but never sign them. */
export const PUBLIC_KEY_ENV = 'GUARDIAN_FEED_PUBLIC_KEY'
export const FEED_DIR_ENV = 'GUARDIAN_FEED_DIR'

/** The `SignatureFeed` row each published kind lives in. */
export const FEED_ROW_NAME: Record<FeedKind, string> = { rules: 'guardian-rules', cve: 'guardian-cve-index' }

/** The upstream sources each kind may be built from. Anything else, ClamAV above all, is refused. */
const ALLOWED_SOURCES: Record<FeedKind, readonly string[]> = { rules: ['guardian'], cve: ['kev', 'nvd', 'osv'] }

const BLOB_NAME = /^(rules|cve)-\d{1,20}-[0-9a-f]{16}\.(zavrules|zavcve)$/

const CACHE_CONTROL = 'private, no-cache'

/** Where published blobs live. Created on first use. */
export function feedDirectory(): string {
  const dir = process.env[FEED_DIR_ENV] || storagePath('guardian/feeds')
  mkdirSync(dir, { recursive: true, mode: 0o750 })
  return dir
}

/** The configured seed file's path, or null when feed signing is not configured. */
export function feedSigningKeyFile(): string | null {
  return process.env[SIGNING_KEY_ENV] || null
}

/**
 * Read the 32-byte seed, refusing before the read a file that is not a regular file of exactly
 * 32 bytes, or that group or others may read or write (on POSIX systems).
 */
function readSeed(file: string): Buffer {
  let fd: number
  try {
    fd = openSync(file, 'r')
  }
  catch (error) {
    throw new FeedError('config', `${SIGNING_KEY_ENV} names a file that cannot be read: ${(error as Error).message}`)
  }
  try {
    const stat = fstatSync(fd)
    if (!stat.isFile() || stat.size !== 32)
      throw new FeedError('config', `${SIGNING_KEY_ENV} must name a file of exactly 32 raw bytes, not ${stat.isFile() ? `${stat.size} bytes` : 'a non-file'}`)
    if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0)
      throw new FeedError('config', `${SIGNING_KEY_ENV} names a file group or others can access (mode ${(stat.mode & 0o777).toString(8)}); make it readable by its owner only (chmod 600)`)
    const seed = Buffer.alloc(32)
    if (readSync(fd, seed, 0, 32, 0) !== 32)
      throw new FeedError('config', `${SIGNING_KEY_ENV} could not be read whole`)
    return seed
  }
  finally {
    closeSync(fd)
  }
}

/** The server's feed signing key, or null when none is configured. A malformed key file throws. */
export function loadFeedSigningKey(): FeedSigningKey | null {
  const file = feedSigningKeyFile()
  if (!file)
    return null
  const seed = readSeed(file)
  try {
    return signingKeyFromSeed(seed)
  }
  finally {
    seed.fill(0)
  }
}

/** The signing key, or `config` when none is set or it is not the configured public key. */
export function requireFeedSigningKey(): FeedSigningKey {
  const key = loadFeedSigningKey()
  if (!key)
    throw new FeedError('config', `${SIGNING_KEY_ENV} is not set, so feeds cannot be published`)
  const configured = process.env[PUBLIC_KEY_ENV]?.trim()
  if (configured && !parsePublicKey(configured).equals(key.publicKey))
    throw new FeedError('config', `${PUBLIC_KEY_ENV} is not the public half of the key ${SIGNING_KEY_ENV} names`)
  return key
}

export interface FeedKeyInfo {
  algorithm: 'ed25519'
  /** 64 hex digits; pass to `zav compile --guardian-key` and to the host updater. */
  publicKey: string
  keyId: string
}

let derivedKeyInfo: { stamp: string, info: FeedKeyInfo } | null = null

/**
 * The public half of the feed key, for enrolment and `GET /api/feeds/key`; null when unconfigured.
 * `GUARDIAN_FEED_PUBLIC_KEY` answers without touching the seed. Otherwise the public key is
 * derived from the seed once per seed file version (path, inode, size and modification time), so
 * request paths do not read the private key on every call.
 */
export function feedKeyInfo(): FeedKeyInfo | null {
  const configured = process.env[PUBLIC_KEY_ENV]?.trim()
  if (configured) {
    const publicKey = parsePublicKey(configured)
    return { algorithm: 'ed25519', publicKey: publicKey.toString('hex').toLowerCase(), keyId: keyIdOf(publicKey) }
  }
  const file = feedSigningKeyFile()
  if (!file)
    return null
  let stamp: string
  try {
    const stat = statSync(file)
    stamp = `${file}:${stat.ino}:${stat.size}:${stat.mtimeMs}`
  }
  catch (error) {
    throw new FeedError('config', `${SIGNING_KEY_ENV} names a file that cannot be read: ${(error as Error).message}`)
  }
  if (derivedKeyInfo?.stamp !== stamp) {
    const key = loadFeedSigningKey()!
    derivedKeyInfo = { stamp, info: { algorithm: 'ed25519', publicKey: key.publicKey.toString('hex'), keyId: key.keyId } }
  }
  return { ...derivedKeyInfo.info }
}

export interface PublishInput {
  kind: FeedKind
  /** The artifact zav wrote. It is copied; the original is left alone. */
  file: string
  /** What the artifact was built from: `['guardian']` for rules, KEV/NVD/OSV for the index. */
  sources: readonly string[]
  /**
   * Accept an index with no embedded signature. The manifest signature still binds its bytes,
   * but a host running `zav audit --cve-key` refuses an unsigned index, so this is off by default
   * and nothing in production sets it.
   */
  allowUnsignedIndex?: boolean
}

export interface PublishResult {
  published: boolean
  manifest: FeedManifest
  /** The published blob was missing or damaged on disk and this identical copy replaced it. */
  restored?: boolean
}

function checkSources(kind: FeedKind, sources: readonly string[]): string[] {
  if (!Array.isArray(sources) || sources.length === 0)
    throw new FeedError('source', `a ${kind} publish names the sources it was built from`)
  const unique = [...new Set(sources)]
  for (const source of unique) {
    if (source === 'clamav')
      throw new FeedError('source', 'ClamAV-derived databases are never served; each host compiles its own')
    if (!ALLOWED_SOURCES[kind].includes(source))
      throw new FeedError('source', `${source} is not a source a ${kind} feed is built from (allowed: ${ALLOWED_SOURCES[kind].join(', ')})`)
  }
  return unique
}

/**
 * Publish a new version of a feed. The version comes from the artifact's own header and must be
 * strictly greater than the published one. Republishing the identical blob, or the same content
 * under a new version or compile time, is a no-op (`published: false`) while the published blob
 * is intact on disk. When it is missing or damaged (a deploy that did not keep the feed
 * directory, a disk fault), the identical blob is put back under its recorded name, and the same
 * content in new bytes is published as a new version, so hosts never stay on a 503.
 *
 * One publish runs at a time per kind, under `<feed dir>/.publish-<kind>.lock`.
 */
export function publishFeed(input: PublishInput): PublishResult {
  if (!isFeedKind(input.kind))
    throw new FeedError('unknown-kind', `${String(input.kind)} is not a feed kind (rules or cve)`)
  const kind = input.kind
  const sources = checkSources(kind, input.sources)
  const key = requireFeedSigningKey()
  const dir = feedDirectory()
  const release = acquireLock(join(dir, `.publish-${kind}.lock`), `a ${kind} feed publish`)
  try {
    return publishLocked(input, kind, sources, key, dir)
  }
  finally {
    release()
  }
}

function publishLocked(input: PublishInput, kind: FeedKind, sources: string[], key: FeedSigningKey, dir: string): PublishResult {
  const incoming = tempPathBeside(join(dir, `incoming.${FILE_EXTENSION[kind]}`))
  const written = copyFileDurably(input.file, incoming, maxBytesFor(kind))
  // Set while a blob is in place that no committed row names yet, so a failure removes it.
  const pending = { blob: null as string | null }
  try {
    // Every check reads the copy, so the bytes checked are the bytes served. A CVE index is
    // checked whole: its header signature does not cover the body by itself.
    const facts = kind === 'rules'
      ? inspectRuleBundle(readFileSync(incoming), key.publicKey)
      : inspectCveIndex(incoming, key.publicKey, input.allowUnsignedIndex === true)

    const manifest: FeedManifest = {
      kind,
      version: facts.version,
      sha256: written.sha256,
      size: written.size,
      createdAt: new Date().toISOString(),
      keyId: key.keyId,
    }
    const signed = signManifest(manifest, key)
    const name = `${kind}-${facts.version}-${written.sha256.slice(0, 16)}.${FILE_EXTENSION[kind]}`

    const outcome = db.transaction(() => {
      const found = SignatureFeed.where('name', FEED_ROW_NAME[kind]).first()
      const row = found?.kind === kind && found.manifest ? found : null
      // The same bytes, or the same content rebuilt (a rule pack of unchanged sources under a new
      // version, an index compiled again from unchanged feeds), is not a new version: hosts keep
      // getting 304. That holds only while the published blob is really there.
      const sameBytes = row?.sha256 === written.sha256
      if (row && (sameBytes || publishedContentId(row.coverage) === facts.contentId)) {
        const published = parseManifest(JSON.parse(String(row.manifest)))
        if (recordedBlobIntact(dir, kind, row))
          return { published: false, restored: false, manifest: published }
        if (sameBytes) {
          commitFile(incoming, join(dir, String(row.path)))
          return { published: false, restored: true, manifest: published }
        }
        // The same content in new bytes, with the published blob gone: publish it as new.
      }
      const current = found?.kind === kind && found.version ? Number(found.version) : 0
      if (facts.version <= current)
        throw new FeedError('downgrade', `${kind} version ${facts.version} is not newer than the published ${current}`)

      // The blob is in place before the row names it.
      commitFile(incoming, join(dir, name))
      pending.blob = name
      const fields = {
        source: 'guardian' as const,
        kind,
        version: String(facts.version),
        enabled: true,
        lastUpdatedAt: manifest.createdAt,
        coverage: JSON.stringify({ sources, signedArtifact: facts.keyId !== null, content: facts.contentId }),
        sha256: written.sha256,
        size: written.size,
        path: name,
        manifest: JSON.stringify(signed.manifest),
        signature: signed.signature,
        keyId: key.keyId,
      }
      if (found)
        found.update(fields)
      else
        SignatureFeed.create({ name: FEED_ROW_NAME[kind], ...fields })
      return { published: true, restored: false, manifest: signed.manifest }
    })

    pending.blob = null
    if (outcome.published)
      pruneBlobs(dir, kind, name)
    return { published: outcome.published, manifest: outcome.manifest, ...(outcome.restored ? { restored: true } : {}) }
  }
  catch (error) {
    if (pending.blob)
      removeQuietly(join(dir, pending.blob))
    throw error
  }
  finally {
    removeQuietly(incoming)
  }
}

/** Whether the blob a row recorded is on disk as a regular file of its recorded size and SHA-256. */
function recordedBlobIntact(dir: string, kind: FeedKind, row: { path?: unknown, size?: unknown, sha256?: unknown }): boolean {
  const name = String(row.path ?? '')
  if (!BLOB_NAME.test(name) || !name.startsWith(`${kind}-`))
    return false
  const path = join(dir, name)
  try {
    if (!lstatSync(path).isFile())
      return false
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    try {
      const size = fstatSync(fd).size
      return size === Number(row.size) && sha256OfFd(fd, size) === row.sha256
    }
    finally {
      closeSync(fd)
    }
  }
  catch {
    return false
  }
}

/** The content identity a published row recorded in its coverage JSON, if any. */
function publishedContentId(coverage: unknown): string | null {
  if (typeof coverage !== 'string' || coverage === '')
    return null
  try {
    const parsed = JSON.parse(coverage) as { content?: unknown }
    return typeof parsed.content === 'string' ? parsed.content : null
  }
  catch {
    return null
  }
}

/**
 * Remove a kind's superseded blobs, keeping the current one. A download already in progress is
 * not cut short: it streams from a descriptor opened before the unlink. A host that read the
 * previous manifest and asks for its blob with `If-Match` gets 412 and retries on its next cycle.
 */
function pruneBlobs(dir: string, kind: FeedKind, keep: string): void {
  for (const entry of readdirSync(dir)) {
    if (BLOB_NAME.test(entry) && entry.startsWith(`${kind}-`) && entry !== keep)
      removeQuietly(join(dir, entry))
  }
}

/** The published row of a kind, or a 404 for an unknown kind or one with nothing published. */
function publishedRow(kind: unknown) {
  if (!isFeedKind(kind))
    throw new HttpError(404, 'Unknown feed')
  const row = SignatureFeed.where('name', FEED_ROW_NAME[kind]).first()
  if (!row || row.kind !== kind || row.source !== 'guardian' || !row.enabled || !row.manifest || !row.signature || !row.sha256 || !row.path)
    throw new HttpError(404, 'Nothing is published for this feed yet')
  return { kind, row }
}

/** The signed manifest of a kind as served. */
export function signedManifestFor(kind: unknown): SignedManifest {
  const { kind: k, row } = publishedRow(kind)
  const manifest = parseManifest(JSON.parse(String(row.manifest)))
  if (manifest.kind !== k)
    throw new HttpError(500, 'Published manifest names another kind')
  return { format: MANIFEST_FORMAT, manifest, signature: String(row.signature) }
}

function sha256Hex(bytes: Uint8Array): string {
  return new Bun.CryptoHasher('sha256').update(bytes).digest('hex')
}

/** `GET /api/feeds/{kind}/manifest`. */
export function feedManifestResponse(kind: unknown, ifNoneMatch: string | null): Response {
  const signed = signedManifestFor(kind)
  const etag = strongEtag(sha256Hex(manifestSigningBytes(signed.manifest)))
  const headers = { 'ETag': etag, 'Cache-Control': CACHE_CONTROL, 'X-Content-Type-Options': 'nosniff' }
  if (ifNoneMatchMatches(ifNoneMatch, etag))
    return new Response(null, { status: 304, headers })
  return new Response(JSON.stringify(signed), { status: 200, headers: { ...headers, 'Content-Type': 'application/json' } })
}

/** The on-disk path of a kind's published blob, resolved only from what publish recorded. */
export function publishedBlobPath(kind: unknown): { kind: FeedKind, path: string, sha256: string, size: number, version: string } {
  const { kind: k, row } = publishedRow(kind)
  const name = String(row.path)
  if (!BLOB_NAME.test(name) || !name.startsWith(`${k}-`))
    throw new HttpError(500, 'Published blob name is not one publish writes')
  return { kind: k, path: join(feedDirectory(), name), sha256: String(row.sha256), size: Number(row.size), version: String(row.version) }
}

/**
 * Blob files whose SHA-256 this process has already checked, by file identity (device, inode,
 * size, modification and change times), so each published blob is hashed once per process rather
 * than on every download. A rewritten file has a new identity and is hashed again.
 */
const verifiedBlobs = new Map<string, string>()

const STREAM_CHUNK = 256 * 1024

/** Stream exactly `size` bytes from an open descriptor, closing it at the end or on cancel. */
function streamDescriptor(fd: number, size: number): ReadableStream<Uint8Array> {
  let position = 0
  let open = true
  const close = () => {
    if (open) {
      open = false
      closeSync(fd)
    }
  }
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      try {
        const chunk = Buffer.allocUnsafe(Math.min(STREAM_CHUNK, size - position))
        const read = chunk.length > 0 ? readSync(fd, chunk, 0, chunk.length, position) : 0
        if (read > 0) {
          position += read
          controller.enqueue(chunk.subarray(0, read))
        }
        // A file that shrank ends the body short of Content-Length, which hosts refuse.
        if (read === 0 || position >= size) {
          close()
          controller.close()
        }
      }
      catch (error) {
        close()
        controller.error(error)
      }
    },
    cancel() {
      close()
    },
  })
}

function unavailable(kind: FeedKind, why: string): HttpError {
  void Promise.resolve(log.error(`[feeds] the published ${kind} blob cannot be served: ${why}. Is ${FEED_DIR_ENV} the same persistent directory on every server?`)).catch(() => {})
  return new HttpError(503, 'The published feed blob is not available')
}

/**
 * `GET /api/feeds/{kind}/blob`. `If-None-Match` matching the blob gives 304; an `If-Match` that
 * does not (a host holding a manifest that a newer publish replaced) gives 412 before any byte.
 */
export function feedBlobResponse(kind: unknown, ifNoneMatch: string | null, ifMatch: string | null = null): Response {
  const blob = publishedBlobPath(kind)
  const etag = strongEtag(blob.sha256)
  const headers: Record<string, string> = {
    'ETag': etag,
    'Cache-Control': CACHE_CONTROL,
    'X-Content-Type-Options': 'nosniff',
    'X-Guardian-Feed-Version': blob.version,
  }
  if (ifMatch !== null && !ifMatchMatches(ifMatch, etag))
    return new Response(null, { status: 412, headers })
  if (ifNoneMatchMatches(ifNoneMatch, etag))
    return new Response(null, { status: 304, headers })

  // Defence in depth: whatever the row says, only the recorded file (never a symlink planted
  // under its name), of the recorded size, starting with the kind's magic and hashing to the
  // recorded SHA-256 leaves this server, and the bytes streamed are read from the descriptor
  // those checks used.
  let fd: number
  try {
    fd = openSync(blob.path, constants.O_RDONLY | constants.O_NOFOLLOW)
  }
  catch (error) {
    throw unavailable(blob.kind, (error as NodeJS.ErrnoException).code ?? 'cannot open it')
  }
  let streaming = false
  try {
    const stat = fstatSync(fd)
    if (!stat.isFile() || stat.size !== blob.size)
      throw unavailable(blob.kind, 'its size is not the size publish recorded')
    const head = Buffer.alloc(8)
    readSync(fd, head, 0, 8, 0)
    try {
      assertMagic(blob.kind, head)
    }
    catch {
      throw unavailable(blob.kind, 'it is not a servable artifact')
    }
    const identity = `${blob.path}:${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeMs}:${stat.ctimeMs}`
    if (verifiedBlobs.get(identity) !== blob.sha256) {
      if (sha256OfFd(fd, blob.size) !== blob.sha256)
        throw unavailable(blob.kind, 'its SHA-256 is not the one publish recorded')
      if (verifiedBlobs.size >= 16)
        verifiedBlobs.clear()
      verifiedBlobs.set(identity, blob.sha256)
    }
    const body = streamDescriptor(fd, blob.size)
    streaming = true
    return new Response(body, {
      status: 200,
      headers: {
        ...headers,
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(blob.size),
        'Content-Disposition': `attachment; filename="guardian.${FILE_EXTENSION[blob.kind]}"`,
      },
    })
  }
  finally {
    if (!streaming)
      closeSync(fd)
  }
}
