/**
 * The Guardian feed wire format, shared by the server (app/Guardian/feed.ts) and the host
 * updater (app/Guardian/feed-client.ts). Nothing here touches the database, so a host agent can
 * import it on its own.
 *
 * Two artifacts are distributable, and nothing else ever is:
 *
 * - `rules`: the signed Guardian source bundle `zav rule-pack` writes (`.zavrules`, magic
 *   `ZAVRULE\n`, Ed25519 footer over every preceding byte; zig-anti-virus docs/rules/guardian.md)
 * - `cve`: the vulnerability index `zav cve compile` writes (`.zavcve`, magic `ZAVCVE\0\n`, the
 *   `.zavdb` container with its own magic; zig-anti-virus src/db/format.zig)
 *
 * ClamAV-derived databases are never distributable: each host compiles those itself.
 *
 * ## Signed manifest, version 1
 *
 * Every published artifact has a manifest of exactly six fields. The signature is Ed25519 over
 * the UTF-8 bytes of
 *
 *     guardian-feed-manifest-v1\n{"createdAt":"…","keyId":"…","kind":"…","sha256":"…","size":N,"version":N}
 *
 * that is, the domain prefix `guardian-feed-manifest-v1` and one LF, then the manifest as JSON
 * with the keys in that (lexicographic) order, no whitespace, integers in decimal and every
 * string plain ASCII, so the bytes have one spelling. The prefix keeps a manifest signature from
 * ever being mistaken for a signature over a zav bundle or database header, which the same key
 * also signs and which begin with their own magic. Field rules:
 *
 * - `kind`: `rules` or `cve`
 * - `version`: a positive safe integer, strictly increasing per kind; it equals the artifact's
 *   own header version (the pack version of a bundle, the `db_version` of an index)
 * - `sha256`: 64 lowercase hex digits over the whole blob; also the blob's strong ETag
 * - `size`: the blob's exact length in bytes
 * - `createdAt`: an ISO 8601 UTC instant (`YYYY-MM-DDTHH:MM:SS(.sss)Z`)
 * - `keyId`: 16 lowercase hex digits, the first 8 bytes of BLAKE3(public key), which is the key
 *   id zav writes into bundles and database headers, so one id names the key everywhere
 *
 * A verifier rebuilds the canonical bytes from the parsed fields and never trusts any other
 * spelling it was sent. The key is a 32-byte raw Ed25519 seed, the same file zav's
 * `--signing-key` reads.
 */
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { closeSync, fstatSync, openSync, readSync } from 'node:fs'

export const FEED_KINDS = ['rules', 'cve'] as const
export type FeedKind = typeof FEED_KINDS[number]

export const MANIFEST_FORMAT = 'guardian-feed-manifest-v1'

export const RULES_MAGIC = Buffer.from('ZAVRULE\n', 'latin1')
export const CVE_MAGIC = Buffer.from('ZAVCVE\0\n', 'latin1')
/** Signature database magic: never served, a host compiles its own. */
export const ZAVDB_MAGIC = Buffer.from('ZAVDB\0\r\n', 'latin1')
/** ClamAV CVD/CLD containers start with this header text. */
export const CLAMAV_MAGIC = Buffer.from('ClamAV-VDB', 'latin1')

/** zav's bundle limit. */
export const MAX_RULES_BYTES = 16 * 1024 * 1024
/** Generous ceiling for a full KEV, NVD and OSV index. */
export const MAX_CVE_BYTES = 2 * 1024 * 1024 * 1024

export const FILE_EXTENSION: Record<FeedKind, string> = { rules: 'zavrules', cve: 'zavcve' }

export type FeedErrorCode =
  | 'unknown-kind'
  | 'manifest'
  | 'bad-signature'
  | 'wrong-key'
  | 'downgrade'
  | 'size'
  | 'digest'
  | 'magic'
  | 'source'
  | 'artifact'
  | 'http'
  | 'locked'
  | 'config'

export class FeedError extends Error {
  constructor(readonly code: FeedErrorCode, message: string) {
    super(message)
    this.name = 'FeedError'
  }
}

export function isFeedKind(value: unknown): value is FeedKind {
  return typeof value === 'string' && (FEED_KINDS as readonly string[]).includes(value)
}

export function magicFor(kind: FeedKind): Buffer {
  return kind === 'rules' ? RULES_MAGIC : CVE_MAGIC
}

export function maxBytesFor(kind: FeedKind): number {
  return kind === 'rules' ? MAX_RULES_BYTES : MAX_CVE_BYTES
}

// --- keys -----------------------------------------------------------------------------------

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

export interface FeedSigningKey {
  privateKey: KeyObject
  publicKey: Buffer
  /** 16 hex digits. */
  keyId: string
}

/** A signing key from a 32-byte raw Ed25519 seed (zav's `--signing-key` format). */
export function signingKeyFromSeed(seed: Uint8Array): FeedSigningKey {
  if (seed.length !== 32)
    throw new FeedError('config', `an Ed25519 seed is exactly 32 raw bytes, not ${seed.length}`)
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, seed])
  let privateKey: KeyObject
  try {
    privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
  }
  finally {
    der.fill(0)
  }
  const publicKey = Buffer.from(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32))
  return { privateKey, publicKey, keyId: keyIdOf(publicKey) }
}

/** A 32-byte public key from its 64-digit hex form. */
export function parsePublicKey(hex: string): Buffer {
  if (typeof hex !== 'string' || !/^[0-9a-f]{64}$/i.test(hex))
    throw new FeedError('config', 'a feed public key is 64 hex digits')
  return Buffer.from(hex, 'hex')
}

function publicKeyObject(publicKey: Uint8Array): KeyObject {
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, publicKey]), format: 'der', type: 'spki' })
}

export function ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== 64)
    return false
  try {
    return edVerify(null, message, publicKeyObject(publicKey), signature)
  }
  catch {
    return false
  }
}

/** zav's key id: the first 8 bytes of BLAKE3(public key), in hex. */
export function keyIdOf(publicKey: Uint8Array): string {
  return Buffer.from(blake3(publicKey).subarray(0, 8)).toString('hex')
}

const B3_IV = Uint32Array.of(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
const B3_CHUNK_START = 1
const B3_CHUNK_END = 2
const B3_PARENT = 4
const B3_ROOT = 8
const B3_CHUNK_LEN = 1024

/** The message word order of each of the seven rounds (the permutation applied round by round). */
const B3_SCHEDULE = (() => {
  const permutation = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
  const out = new Uint8Array(7 * 16)
  let order = Array.from({ length: 16 }, (_, i) => i)
  for (let round = 0; round < 7; round++) {
    out.set(order, round * 16)
    order = permutation.map(i => order[i]!)
  }
  return out
})()

const b3State = new Uint32Array(16)

/** The BLAKE3 compression function; the 16-word result is left in `b3State`. */
function b3Compress(cv: Uint32Array, m: Uint32Array, counter: number, blockLen: number, flags: number): Uint32Array {
  const v = b3State
  v.set(cv, 0)
  v[8] = B3_IV[0]!
  v[9] = B3_IV[1]!
  v[10] = B3_IV[2]!
  v[11] = B3_IV[3]!
  v[12] = counter >>> 0
  v[13] = Math.floor(counter / 0x1_0000_0000) >>> 0
  v[14] = blockLen
  v[15] = flags
  const g = (a: number, b: number, c: number, d: number, x: number, y: number) => {
    let va = v[a]!, vb = v[b]!, vc = v[c]!, vd = v[d]!
    va = (va + vb + x) | 0
    vd ^= va
    vd = (vd >>> 16) | (vd << 16)
    vc = (vc + vd) | 0
    vb ^= vc
    vb = (vb >>> 12) | (vb << 20)
    va = (va + vb + y) | 0
    vd ^= va
    vd = (vd >>> 8) | (vd << 24)
    vc = (vc + vd) | 0
    vb ^= vc
    vb = (vb >>> 7) | (vb << 25)
    v[a] = va
    v[b] = vb
    v[c] = vc
    v[d] = vd
  }
  for (let r = 0; r < 112; r += 16) {
    const s = B3_SCHEDULE
    g(0, 4, 8, 12, m[s[r]!]!, m[s[r + 1]!]!)
    g(1, 5, 9, 13, m[s[r + 2]!]!, m[s[r + 3]!]!)
    g(2, 6, 10, 14, m[s[r + 4]!]!, m[s[r + 5]!]!)
    g(3, 7, 11, 15, m[s[r + 6]!]!, m[s[r + 7]!]!)
    g(0, 5, 10, 15, m[s[r + 8]!]!, m[s[r + 9]!]!)
    g(1, 6, 11, 12, m[s[r + 10]!]!, m[s[r + 11]!]!)
    g(2, 7, 8, 13, m[s[r + 12]!]!, m[s[r + 13]!]!)
    g(3, 4, 9, 14, m[s[r + 14]!]!, m[s[r + 15]!]!)
  }
  for (let i = 0; i < 8; i++) {
    v[i] = v[i]! ^ v[i + 8]!
    v[i + 8] = v[i + 8]! ^ cv[i]!
  }
  return v
}

function b3Words(bytes: Uint8Array, offset: number, length: number, into: Uint32Array): Uint32Array {
  into.fill(0)
  for (let i = 0; i < length; i++)
    into[i >> 2] = into[i >> 2]! | (bytes[offset + i]! << ((i & 3) * 8))
  return into
}

/**
 * Streaming BLAKE3 (unkeyed, 32-byte output), the hash zav uses for key ids and for the root of
 * a database body. Bun and node:crypto have no BLAKE3, and one hash is not worth a dependency.
 * Checked against vectors from Zig's std.crypto.hash.Blake3 (tests/feature/feed.test.ts).
 */
export class Blake3 {
  private readonly stack: Uint32Array[] = []
  private cv = Uint32Array.from(B3_IV)
  private chunkCounter = 0
  private readonly block = new Uint8Array(64)
  private blockLen = 0
  private blocksCompressed = 0
  private readonly words = new Uint32Array(16)

  private chunkLength(): number {
    return this.blocksCompressed * 64 + this.blockLen
  }

  private startFlag(): number {
    return this.blocksCompressed === 0 ? B3_CHUNK_START : 0
  }

  private compressBlock(bytes: Uint8Array, offset: number): void {
    const out = b3Compress(this.cv, b3Words(bytes, offset, 64, this.words), this.chunkCounter, 64, this.startFlag())
    this.cv.set(out.subarray(0, 8))
    this.blocksCompressed++
  }

  private chunkUpdate(input: Uint8Array, offset: number, length: number): void {
    const end = offset + length
    while (offset < end) {
      if (this.blockLen === 64) {
        this.compressBlock(this.block, 0)
        this.blockLen = 0
      }
      // Full blocks straight from the input, keeping the chunk's last block for its end flag.
      while (this.blockLen === 0 && end - offset > 64) {
        this.compressBlock(input, offset)
        offset += 64
      }
      const take = Math.min(64 - this.blockLen, end - offset)
      this.block.set(input.subarray(offset, offset + take), this.blockLen)
      this.blockLen += take
      offset += take
    }
  }

  private parentCv(left: Uint32Array, right: Uint32Array): Uint32Array {
    const m = new Uint32Array(16)
    m.set(left, 0)
    m.set(right, 8)
    return Uint32Array.from(b3Compress(B3_IV, m, 0, 64, B3_PARENT).subarray(0, 8))
  }

  update(input: Uint8Array): this {
    let offset = 0
    while (offset < input.length) {
      if (this.chunkLength() === B3_CHUNK_LEN) {
        const out = b3Compress(this.cv, b3Words(this.block, 0, this.blockLen, this.words), this.chunkCounter, this.blockLen, this.startFlag() | B3_CHUNK_END)
        let cv: Uint32Array = Uint32Array.from(out.subarray(0, 8))
        let total = this.chunkCounter + 1
        while (total % 2 === 0) {
          cv = this.parentCv(this.stack.pop()!, cv)
          total /= 2
        }
        this.stack.push(cv)
        this.chunkCounter++
        this.cv = Uint32Array.from(B3_IV)
        this.blockLen = 0
        this.blocksCompressed = 0
      }
      const take = Math.min(B3_CHUNK_LEN - this.chunkLength(), input.length - offset)
      this.chunkUpdate(input, offset, take)
      offset += take
    }
    return this
  }

  digest(): Uint8Array {
    let cv = this.cv
    let m = Uint32Array.from(b3Words(this.block, 0, this.blockLen, this.words))
    let counter = this.chunkCounter
    let blockLen = this.blockLen
    let flags = this.startFlag() | B3_CHUNK_END
    for (let i = this.stack.length - 1; i >= 0; i--) {
      const right = Uint32Array.from(b3Compress(cv, m, counter, blockLen, flags).subarray(0, 8))
      m = new Uint32Array(16)
      m.set(this.stack[i]!, 0)
      m.set(right, 8)
      cv = B3_IV
      counter = 0
      blockLen = 64
      flags = B3_PARENT
    }
    const out = b3Compress(cv, m, counter, blockLen, flags | B3_ROOT)
    const bytes = new Uint8Array(32)
    const view = new DataView(bytes.buffer)
    for (let i = 0; i < 8; i++)
      view.setUint32(i * 4, out[i]!, true)
    return bytes
  }
}

/** BLAKE3 of a whole input. */
export function blake3(input: Uint8Array): Uint8Array {
  return new Blake3().update(input).digest()
}

// --- manifest -------------------------------------------------------------------------------

export interface FeedManifest {
  kind: FeedKind
  version: number
  sha256: string
  size: number
  createdAt: string
  keyId: string
}

/** What the manifest endpoint returns. */
export interface SignedManifest {
  format: typeof MANIFEST_FORMAT
  manifest: FeedManifest
  /** Base64 Ed25519 signature over `manifestSigningBytes(manifest)`. */
  signature: string
}

const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/

/** Validate the six fields strictly; anything else in the object is refused, not ignored. */
export function parseManifest(value: unknown): FeedManifest {
  const fail = (why: string): never => {
    throw new FeedError('manifest', `manifest ${why}`)
  }
  if (!value || typeof value !== 'object' || Array.isArray(value))
    fail('is not an object')
  const raw = value as Record<string, unknown>
  const keys = Object.keys(raw).sort()
  if (keys.join(',') !== 'createdAt,keyId,kind,sha256,size,version')
    fail(`has fields ${keys.join(', ')}; expected exactly createdAt, keyId, kind, sha256, size, version`)
  if (!isFeedKind(raw.kind))
    fail('kind is not rules or cve')
  const kind = raw.kind as FeedKind
  if (typeof raw.version !== 'number' || !Number.isSafeInteger(raw.version) || raw.version < 1)
    fail('version is not a positive integer')
  if (typeof raw.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(raw.sha256))
    fail('sha256 is not 64 lowercase hex digits')
  if (typeof raw.size !== 'number' || !Number.isSafeInteger(raw.size) || raw.size < RULES_MAGIC.length || raw.size > maxBytesFor(kind))
    fail('size is out of range')
  if (typeof raw.createdAt !== 'string' || !INSTANT.test(raw.createdAt))
    fail('createdAt is not an ISO 8601 UTC instant')
  if (typeof raw.keyId !== 'string' || !/^[0-9a-f]{16}$/.test(raw.keyId))
    fail('keyId is not 16 lowercase hex digits')
  return {
    kind,
    version: raw.version as number,
    sha256: raw.sha256 as string,
    size: raw.size as number,
    createdAt: raw.createdAt as string,
    keyId: raw.keyId as string,
  }
}

/** The manifest's canonical JSON (keys in lexicographic order, no whitespace). */
export function canonicalManifest(manifest: FeedManifest): string {
  const m = parseManifest(manifest)
  return `{"createdAt":${JSON.stringify(m.createdAt)},"keyId":${JSON.stringify(m.keyId)},"kind":${JSON.stringify(m.kind)},"sha256":${JSON.stringify(m.sha256)},"size":${m.size},"version":${m.version}}`
}

/** The exact bytes the manifest signature covers. */
export function manifestSigningBytes(manifest: FeedManifest): Buffer {
  return Buffer.from(`${MANIFEST_FORMAT}\n${canonicalManifest(manifest)}`, 'utf8')
}

export function signManifest(manifest: FeedManifest, key: FeedSigningKey): SignedManifest {
  if (manifest.keyId !== key.keyId)
    throw new FeedError('wrong-key', 'manifest keyId does not name the signing key')
  const signature = edSign(null, manifestSigningBytes(manifest), key.privateKey).toString('base64')
  return { format: MANIFEST_FORMAT, manifest: parseManifest(manifest), signature }
}

/**
 * Verify a manifest response against a pinned public key, returning the validated manifest.
 * Throws `wrong-key` when it names a different key and `bad-signature` when the bytes do not
 * verify; a host keeps what it has installed in either case.
 */
export function verifySignedManifest(value: unknown, publicKey: Uint8Array): FeedManifest {
  if (!value || typeof value !== 'object')
    throw new FeedError('manifest', 'manifest response is not an object')
  const body = value as Record<string, unknown>
  if (body.format !== MANIFEST_FORMAT)
    throw new FeedError('manifest', `manifest format is not ${MANIFEST_FORMAT}`)
  const manifest = parseManifest(body.manifest)
  if (manifest.keyId !== keyIdOf(publicKey))
    throw new FeedError('wrong-key', `manifest is signed by key ${manifest.keyId}, not the pinned key ${keyIdOf(publicKey)}`)
  if (typeof body.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(body.signature))
    throw new FeedError('bad-signature', 'manifest signature is not a base64 Ed25519 signature')
  if (!ed25519Verify(publicKey, manifestSigningBytes(manifest), Buffer.from(body.signature, 'base64')))
    throw new FeedError('bad-signature', 'manifest signature does not verify')
  return manifest
}

// --- artifacts ------------------------------------------------------------------------------

export interface ArtifactFacts {
  /** The header version: the pack version of a bundle, the db_version of an index. */
  version: number
  /** The embedded signing key id, or null for an unsigned index. */
  keyId: string | null
  /**
   * A digest of everything in the artifact but its version, compile time and signature (see
   * `ruleBundleContentId` and `cveContentId`). Rebuilding unchanged sources gives the same id, so
   * publish treats it as nothing new and hosts keep getting 304.
   */
  contentId: string
}

/** Which known container a blob's leading bytes name, for refusal messages. */
export function describeMagic(head: Uint8Array): string {
  const starts = (magic: Buffer) => head.length >= magic.length && Buffer.from(head.subarray(0, magic.length)).equals(magic)
  if (starts(RULES_MAGIC))
    return 'a Guardian rule bundle'
  if (starts(CVE_MAGIC))
    return 'a CVE index'
  if (starts(ZAVDB_MAGIC))
    return 'a zav signature database (.zavdb), which hosts compile themselves'
  if (starts(CLAMAV_MAGIC))
    return 'a ClamAV database (CVD/CLD/CUD), which is never served'
  return 'an unrecognised file'
}

/** Refuse anything whose first bytes are not the kind's magic. */
export function assertMagic(kind: FeedKind, head: Uint8Array): void {
  const magic = magicFor(kind)
  if (head.length < magic.length || !Buffer.from(head.subarray(0, magic.length)).equals(magic))
    throw new FeedError('magic', `a ${kind} feed blob must start with ${JSON.stringify(magic.toString('latin1'))}; this is ${describeMagic(head)}`)
}

function u64(bytes: Buffer, offset: number): number {
  const value = bytes.readBigUInt64LE(offset)
  if (value > BigInt(Number.MAX_SAFE_INTEGER))
    throw new FeedError('artifact', `header field at ${offset} is out of range`)
  return Number(value)
}

/**
 * The content identity of a rule bundle: SHA-256 over the bundle without its version (offsets 16
 * to 24) and its Ed25519 footer. It still covers the format, the size, the signing key id and
 * every source byte, so the same rules packed under another version share it.
 */
export function ruleBundleContentId(bytes: Buffer): string {
  return new Bun.CryptoHasher('sha256')
    .update(bytes.subarray(8, 16))
    .update(bytes.subarray(24, bytes.length - 64))
    .digest('hex')
}

/**
 * Check a rule bundle's frame and its Ed25519 footer against `publicKey`. `bytes` is the whole
 * bundle (at most 16 MiB). Layout: zig-anti-virus docs/rules/guardian.md, "Bundle format".
 */
export function inspectRuleBundle(bytes: Buffer, publicKey: Uint8Array): ArtifactFacts {
  assertMagic('rules', bytes)
  if (bytes.length < 40 + 64 || bytes.length > MAX_RULES_BYTES)
    throw new FeedError('artifact', 'rule bundle size is out of range')
  if (bytes.readUInt32LE(8) !== 1)
    throw new FeedError('artifact', 'rule bundle format version is not 1')
  const version = u64(bytes, 16)
  if (version < 1 || version > 0xFFFFFFFF)
    throw new FeedError('artifact', 'rule bundle version is out of range')
  if (u64(bytes, 24) !== bytes.length)
    throw new FeedError('artifact', 'rule bundle size does not match its header')
  const keyId = bytes.subarray(32, 40).toString('hex')
  if (keyId !== keyIdOf(publicKey))
    throw new FeedError('wrong-key', `rule bundle is signed by key ${keyId}, not ${keyIdOf(publicKey)}`)
  const body = bytes.subarray(0, bytes.length - 64)
  if (!ed25519Verify(publicKey, body, bytes.subarray(bytes.length - 64)))
    throw new FeedError('bad-signature', 'rule bundle signature does not verify')
  return { version, keyId, contentId: ruleBundleContentId(bytes) }
}

/** The CVE index header: the first 4096 bytes of a `.zavcve` (zig-anti-virus src/db/format.zig). */
export const CVE_HEADER_BYTES = 4096
const CVE_KEY_ID_OFFSET = 288
const CVE_SIGNATURE_OFFSET = 296
const CVE_SECTION_TABLE_OFFSET = 512

/**
 * The content identity of a CVE index: SHA-256 over its header without `db_version` and
 * `build_unix_time` (offsets 24 to 40, both the compile time) and without the signature, plus the
 * section table. What remains covers the format, flags, total size, sources, the section table
 * and its hash, the BLAKE3 root of the whole body and the signing key id. zav compiles the body
 * deterministically, so unchanged feeds give the same identity at any time; a changed record,
 * or a different signing key, gives a new one.
 */
export function cveContentId(head: Buffer): string {
  return new Bun.CryptoHasher('sha256')
    .update(head.subarray(8, 24))
    .update(head.subarray(40, CVE_SIGNATURE_OFFSET))
    .update(head.subarray(CVE_SECTION_TABLE_OFFSET, CVE_HEADER_BYTES))
    .digest('hex')
}

/**
 * Check a CVE index header. `head` is at least its first 4096 bytes, `size` the whole file's
 * length. A signed index must be signed by `publicKey`; an unsigned one is accepted only when
 * `allowUnsigned` is set (the outer manifest signature and SHA-256 still bind its bytes).
 */
export function inspectCveHeader(head: Buffer, size: number, publicKey: Uint8Array, allowUnsigned: boolean): ArtifactFacts {
  assertMagic('cve', head)
  if (head.length < CVE_HEADER_BYTES || size < CVE_HEADER_BYTES || size > MAX_CVE_BYTES)
    throw new FeedError('artifact', 'CVE index size is out of range')
  if (head.readUInt16LE(8) !== 1 || head.readUInt32LE(12) !== CVE_HEADER_BYTES)
    throw new FeedError('artifact', 'CVE index header is not format 1')
  const version = u64(head, 24)
  if (version < 1)
    throw new FeedError('artifact', 'CVE index version is not positive')
  if (u64(head, 40) !== size)
    throw new FeedError('artifact', 'CVE index size does not match its header')
  const idBytes = head.subarray(CVE_KEY_ID_OFFSET, CVE_KEY_ID_OFFSET + 8)
  if (idBytes.every(b => b === 0)) {
    if (!allowUnsigned)
      throw new FeedError('bad-signature', 'CVE index is unsigned (compile it with --signing-key)')
    return { version, keyId: null, contentId: cveContentId(head) }
  }
  const keyId = idBytes.toString('hex')
  if (keyId !== keyIdOf(publicKey))
    throw new FeedError('wrong-key', `CVE index is signed by key ${keyId}, not ${keyIdOf(publicKey)}`)
  if (!ed25519Verify(publicKey, head.subarray(0, CVE_SIGNATURE_OFFSET), head.subarray(CVE_SIGNATURE_OFFSET, CVE_SIGNATURE_OFFSET + 64)))
    throw new FeedError('bad-signature', 'CVE index header signature does not verify')
  return { version, keyId, contentId: cveContentId(head) }
}

const CVE_SECTION_COUNT_OFFSET = 48
const CVE_TABLE_OFFSET_FIELD = 52
const CVE_TABLE_XXH3_OFFSET = 120
const CVE_ROOT_OFFSET = 256
const CVE_TAIL_OFFSET = CVE_SIGNATURE_OFFSET + 64
const CVE_SECTION_ENTRY_BYTES = 64
const CVE_MAX_SECTIONS = (CVE_HEADER_BYTES - CVE_SECTION_TABLE_OFFSET) / CVE_SECTION_ENTRY_BYTES

function allZero(bytes: Uint8Array): boolean {
  for (const b of bytes) {
    if (b !== 0)
      return false
  }
  return true
}

/**
 * Check a whole CVE index: its header (`inspectCveHeader`), then everything the header signature
 * does not cover by itself. zav's `Index.open` checks only the header, so this is what makes a
 * blob safe to swap in:
 *
 * - the section table hashes to the signed `section_table_xxh3`, and its entries are in bounds,
 *   aligned and disjoint (the checks zav's reader makes on open);
 * - the unsigned header tail (bytes 360 to 512) and the unused end of the section table are zero;
 * - BLAKE3 over every byte from 4096 to the end equals the signed `blake3_root`.
 *
 * The root binds every body byte to the signature, so the per-section xxh3 values, computed from
 * the same bytes when zav wrote them, need no separate pass. The body is streamed, so memory stays
 * flat whatever the index size.
 */
export function inspectCveIndex(path: string, publicKey: Uint8Array, allowUnsigned: boolean): ArtifactFacts {
  const fd = openSync(path, 'r')
  try {
    const size = fstatSync(fd).size
    const head = Buffer.alloc(CVE_HEADER_BYTES)
    const got = readFully(fd, head, 0)
    const facts = inspectCveHeader(head.subarray(0, got), size, publicKey, allowUnsigned)

    const count = head.readUInt32LE(CVE_SECTION_COUNT_OFFSET)
    if (head.readUInt32LE(CVE_TABLE_OFFSET_FIELD) !== CVE_SECTION_TABLE_OFFSET || count > CVE_MAX_SECTIONS)
      throw new FeedError('artifact', 'CVE index section table is malformed')
    const tableEnd = CVE_SECTION_TABLE_OFFSET + count * CVE_SECTION_ENTRY_BYTES
    if (Bun.hash.xxHash3(head.subarray(CVE_SECTION_TABLE_OFFSET, tableEnd)) !== head.readBigUInt64LE(CVE_TABLE_XXH3_OFFSET))
      throw new FeedError('artifact', 'CVE index section table does not match its signed hash')
    if (!allZero(head.subarray(CVE_TAIL_OFFSET, CVE_SECTION_TABLE_OFFSET)) || !allZero(head.subarray(tableEnd)))
      throw new FeedError('artifact', 'CVE index has data in header bytes no signature covers')

    const sections: { offset: number, size: number }[] = []
    for (let i = 0; i < count; i++) {
      const entry = head.subarray(CVE_SECTION_TABLE_OFFSET + i * CVE_SECTION_ENTRY_BYTES)
      const offset = u64(entry, 8)
      const length = u64(entry, 16)
      const alignLog2 = entry[32]!
      if (offset < CVE_HEADER_BYTES || offset > size || length > size - offset)
        throw new FeedError('artifact', 'CVE index section is out of bounds')
      if (alignLog2 < 12 || alignLog2 > 30 || offset % 2 ** alignLog2 !== 0)
        throw new FeedError('artifact', 'CVE index section is misaligned')
      sections.push({ offset, size: length })
    }
    sections.sort((a, b) => a.offset - b.offset)
    for (let i = 1; i < sections.length; i++) {
      if (sections[i]!.offset < sections[i - 1]!.offset + sections[i - 1]!.size)
        throw new FeedError('artifact', 'CVE index sections overlap')
    }

    const hasher = new Blake3()
    const buffer = Buffer.allocUnsafe(1024 * 1024)
    let position = CVE_HEADER_BYTES
    while (position < size) {
      const read = readSync(fd, buffer, 0, Math.min(buffer.length, size - position), position)
      if (read === 0)
        throw new FeedError('artifact', 'CVE index ended early')
      hasher.update(buffer.subarray(0, read))
      position += read
    }
    if (!Buffer.from(hasher.digest()).equals(head.subarray(CVE_ROOT_OFFSET, CVE_ROOT_OFFSET + 32)))
      throw new FeedError('artifact', 'CVE index body does not match its signed BLAKE3 root')
    return facts
  }
  finally {
    closeSync(fd)
  }
}

function readFully(fd: number, into: Buffer, position: number): number {
  let total = 0
  while (total < into.length) {
    const read = readSync(fd, into, total, into.length - total, position + total)
    if (read === 0)
      break
    total += read
  }
  return total
}

// --- conditional requests -------------------------------------------------------------------

/** A strong entity tag for a hex digest. */
export function strongEtag(hex: string): string {
  return `"${hex}"`
}

/**
 * Whether an `If-None-Match` header matches `etag` (RFC 9110 13.1.2: weak comparison, `*`
 * matches any current representation).
 */
export function ifNoneMatchMatches(header: string | null | undefined, etag: string): boolean {
  if (!header)
    return false
  if (header.trim() === '*')
    return true
  const bare = etag.replace(/^W\//, '')
  return header.split(',').some(tag => tag.trim().replace(/^W\//, '') === bare)
}

/**
 * Whether an `If-Match` header matches `etag` (RFC 9110 13.1.1: strong comparison, so a weak tag
 * never matches; `*` matches any current representation).
 */
export function ifMatchMatches(header: string, etag: string): boolean {
  if (header.trim() === '*')
    return true
  return header.split(',').some(tag => tag.trim() === etag)
}
