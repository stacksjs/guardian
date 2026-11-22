import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { createHash, randomBytes } from 'node:crypto'
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { hostname, tmpdir } from 'node:os'
import { join, relative, resolve } from 'node:path'
import process from 'node:process'
import { serverResponse } from '@stacksjs/router'
import { FEED_DIR_ENV, feedDirectory, feedKeyInfo, loadFeedSigningKey, PUBLIC_KEY_ENV, publishedBlobPath, publishFeed, requireFeedSigningKey, SIGNING_KEY_ENV } from '../../app/Guardian/feed'
import type { FeedLogger } from '../../app/Guardian/feed-build'
import { DEFAULT_OSV_ECOSYSTEMS, fetchWithZav, publishRulePack, rebuildCveIndex, runScheduledCveRebuild, ZAV_BIN_ENV, zavEnvironment } from '../../app/Guardian/feed-build'
import { acquireLock } from '../../app/Guardian/feed-files'
import { updateFeed } from '../../app/Guardian/feed-client'
import type { FeedErrorCode, FeedKind, SignedManifest } from '../../app/Guardian/feed-format'
import {
  blake3,
  CLAMAV_MAGIC,
  CVE_MAGIC,
  FeedError,
  ifNoneMatchMatches,
  inspectCveIndex,
  keyIdOf,
  manifestSigningBytes,
  RULES_MAGIC,
  signingKeyFromSeed,
  signManifest,
  verifySignedManifest,
  ZAVDB_MAGIC,
} from '../../app/Guardian/feed-format'
import { createEnrolmentToken, enrolHost } from '../../app/Guardian/ingest'
import { freshDatabase } from '../support/database'
import { cveIndex, resignCveHeader, ruleBundle } from '../support/feed-artifacts'

/**
 * Feed distribution, exercised through the real routes: requests go through the router's
 * `serverResponse` in process (the `host` middleware, rate limits and handlers all run), and the
 * host updater talks to it through an injected `fetch`. No network is used.
 *
 * Real artifacts come from the zav binary: `GUARDIAN_ZAV_BIN`, else the sibling checkout's
 * `zig-anti-virus/zig-out/bin/zav`. Tests that need it are skipped, with the reason printed,
 * when it is absent. The CVE index is compiled, and signed with the feed key, from zav's own
 * fixtures (zig-anti-virus src/cve/fixtures) laid out the way `zav cve fetch` writes them.
 */

const ROOT = resolve(import.meta.dir, '../..')
const ZAV_CHECKOUT = resolve(ROOT, '../zig-anti-virus')
const ZAV = process.env.GUARDIAN_ZAV_BIN || join(ZAV_CHECKOUT, 'zig-out/bin/zav')
const HAVE_ZAV = existsSync(ZAV)
const RULES_DIR = join(ZAV_CHECKOUT, 'rules')
const CVE_FIXTURES = join(ZAV_CHECKOUT, 'src/cve/fixtures')
const HAVE_ARTIFACTS = HAVE_ZAV && existsSync(RULES_DIR) && existsSync(CVE_FIXTURES)
if (!HAVE_ARTIFACTS)
  console.warn(`feed tests: skipping the zav-backed tests: no zav binary at ${ZAV} (set GUARDIAN_ZAV_BIN) or no rules/fixtures in ${ZAV_CHECKOUT}`)

const work = mkdtempSync(join(tmpdir(), 'guardian-feed-'))
const seed = randomBytes(32)
const key = signingKeyFromSeed(seed)
const PUBLIC = key.publicKey.toString('hex')
const attacker = signingKeyFromSeed(randomBytes(32))
const saved = { key: process.env[SIGNING_KEY_ENV], dir: process.env[FEED_DIR_ENV] }

let credential = ''

/** Every blob body a 200 answer carried, to prove nothing but ZAVRULE and ZAVCVE leaves. */
const servedBlobs: Buffer[] = []

async function call(path: string, headers: Record<string, string> = {}): Promise<Response> {
  const response = await serverResponse(new Request(`http://localhost${path}`, { headers: { Accept: 'application/json', ...headers } }))
  if (path.endsWith('/blob') && response.status === 200)
    servedBlobs.push(Buffer.from(await response.clone().arrayBuffer()))
  return response
}

function asHost(path: string, headers: Record<string, string> = {}): Promise<Response> {
  return call(path, { Authorization: `Bearer ${credential}`, ...headers })
}

type Tamper = (path: string, response: Response) => Promise<Response>

/** The host updater's `fetch`, routed into the app, optionally rewriting what the "server" says. */
function hostFetch(tamper?: Tamper, statuses?: number[]) {
  return async (input: string, init: RequestInit): Promise<Response> => {
    const url = new URL(input)
    const response = await call(url.pathname, Object.fromEntries(new Headers(init.headers).entries()))
    statuses?.push(response.status)
    return tamper ? tamper(url.pathname, response) : response
  }
}

function installTarget(name: string) {
  const dir = join(work, 'host', name)
  mkdirSync(dir, { recursive: true })
  return { installPath: join(dir, 'installed.bin'), statePath: join(dir, 'installed.bin.state.json') }
}

function update(kind: FeedKind, target: { installPath: string, statePath: string }, extra: { tamper?: Tamper, publicKey?: string, statuses?: number[], credential?: string } = {}) {
  return updateFeed({
    server: 'http://localhost',
    credential: extra.credential ?? credential,
    kind,
    publicKey: extra.publicKey ?? PUBLIC,
    installPath: target.installPath,
    statePath: target.statePath,
    fetch: hostFetch(extra.tamper, extra.statuses),
  })
}

function snapshot(target: { installPath: string, statePath: string }): string {
  const read = (p: string) => (existsSync(p) ? createHash('sha256').update(readFileSync(p)).digest('hex') : 'absent')
  return `${read(target.installPath)}:${read(target.statePath)}`
}

function leftovers(dir: string): string[] {
  return readdirSync(dir).filter(n => n.includes('.tmp-'))
}

async function expectRefused(promise: Promise<unknown>, code: FeedErrorCode): Promise<void> {
  let caught: unknown
  try {
    await promise
  }
  catch (error) {
    caught = error
  }
  expect(caught).toBeInstanceOf(FeedError)
  expect((caught as FeedError).code).toBe(code)
}

function refusedSync(fn: () => unknown, code: FeedErrorCode): void {
  let caught: unknown
  try {
    fn()
  }
  catch (error) {
    caught = error
  }
  expect(caught).toBeInstanceOf(FeedError)
  expect((caught as FeedError).code).toBe(code)
}

async function runZav(args: string[]): Promise<{ exitCode: number, output: string }> {
  const child = Bun.spawn([ZAV, ...args], { stdout: 'pipe', stderr: 'pipe' })
  const [out, err, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited])
  return { exitCode, output: out + err }
}

/** A copy of the starter rules with one rule file changed, so it packs to new content. */
function editedRules(tag: string): string {
  const edited = join(work, `rules-${tag}`)
  cpSync(RULES_DIR, edited, { recursive: true })
  const yar = join(edited, 'webshell-php', readdirSync(join(edited, 'webshell-php')).find(n => n.endsWith('.yar'))!)
  writeFileSync(yar, `${readFileSync(yar, 'utf8')}\n// ${tag}\n`)
  return edited
}

/** A logger that keeps what it was told, so tests can read the job's messages. */
function captureLog(): FeedLogger & { lines: string[] } {
  const lines: string[] = []
  return { lines, info: (m: string) => lines.push(`info: ${m}`), error: (m: string) => lines.push(`error: ${m}`) }
}

/** Point the feed layer at zav's CVE fixtures instead of the network. */
async function fixtureFeeds(ctx: { feedsDir: string }): Promise<void> {
  mkdirSync(join(ctx.feedsDir, 'kev'), { recursive: true })
  mkdirSync(join(ctx.feedsDir, 'nvd/pages'), { recursive: true })
  mkdirSync(join(ctx.feedsDir, 'osv/npm'), { recursive: true })
  cpSync(join(CVE_FIXTURES, 'kev.json'), join(ctx.feedsDir, 'kev/known_exploited_vulnerabilities.json'))
  cpSync(join(CVE_FIXTURES, 'nvd-cve-2021-44228.json'), join(ctx.feedsDir, 'nvd/pages/0001.json'))
  cpSync(join(CVE_FIXTURES, 'osv-npm.zip'), join(ctx.feedsDir, 'osv/npm/all.zip'))
}

beforeAll(async () => {
  writeFileSync(join(work, 'seed'), seed, { mode: 0o600 })
  process.env[SIGNING_KEY_ENV] = join(work, 'seed')
  process.env[FEED_DIR_ENV] = join(work, 'feeds')
  await freshDatabase()
  credential = enrolHost({ token: createEnrolmentToken('feed'), name: 'feed-host', platform: 'linux' }).credential
})

afterAll(() => {
  for (const [name, value] of [[SIGNING_KEY_ENV, saved.key], [FEED_DIR_ENV, saved.dir]] as const) {
    if (value === undefined)
      delete process.env[name]
    else
      process.env[name] = value
  }
  rmSync(work, { recursive: true, force: true })
})

describe('feed key', () => {
  it('derives key ids the way zav does (BLAKE3 of the public key)', () => {
    // BLAKE3 of the empty input, from the reference test vectors.
    expect(Buffer.from(blake3(new Uint8Array())).toString('hex')).toBe('af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262')
    expect(key.keyId).toMatch(/^[0-9a-f]{16}$/)
    expect(keyIdOf(key.publicKey)).toBe(key.keyId)
  })

  it('hashes with BLAKE3 exactly as Zig\'s std.crypto.hash.Blake3 does, across chunk and tree boundaries', () => {
    // Digests of bytes i % 251, from Zig's std.crypto.hash.Blake3 (the hash zav's writer uses).
    const vectors: [number, string][] = [
      [1, '2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213'],
      [64, '4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98'],
      [65, 'de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee'],
      [1024, '42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7'],
      [1025, 'd00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444'],
      [3073, '7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3'],
      [102400, 'bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085'],
    ]
    for (const [length, digest] of vectors) {
      const input = Uint8Array.from({ length }, (_, i) => i % 251)
      expect(Buffer.from(blake3(input)).toString('hex')).toBe(digest)
    }
  })

  it('is delivered in the enrolment response and at GET /api/feeds/key', async () => {
    const enrolment = enrolHost({ token: createEnrolmentToken('feed'), name: 'feed-host-2', platform: 'macos' })
    expect(enrolment.feedKey).toEqual({ algorithm: 'ed25519', publicKey: PUBLIC, keyId: key.keyId })
    const response = await asHost('/api/feeds/key')
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ algorithm: 'ed25519', publicKey: PUBLIC, keyId: key.keyId })
  })

  it('requires a host credential for every feed endpoint', async () => {
    for (const path of ['/api/feeds/key', '/api/feeds/rules/manifest', '/api/feeds/rules/blob'])
      expect((await call(path)).status).toBe(401)
  })
})

describe('manifest format', () => {
  const manifest = { kind: 'rules' as const, version: 7, sha256: 'a'.repeat(64), size: 4096, createdAt: '2026-11-20T00:00:00.000Z', keyId: key.keyId }

  it('signs one canonical spelling with a domain prefix', () => {
    expect(manifestSigningBytes(manifest).toString('utf8')).toBe(`guardian-feed-manifest-v1\n{"createdAt":"2026-11-20T00:00:00.000Z","keyId":"${key.keyId}","kind":"rules","sha256":"${'a'.repeat(64)}","size":4096,"version":7}`)
    expect(verifySignedManifest(signManifest(manifest, key), key.publicKey)).toEqual(manifest)
  })

  it('refuses an extra field, a changed field and a foreign key', () => {
    const signed = signManifest(manifest, key)
    refusedSync(() => verifySignedManifest({ ...signed, manifest: { ...signed.manifest, extra: 1 } }, key.publicKey), 'manifest')
    refusedSync(() => verifySignedManifest({ ...signed, manifest: { ...signed.manifest, version: 8 } }, key.publicKey), 'bad-signature')
    refusedSync(() => verifySignedManifest(signed, attacker.publicKey), 'wrong-key')
  })

  it('compares If-None-Match the way RFC 9110 says', () => {
    expect(ifNoneMatchMatches('"abc"', '"abc"')).toBe(true)
    expect(ifNoneMatchMatches('W/"abc"', '"abc"')).toBe(true)
    expect(ifNoneMatchMatches('"x", "abc"', '"abc"')).toBe(true)
    expect(ifNoneMatchMatches('*', '"abc"')).toBe(true)
    expect(ifNoneMatchMatches('"abd"', '"abc"')).toBe(false)
    expect(ifNoneMatchMatches(null, '"abc"')).toBe(false)
  })
})

describe('no ClamAV-derived file is ever served', () => {
  function file(name: string, bytes: Buffer): string {
    const path = join(work, name)
    writeFileSync(path, bytes)
    return path
  }

  it('answers 404 for a clamav kind, an unknown kind and a kind with nothing published', async () => {
    SignatureFeed.create({ name: 'clamav-main', source: 'clamav', version: '62', enabled: true })
    for (const kind of ['clamav', 'clamav-main', 'zavdb', 'main.cvd', 'RULES'])
      for (const what of ['manifest', 'blob'])
        expect((await asHost(`/api/feeds/${kind}/${what}`)).status).toBe(404)
    expect((await asHost('/api/feeds/cve/manifest')).status).toBe(404)
  })

  it('refuses a clamav source, and any source a kind is not built from', () => {
    const anything = file('any.bin', Buffer.concat([RULES_MAGIC, Buffer.alloc(200)]))
    refusedSync(() => publishFeed({ kind: 'rules', file: anything, sources: ['clamav'] }), 'source')
    refusedSync(() => publishFeed({ kind: 'rules', file: anything, sources: ['guardian', 'clamav'] }), 'source')
    refusedSync(() => publishFeed({ kind: 'cve', file: anything, sources: ['kev', 'clamav'] }), 'source')
    refusedSync(() => publishFeed({ kind: 'cve', file: anything, sources: ['malwarebazaar'] }), 'source')
    refusedSync(() => publishFeed({ kind: 'rules', file: anything, sources: [] }), 'source')
    refusedSync(() => publishFeed({ kind: 'clamav' as FeedKind, file: anything, sources: ['clamav'] }), 'unknown-kind')
  })

  it('refuses a ClamAV CVD and a zav signature database under either kind', () => {
    const cvd = file('main.cvd', Buffer.concat([CLAMAV_MAGIC, Buffer.from(':20 Nov 2026 00-00 +0000:62:1:90:x:x:x:0'), Buffer.alloc(8192)]))
    const zavdb = file('local.zavdb', Buffer.concat([ZAVDB_MAGIC, Buffer.alloc(8192)]))
    for (const blob of [cvd, zavdb]) {
      refusedSync(() => publishFeed({ kind: 'rules', file: blob, sources: ['guardian'] }), 'magic')
      refusedSync(() => publishFeed({ kind: 'cve', file: blob, sources: ['kev'], allowUnsignedIndex: true }), 'magic')
    }
    expect(SignatureFeed.where('kind', 'rules').count()).toBe(0)
    expect(SignatureFeed.where('kind', 'cve').count()).toBe(0)
    expect(leftovers(feedDirectory())).toEqual([])
  })

  it.skipIf(!HAVE_ZAV)('refuses a real compiled .zavdb', async () => {
    const out = join(work, 'real.zavdb')
    const built = await runZav(['compile', '--guardian', RULES_DIR, '--guardian-version', '1', '--out', out])
    expect(built.exitCode).toBe(0)
    expect(readFileSync(out).subarray(0, 8).equals(ZAVDB_MAGIC)).toBe(true)
    refusedSync(() => publishFeed({ kind: 'rules', file: out, sources: ['guardian'] }), 'magic')
    refusedSync(() => publishFeed({ kind: 'cve', file: out, sources: ['kev'], allowUnsignedIndex: true }), 'magic')
  })
})

describe.skipIf(!HAVE_ARTIFACTS)('rule pack distribution', () => {
  const host = installTarget('rules')
  let v1: { manifest: SignedManifest, blob: Buffer }

  it('publishes a zav rule pack signed with the feed key', async () => {
    const result = await publishRulePack({ source: RULES_DIR, zav: ZAV })
    expect(result.published).toBe(true)
    expect(result.manifest.version).toBe(1)
    const blob = readFileSync(publishedBlobPath('rules').path)
    // zav and Guardian agree on the key id.
    expect(blob.subarray(32, 40).toString('hex')).toBe(key.keyId)
    expect(result.manifest.sha256).toBe(createHash('sha256').update(blob).digest('hex'))
  })

  it('lets a host update from the server, and the host engine accepts what it installed', async () => {
    const statuses: number[] = []
    const result = await update('rules', host, { statuses })
    expect(result).toMatchObject({ status: 'updated', version: 1 })
    expect(statuses).toEqual([200, 200])
    const installed = readFileSync(host.installPath)
    expect(installed.equals(readFileSync(publishedBlobPath('rules').path))).toBe(true)
    const compiled = await runZav(['compile', '--guardian-bundle', host.installPath, '--guardian-key', PUBLIC, '--out', join(work, 'host-compiled.zavdb')])
    expect(compiled.exitCode).toBe(0)
    v1 = { manifest: await (await asHost('/api/feeds/rules/manifest')).json() as SignedManifest, blob: installed }
  })

  it('answers 304 to a matching If-None-Match for the manifest and the blob', async () => {
    const manifest = await asHost('/api/feeds/rules/manifest')
    const blob = await asHost('/api/feeds/rules/blob')
    expect(manifest.status).toBe(200)
    expect(blob.status).toBe(200)
    expect(manifest.headers.get('cache-control')).toBe('private, no-cache')
    const blobEtag = blob.headers.get('etag')!
    expect(blobEtag).toBe(`"${v1.manifest.manifest.sha256}"`)
    for (const [path, etag] of [['/api/feeds/rules/manifest', manifest.headers.get('etag')!], ['/api/feeds/rules/blob', blobEtag]] as const) {
      const again = await asHost(path, { 'If-None-Match': etag })
      expect(again.status).toBe(304)
      expect(await again.text()).toBe('')
      expect(again.headers.get('etag')).toBe(etag)
      expect((await asHost(path, { 'If-None-Match': '"0000"' })).status).toBe(200)
    }
    // And the updater uses it: nothing changed, so no blob is fetched.
    const statuses: number[] = []
    expect(await update('rules', host, { statuses })).toMatchObject({ status: 'current', version: 1 })
    expect(statuses).toEqual([304])
  })

  it('treats the identical blob as a no-op and refuses an older or equal version', async () => {
    const before = await (await asHost('/api/feeds/rules/manifest')).text()
    // zav packs deterministically, so the same source and version is the same blob.
    expect((await publishRulePack({ source: RULES_DIR, zav: ZAV, version: 1 })).published).toBe(false)
    // Different bytes under a version that is not newer.
    await expectRefused(publishRulePack({ source: editedRules('edited'), zav: ZAV, version: 1 }), 'downgrade')
    expect(await (await asHost('/api/feeds/rules/manifest')).text()).toBe(before)
    expect(leftovers(feedDirectory())).toEqual([])
    expect(readdirSync(feedDirectory()).filter(n => n.startsWith('rules-')).length).toBe(1)
  })

  it('publishes nothing for unchanged sources under a new version, so hosts keep getting 304', async () => {
    const before = await (await asHost('/api/feeds/rules/manifest')).text()
    const result = await publishRulePack({ source: RULES_DIR, zav: ZAV })
    expect(result.published).toBe(false)
    expect(result.manifest.version).toBe(1)
    expect(await (await asHost('/api/feeds/rules/manifest')).text()).toBe(before)
    const statuses: number[] = []
    expect(await update('rules', host, { statuses })).toMatchObject({ status: 'current', version: 1 })
    expect(statuses).toEqual([304])
  })

  it('serves 200 with a new ETag after a new publish, and the host moves to it', async () => {
    const oldManifestEtag = (await asHost('/api/feeds/rules/manifest')).headers.get('etag')!
    const oldBlobEtag = `"${v1.manifest.manifest.sha256}"`
    const result = await publishRulePack({ source: editedRules('v2'), zav: ZAV })
    expect(result.manifest.version).toBe(2)
    const manifest = await asHost('/api/feeds/rules/manifest', { 'If-None-Match': oldManifestEtag })
    const blob = await asHost('/api/feeds/rules/blob', { 'If-None-Match': oldBlobEtag })
    expect(manifest.status).toBe(200)
    expect(blob.status).toBe(200)
    expect(manifest.headers.get('etag')).not.toBe(oldManifestEtag)
    expect(blob.headers.get('etag')).toBe(`"${result.manifest.sha256}"`)
    expect(await update('rules', host)).toMatchObject({ status: 'updated', version: 2 })
  })

  describe('a host refuses, keeping its installed file', () => {
    async function refused(code: FeedErrorCode, extra: Parameters<typeof update>[2]): Promise<void> {
      // Forget the ETag so the updater takes the full path every time.
      rmSync(host.statePath, { force: true })
      const before = snapshot(host)
      expect(before.startsWith('absent')).toBe(false)
      await expectRefused(update('rules', host, extra), code)
      expect(snapshot(host)).toBe(before)
      expect(leftovers(join(work, 'host', 'rules'))).toEqual([])
    }

    async function withNewerPublish(): Promise<void> {
      // A real newer version on the server, so each refusal below is about the tampering alone.
      expect((await publishRulePack({ source: editedRules('v3'), zav: ZAV })).published).toBe(true)
    }

    it('a tampered manifest', async () => {
      await withNewerPublish()
      await refused('bad-signature', {
        tamper: async (path, response) => {
          if (!path.endsWith('/manifest'))
            return response
          const body = await response.json() as SignedManifest
          body.manifest.version += 1
          return new Response(JSON.stringify(body), { status: 200, headers: response.headers })
        },
      })
    })

    it('a tampered blob byte', async () => {
      await refused('digest', {
        tamper: async (path, response) => {
          if (!path.endsWith('/blob'))
            return response
          const bytes = Buffer.from(await response.arrayBuffer())
          bytes[bytes.length >> 1]! ^= 0x01
          return new Response(bytes, { status: 200, headers: response.headers })
        },
      })
    })

    it('a manifest signed by another key, under either key id', async () => {
      const resign = (keyId: string): Tamper => async (path, response) => {
        if (!path.endsWith('/manifest'))
          return response
        const body = await response.json() as SignedManifest
        const forged = signManifest({ ...body.manifest, keyId: attacker.keyId }, attacker)
        return new Response(JSON.stringify({ ...forged, manifest: { ...forged.manifest, keyId } }), { status: 200, headers: response.headers })
      }
      await refused('wrong-key', { tamper: resign(attacker.keyId) })
      await refused('bad-signature', { tamper: resign(key.keyId) })
    })

    it('a signed manifest whose version is not the blob\'s own', async () => {
      await refused('artifact', {
        tamper: async (path, response) => {
          if (!path.endsWith('/manifest'))
            return response
          const body = await response.json() as SignedManifest
          return new Response(JSON.stringify(signManifest({ ...body.manifest, version: body.manifest.version + 50 }, key)), { status: 200, headers: response.headers })
        },
      })
    })

    it('a host that pinned a different key', async () => {
      await refused('wrong-key', { publicKey: attacker.publicKey.toString('hex') })
    })

    it('a replayed older version, authentic and correctly signed', async () => {
      await refused('downgrade', {
        tamper: async (path, response) => {
          if (path.endsWith('/manifest'))
            return new Response(JSON.stringify(v1.manifest), { status: 200, headers: { 'Content-Type': 'application/json' } })
          return new Response(new Uint8Array(v1.blob), { status: 200 })
        },
      })
    })

    it('and still updates once the server is honest', async () => {
      expect(await update('rules', host)).toMatchObject({ status: 'updated', version: 3 })
    })
  })

  it('refuses to serve a blob that no longer carries its magic', async () => {
    const blob = publishedBlobPath('rules')
    const original = readFileSync(blob.path)
    try {
      writeFileSync(blob.path, Buffer.concat([ZAVDB_MAGIC, original.subarray(8)]))
      expect((await asHost('/api/feeds/rules/blob')).status).toBe(503)
    }
    finally {
      writeFileSync(blob.path, original)
    }
    expect((await asHost('/api/feeds/rules/blob')).status).toBe(200)
  })

  it('serves only the file publish recorded', async () => {
    const row = SignatureFeed.where('kind', 'rules').first()!
    const recorded = row.path
    try {
      row.update({ path: '../../../database/stacks.sqlite' })
      expect((await asHost('/api/feeds/rules/blob')).status).toBe(500)
    }
    finally {
      SignatureFeed.where('kind', 'rules').first()!.update({ path: recorded })
    }
  })

  it('never serves a ClamAV row, even one carrying a published blob\'s fields', async () => {
    const rules = SignatureFeed.where('kind', 'rules').first()!
    SignatureFeed.create({
      name: 'clamav-daily',
      source: 'clamav',
      version: '27000',
      enabled: true,
      sha256: rules.sha256,
      // Postgres hands a bigint back as a string, which `schema.number()` refuses on the way in.
      size: Number(rules.size),
      path: rules.path,
      manifest: rules.manifest,
      signature: rules.signature,
      keyId: rules.keyId,
    })
    for (const kind of ['clamav-daily', 'clamav'])
      for (const what of ['manifest', 'blob'])
        expect((await asHost(`/api/feeds/${kind}/${what}`)).status).toBe(404)
  })

  it('keeps only the current blob', () => {
    expect(readdirSync(feedDirectory()).filter(n => n.startsWith('rules-'))).toEqual([publishedBlobPath('rules').path.split('/').at(-1)!])
  })
})

describe.skipIf(!HAVE_ARTIFACTS)('CVE index distribution', () => {
  const host = installTarget('cve')
  const workDir = join(work, 'cve-work')
  let firstEtag = ''

  it('publishes only an index signed with the feed key', async () => {
    const unsigned = join(work, 'unsigned.zavcve')
    const feeds = join(work, 'unsigned-feeds')
    await fixtureFeeds({ feedsDir: feeds })
    expect((await runZav(['cve', 'compile', '--feeds', feeds, '--state', join(work, 'unsigned-state'), '--out', unsigned])).exitCode).toBe(0)
    refusedSync(() => publishFeed({ kind: 'cve', file: unsigned, sources: ['kev', 'osv'] }), 'bad-signature')
    const foreignSeed = join(work, 'foreign-seed')
    writeFileSync(foreignSeed, randomBytes(32), { mode: 0o600 })
    const foreign = join(work, 'foreign.zavcve')
    expect((await runZav(['cve', 'compile', '--feeds', feeds, '--state', join(work, 'unsigned-state'), '--out', foreign, '--signing-key', foreignSeed])).exitCode).toBe(0)
    refusedSync(() => publishFeed({ kind: 'cve', file: foreign, sources: ['kev', 'osv'] }), 'wrong-key')
    expect(SignatureFeed.where('kind', 'cve').count()).toBe(0)
  })

  it('refuses a second rebuild while one holds the lock', async () => {
    mkdirSync(workDir, { recursive: true })
    const release = acquireLock(join(workDir, 'rebuild.lock'), 'a test rebuild')
    try {
      await expectRefused(rebuildCveIndex({ zav: ZAV, workDir, fetchFeeds: fixtureFeeds }), 'locked')
      // The scheduled run treats it as a skip, not a failure.
      expect(await runScheduledCveRebuild({ zav: ZAV, workDir, fetchFeeds: fixtureFeeds, log: captureLog() })).toMatchObject({ status: 'skipped' })
    }
    finally {
      release()
    }
    expect(SignatureFeed.where('kind', 'cve').count()).toBe(0)
  })

  it('end to end: the job builds and publishes, a host installs it, and a run with no change gives the host 304', async () => {
    // 1. The scheduled job, with the network step replaced by zav's fixtures.
    const log = captureLog()
    const first = await runScheduledCveRebuild({ zav: ZAV, workDir, fetchFeeds: fixtureFeeds, log })
    expect(first).toMatchObject({ status: 'published', sources: ['kev', 'osv', 'nvd'] })
    expect(log.lines.some(l => l.startsWith('info: [feeds] CVE index version'))).toBe(true)
    expect(existsSync(join(workDir, 'rebuild.lock'))).toBe(false)
    const published = readFileSync(publishedBlobPath('cve').path)
    // Signed by the feed key: zav wrote its key id into the index header.
    expect(published.subarray(288, 296).toString('hex')).toBe(key.keyId)

    // 2. A host updates through the updater and installs it.
    const statuses: number[] = []
    expect(await update('cve', host, { statuses })).toMatchObject({ status: 'updated', version: (first as { version: number }).version })
    expect(statuses).toEqual([200, 200])
    const installed = readFileSync(host.installPath)
    expect(installed.equals(published)).toBe(true)
    expect(installed.subarray(0, 8).equals(CVE_MAGIC)).toBe(true)

    // 3. The host engine opens it only with the pinned key, checking the whole body.
    const empty = join(work, 'empty')
    mkdirSync(empty, { recursive: true })
    const audit = (cveKey: string) => runZav(['audit', '--cve-index', host.installPath, '--cve-key', cveKey, '--state', join(work, 'zav-state'), '--json', empty])
    expect((await audit(PUBLIC)).exitCode).toBe(0)
    const wrong = await audit(attacker.publicKey.toString('hex'))
    expect(wrong.exitCode).toBe(2)
    expect(wrong.output).toContain('UnknownKey')

    // 4. Wait past the compile second, so a republish would carry a newer version, then run the
    //    job again over unchanged feeds: nothing new is published and the host gets 304.
    firstEtag = (await asHost('/api/feeds/cve/manifest')).headers.get('etag')!
    await Bun.sleep(1100)
    const second = await runScheduledCveRebuild({ zav: ZAV, workDir, fetchFeeds: fixtureFeeds, log })
    expect(second).toMatchObject({ status: 'unchanged', version: (first as { version: number }).version })
    expect(log.lines.at(-1)).toContain('unchanged')
    expect((await asHost('/api/feeds/cve/manifest')).headers.get('etag')).toBe(firstEtag)
    const again: number[] = []
    expect(await update('cve', host, { statuses: again })).toMatchObject({ status: 'current' })
    expect(again).toEqual([304])
  })

  it('logs a failed fetch or compile and keeps serving the published index', async () => {
    const before = { etag: firstEtag, blob: readFileSync(publishedBlobPath('cve').path) }
    const failingFetch = async () => {
      throw new FeedError('artifact', 'zav cve fetch failed (exit 1): simulated outage')
    }
    const failingCompile: Parameters<typeof rebuildCveIndex>[0] = {
      zav: ZAV,
      workDir,
      fetchFeeds: fixtureFeeds,
      run: async argv => (argv.includes('compile') ? { exitCode: 1, stdout: '', stderr: 'zav: simulated compile failure' } : { exitCode: 0, stdout: '', stderr: '' }),
    }
    for (const options of [{ zav: ZAV, workDir, fetchFeeds: failingFetch }, failingCompile]) {
      const log = captureLog()
      const result = await runScheduledCveRebuild({ ...options, log })
      expect(result).toMatchObject({ status: 'failed', code: 'artifact' })
      expect(log.lines).toHaveLength(1)
      expect(log.lines[0]).toStartWith('error: [feeds] CVE index rebuild failed (artifact): zav cve ')
      expect(log.lines[0]).toContain('previously published index is still served')
      expect(existsSync(join(workDir, 'rebuild.lock'))).toBe(false)
      expect((await asHost('/api/feeds/cve/manifest')).headers.get('etag')).toBe(before.etag)
      expect(readFileSync(publishedBlobPath('cve').path).equals(before.blob)).toBe(true)
      const statuses: number[] = []
      expect(await update('cve', host, { statuses })).toMatchObject({ status: 'current' })
      expect(statuses).toEqual([304])
    }
  })

  it('publishes a newer version when the feeds change, and the host moves to it', async () => {
    const before = readFileSync(publishedBlobPath('cve').path)
    await Bun.sleep(1100)
    const fewer = async (ctx: { feedsDir: string }) => {
      await fixtureFeeds(ctx)
      rmSync(join(ctx.feedsDir, 'nvd'), { recursive: true, force: true })
    }
    const result = await runScheduledCveRebuild({ zav: ZAV, workDir, fetchFeeds: fewer, nvd: false, log: captureLog() })
    expect(result).toMatchObject({ status: 'published', sources: ['kev', 'osv'] })
    expect(readFileSync(publishedBlobPath('cve').path).equals(before)).toBe(false)
    expect((await asHost('/api/feeds/cve/manifest', { 'If-None-Match': firstEtag })).status).toBe(200)
    expect(await update('cve', host)).toMatchObject({ status: 'updated', version: (result as { version: number }).version })
  })

  it('answers 304 to a matching If-None-Match for the manifest and the blob', async () => {
    for (const path of ['/api/feeds/cve/manifest', '/api/feeds/cve/blob']) {
      const first = await asHost(path)
      expect(first.status).toBe(200)
      expect((await asHost(path, { 'If-None-Match': first.headers.get('etag')! })).status).toBe(304)
    }
  })

  it('checks a zav-compiled index whole: the body against its root, the unsigned tail, the table', () => {
    const published = publishedBlobPath('cve').path
    expect(inspectCveIndex(published, key.publicKey, false).keyId).toBe(key.keyId)
    const original = readFileSync(published)
    for (const [offset, code] of [[original.length - 1, 'artifact'], [8192 + 5, 'artifact'], [400, 'artifact'], [520, 'artifact'], [300, 'bad-signature']] as const) {
      const changed = Buffer.from(original)
      changed[offset]! ^= 0x01
      const copy = join(work, `zav-index-${offset}.zavcve`)
      writeFileSync(copy, changed)
      refusedSync(() => inspectCveIndex(copy, key.publicKey, false), code)
    }
  })

  it('refuses a tampered index byte and installs nothing', async () => {
    const fresh = installTarget('cve-fresh')
    await expectRefused(update('cve', fresh, {
      tamper: async (path, response) => {
        if (!path.endsWith('/blob'))
          return response
        const bytes = Buffer.from(await response.arrayBuffer())
        bytes[5000]! ^= 0x80
        return new Response(bytes, { status: 200 })
      },
    }), 'digest')
    expect(snapshot(fresh)).toBe('absent:absent')
    expect(leftovers(join(work, 'host', 'cve-fresh'))).toEqual([])
  })
})


/** The two published rows, removed so a suite starts from nothing published. */
function deleteFeedRows(): void {
  for (const name of ['guardian-rules', 'guardian-cve-index'])
    SignatureFeed.where('name', name).first()?.delete()
}

function enrolTestHost(name: string): string {
  return enrolHost({ token: createEnrolmentToken(name), name, platform: 'linux' }).credential
}

function artifactFile(name: string, bytes: Buffer): string {
  const path = join(work, name)
  writeFileSync(path, bytes)
  return path
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

/** A server that holds the feed key and signs an honest manifest over `blob`. */
function serveSigned(kind: FeedKind, version: number, blob: Buffer): Tamper {
  return async (path) => {
    if (path.endsWith('/manifest'))
      return Response.json(signManifest({ kind, version, sha256: sha256(blob), size: blob.length, createdAt: new Date().toISOString(), keyId: key.keyId }, key))
    return new Response(new Uint8Array(blob), { status: 200 })
  }
}

/** Run a suite in its own feed directory, with nothing published, as its own host. */
function isolatedFeeds(name: string): { credential: () => string } {
  let hostCredential = ''
  beforeAll(() => {
    process.env[FEED_DIR_ENV] = join(work, `feeds-${name}`)
    deleteFeedRows()
    hostCredential = enrolTestHost(name)
  })
  afterAll(() => {
    deleteFeedRows()
    process.env[FEED_DIR_ENV] = join(work, 'feeds')
  })
  return { credential: () => hostCredential }
}

describe('rule pack distribution, with no zav needed', () => {
  const suite = isolatedFeeds('plain-rules')
  const host = installTarget('plain-rules')
  const as = (path: string, headers: Record<string, string> = {}) => call(path, { Authorization: `Bearer ${suite.credential()}`, ...headers })
  const filesFor = (n: number) => ({ 'test-family/meta.toml': 'name = "test-family"\n', 'test-family/marker.yar': `rule marker_${n} { strings: $a = "guardian-${n}" condition: $a }\n` })
  const publishBundle = (version: number, files = filesFor(version)) =>
    publishFeed({ kind: 'rules', file: artifactFile(`plain-${version}-${randomBytes(4).toString('hex')}.zavrules`, ruleBundle({ version, key, files })), sources: ['guardian'] })
  const hostUpdate = (extra: Parameters<typeof update>[2] = {}) => update('rules', host, { credential: suite.credential(), ...extra })

  it('publishes a bundle, and a host updates from the server', async () => {
    expect(publishBundle(1)).toMatchObject({ published: true, manifest: { kind: 'rules', version: 1 } })
    const statuses: number[] = []
    expect(await hostUpdate({ statuses })).toMatchObject({ status: 'updated', version: 1 })
    expect(statuses).toEqual([200, 200])
    expect(readFileSync(host.installPath).equals(readFileSync(publishedBlobPath('rules').path))).toBe(true)
  })

  it('answers 304 when nothing changed, for the manifest, the blob and the updater', async () => {
    for (const path of ['/api/feeds/rules/manifest', '/api/feeds/rules/blob']) {
      const first = await as(path)
      expect(first.status).toBe(200)
      const again = await as(path, { 'If-None-Match': first.headers.get('etag')! })
      expect(again.status).toBe(304)
      expect(await again.text()).toBe('')
    }
    const statuses: number[] = []
    expect(await hostUpdate({ statuses })).toMatchObject({ status: 'current', version: 1 })
    expect(statuses).toEqual([304])
  })

  it('refuses at publish a bundle not signed by the feed key, whatever key id it names', () => {
    const footer = ruleBundle({ version: 2, key })
    footer[footer.length - 1]! ^= 0x01
    refusedSync(() => publishFeed({ kind: 'rules', file: artifactFile('plain-footer.zavrules', footer), sources: ['guardian'] }), 'bad-signature')
    refusedSync(() => publishFeed({ kind: 'rules', file: artifactFile('plain-foreign.zavrules', ruleBundle({ version: 2, key: attacker })), sources: ['guardian'] }), 'wrong-key')
    refusedSync(() => publishFeed({ kind: 'rules', file: artifactFile('plain-forged.zavrules', ruleBundle({ version: 2, key, signer: attacker })), sources: ['guardian'] }), 'bad-signature')
    expect(publishedBlobPath('rules').version).toBe('1')
  })

  it('refuses a tampered blob byte and keeps the installed file', async () => {
    publishBundle(2)
    const before = snapshot(host)
    await expectRefused(hostUpdate({
      tamper: async (path, response) => {
        if (!path.endsWith('/blob'))
          return response
        const bytes = Buffer.from(await response.arrayBuffer())
        bytes[bytes.length >> 1]! ^= 0x01
        return new Response(bytes, { status: 200 })
      },
    }), 'digest')
    expect(snapshot(host)).toBe(before)
    expect(leftovers(join(work, 'host', 'plain-rules'))).toEqual([])
  })

  it('refuses a bundle whose own signature or key id is wrong, even under an honestly signed manifest', async () => {
    const before = snapshot(host)
    const broken = ruleBundle({ version: 2, key, files: filesFor(2) })
    broken[broken.length - 1]! ^= 0x01
    await expectRefused(hostUpdate({ tamper: serveSigned('rules', 2, broken) }), 'bad-signature')
    await expectRefused(hostUpdate({ tamper: serveSigned('rules', 2, ruleBundle({ version: 2, key: attacker })) }), 'wrong-key')
    expect(snapshot(host)).toBe(before)
  })

  it('keeps a host whose state file was lost current, without downloading again', async () => {
    expect(await hostUpdate()).toMatchObject({ status: 'updated', version: 2 })
    rmSync(host.statePath)
    const statuses: number[] = []
    expect(await hostUpdate({ statuses })).toMatchObject({ status: 'current', version: 2 })
    expect(statuses).toEqual([200])
    const next: number[] = []
    expect(await hostUpdate({ statuses: next })).toMatchObject({ status: 'current', version: 2 })
    expect(next).toEqual([304])
  })

  it('answers 412 to a blob request for a manifest a newer publish replaced', async () => {
    const stale = `"${publishedBlobPath('rules').sha256}"`
    publishBundle(3)
    const response = await as('/api/feeds/rules/blob', { 'If-Match': stale })
    expect(response.status).toBe(412)
    expect(await response.text()).toBe('')
    expect((await as('/api/feeds/rules/blob', { 'If-Match': `"${publishedBlobPath('rules').sha256}"` })).status).toBe(200)
    // The updater: a publish lands between its manifest and blob requests.
    const before = snapshot(host)
    await expectRefused(hostUpdate({
      tamper: async (path, response) => {
        if (path.endsWith('/manifest'))
          publishBundle(4)
        return response
      },
    }), 'http')
    expect(snapshot(host)).toBe(before)
    expect(await hostUpdate()).toMatchObject({ status: 'updated', version: 4 })
  })

  it('restores a published blob lost from disk instead of serving 503 until the sources change', async () => {
    const lost = publishedBlobPath('rules')
    const bytes = readFileSync(lost.path)
    rmSync(lost.path)
    expect((await as('/api/feeds/rules/blob')).status).toBe(503)
    // The identical bundle again: put back under the recorded name; nothing new is published.
    expect(publishFeed({ kind: 'rules', file: artifactFile('plain-again.zavrules', bytes), sources: ['guardian'] }))
      .toMatchObject({ published: false, restored: true, manifest: { version: 4 } })
    expect((await as('/api/feeds/rules/blob')).status).toBe(200)
    // The same rules under a newer version while the blob is intact: still nothing new.
    expect(publishBundle(5, filesFor(4)).published).toBe(false)
    // And with the blob gone, the same rules under a newer version are published as that version.
    rmSync(publishedBlobPath('rules').path)
    expect(publishBundle(5, filesFor(4))).toMatchObject({ published: true, manifest: { version: 5 } })
    expect((await as('/api/feeds/rules/blob')).status).toBe(200)
    // Only the current blob is kept.
    expect(readdirSync(feedDirectory()).filter(n => n.startsWith('rules-'))).toEqual([relative(feedDirectory(), publishedBlobPath('rules').path)])
  })

  it('runs one publish of a kind at a time', () => {
    const release = acquireLock(join(feedDirectory(), '.publish-rules.lock'), 'a test publish')
    try {
      refusedSync(() => publishBundle(99), 'locked')
    }
    finally {
      release()
    }
    expect(publishedBlobPath('rules').version).toBe('5')
  })

  it('serves only the recorded file, intact: not truncated, not swapped, not a symlink', async () => {
    const blob = publishedBlobPath('rules')
    const original = readFileSync(blob.path)
    expect((await as('/api/feeds/rules/blob')).status).toBe(200)
    try {
      writeFileSync(blob.path, original.subarray(0, original.length - 1))
      expect((await as('/api/feeds/rules/blob')).status).toBe(503)
      const swapped = Buffer.from(original)
      swapped[swapped.length >> 1]! ^= 0x01
      writeFileSync(blob.path, swapped)
      expect((await as('/api/feeds/rules/blob')).status).toBe(503)
      // Grown past the recorded size, even with the recorded bytes as its prefix.
      writeFileSync(blob.path, Buffer.concat([original, Buffer.from([0])]))
      expect((await as('/api/feeds/rules/blob')).status).toBe(503)
      rmSync(blob.path)
      symlinkSync(artifactFile('plain-planted.zavrules', original), blob.path)
      expect((await as('/api/feeds/rules/blob')).status).toBe(503)
    }
    finally {
      rmSync(blob.path, { force: true })
      writeFileSync(blob.path, original)
    }
    const served = await as('/api/feeds/rules/blob')
    expect(served.status).toBe(200)
    expect(Buffer.from(await served.arrayBuffer()).equals(original)).toBe(true)
  })

  it('streams the bytes it checked, even when the file is replaced before the body is read', async () => {
    const blob = publishedBlobPath('rules')
    const original = readFileSync(blob.path)
    const response = await serverResponse(new Request('http://localhost/api/feeds/rules/blob', { headers: { Authorization: `Bearer ${suite.credential()}` } }))
    expect(response.status).toBe(200)
    const other = Buffer.from(original)
    other[other.length >> 1]! ^= 0x01
    const replacement = artifactFile('plain-replacement.zavrules', other)
    renameSync(replacement, blob.path)
    try {
      const body = Buffer.from(await response.arrayBuffer())
      servedBlobs.push(body)
      expect(body.equals(original)).toBe(true)
    }
    finally {
      writeFileSync(blob.path, original)
    }
  })

  it('serves nothing from the rules row once it is not an enabled Guardian rules row', async () => {
    for (const change of [{ source: 'clamav' }, { enabled: false }, { kind: 'cve' }] as const) {
      const row = SignatureFeed.where('name', 'guardian-rules').first()!
      const saved = { source: 'guardian', enabled: true, kind: 'rules' } as const
      expect(row).toMatchObject({ source: saved.source, kind: saved.kind })
      try {
        row.update(change)
        for (const what of ['manifest', 'blob'])
          expect((await as(`/api/feeds/rules/${what}`)).status).toBe(404)
      }
      finally {
        SignatureFeed.where('name', 'guardian-rules').first()!.update(saved)
      }
    }
    expect((await as('/api/feeds/rules/manifest')).status).toBe(200)
  })

  it('stops reading a blob at the manifest size', async () => {
    publishBundle(6)
    const size = publishedBlobPath('rules').size
    let pulled = 0
    const before = snapshot(host)
    await expectRefused(hostUpdate({
      tamper: async (path, response) => {
        if (!path.endsWith('/blob'))
          return response
        const endless = new ReadableStream<Uint8Array>({
          pull(controller) {
            pulled += 1 << 20
            if (pulled > 64 << 20)
              controller.close()
            else
              controller.enqueue(new Uint8Array(1 << 20))
          },
        })
        return new Response(endless, { status: 200 })
      },
    }), 'size')
    expect(pulled).toBeLessThanOrEqual(size + (2 << 20))
    expect(snapshot(host)).toBe(before)
    expect(leftovers(join(work, 'host', 'plain-rules'))).toEqual([])
  })

  it('limits each host credential on its own, not every host behind one address', async () => {
    const [first, second] = [enrolTestHost('limit-a'), enrolTestHost('limit-b')]
    let limited = false
    for (let i = 0; i < 130 && !limited; i++) {
      const response = await call('/api/feeds/rules/manifest', { Authorization: `Bearer ${first}` })
      limited = response.status === 429
      if (!limited)
        expect(response.status).toBe(200)
    }
    expect(limited).toBe(true)
    expect((await call('/api/feeds/rules/manifest', { Authorization: `Bearer ${second}` })).status).toBe(200)
  })
})

describe('CVE index distribution, with no zav needed', () => {
  const suite = isolatedFeeds('plain-cve')
  const host = installTarget('plain-cve')
  const hostUpdate = (extra: Parameters<typeof update>[2] = {}) => update('cve', host, { credential: suite.credential(), ...extra })
  const publishIndex = (bytes: Buffer, name = `plain-${randomBytes(4).toString('hex')}.zavcve`) =>
    publishFeed({ kind: 'cve', file: artifactFile(name, bytes), sources: ['kev', 'osv'] })

  it('publishes an index signed with the feed key; a host installs it, then gets 304', async () => {
    expect(publishIndex(cveIndex({ version: 1000, key }))).toMatchObject({ published: true, manifest: { kind: 'cve', version: 1000 } })
    const statuses: number[] = []
    expect(await hostUpdate({ statuses })).toMatchObject({ status: 'updated', version: 1000 })
    expect(statuses).toEqual([200, 200])
    const again: number[] = []
    expect(await hostUpdate({ statuses: again })).toMatchObject({ status: 'current' })
    expect(again).toEqual([304])
  })

  it('refuses at publish an index whose body, table, tail, size or signature is wrong', () => {
    const good = cveIndex({ version: 2000, key })
    const changed = (offset: number) => {
      const out = Buffer.from(good)
      out[offset]! ^= 0x01
      return out
    }
    const withSize = Buffer.from(good)
    withSize.writeBigUInt64LE(BigInt(good.length + 1), 40)
    const withTable = Buffer.from(good)
    withTable[512 + 33] = 1
    const forged = cveIndex({ version: 2000, key: attacker })
    Buffer.from(key.keyId, 'hex').copy(forged, 288)
    const cases: [Buffer, FeedErrorCode][] = [
      [changed(good.length - 1), 'artifact'],
      [changed(400), 'artifact'],
      [resignCveHeader(withTable, key), 'artifact'],
      [resignCveHeader(withSize, key), 'artifact'],
      [changed(300), 'bad-signature'],
      [changed(60), 'bad-signature'],
      [forged, 'bad-signature'],
      [cveIndex({ version: 2000, key: attacker }), 'wrong-key'],
      [cveIndex({ version: 2000, key: null }), 'bad-signature'],
    ]
    for (const [bytes, code] of cases)
      refusedSync(() => publishIndex(bytes), code)
    expect(publishedBlobPath('cve').version).toBe('1000')
    expect(leftovers(feedDirectory())).toEqual([])
  })

  it('refuses a body-tampered or unsigned index under an honestly signed manifest, installing nothing', async () => {
    const before = snapshot(host)
    const tampered = cveIndex({ version: 3000, key })
    tampered[tampered.length - 1]! ^= 0x01
    await expectRefused(hostUpdate({ tamper: serveSigned('cve', 3000, tampered) }), 'artifact')
    await expectRefused(hostUpdate({ tamper: serveSigned('cve', 3000, cveIndex({ version: 3000, key: null })) }), 'bad-signature')
    expect(snapshot(host)).toBe(before)
    expect(leftovers(join(work, 'host', 'plain-cve'))).toEqual([])
  })

  it('publishes nothing for the same content compiled again, unless its blob is gone', async () => {
    expect(publishIndex(cveIndex({ version: 4000, key, records: 'same records\n' })).published).toBe(true)
    expect(publishIndex(cveIndex({ version: 4001, key, records: 'same records\n' })).published).toBe(false)
    rmSync(publishedBlobPath('cve').path)
    expect(publishIndex(cveIndex({ version: 4002, key, records: 'same records\n' }))).toMatchObject({ published: true, manifest: { version: 4002 } })
    expect(await hostUpdate()).toMatchObject({ status: 'updated', version: 4002 })
  })
})

describe('the scheduled CVE rebuild, with zav stubbed', () => {
  isolatedFeeds('plain-job')
  const workDir = join(work, 'plain-job-work')
  let nextVersion = 6000

  /** A runner whose `cve compile` writes a signed index and records what the feeds dir held. */
  function stubRunner(seen: { feeds: string[] }) {
    return async (argv: string[]) => {
      if (argv[1] === 'cve' && argv[2] === 'compile') {
        const feeds = argv[argv.indexOf('--feeds') + 1]!
        const list = (dir: string) => (existsSync(dir) ? readdirSync(dir).map(n => relative(feeds, join(dir, n))) : [])
        seen.feeds = [...list(feeds), ...list(join(feeds, 'osv'))].sort()
        writeFileSync(argv[argv.indexOf('--out') + 1]!, cveIndex({ version: nextVersion++, key, records: `${seen.feeds.join(',')}\n` }))
      }
      return { exitCode: 0, stdout: '', stderr: '' }
    }
  }

  async function staleMirror(ctx: { feedsDir: string, osv: string[], nvd: boolean }, seenFetch: { osv?: string[], nvd?: boolean }): Promise<void> {
    seenFetch.osv = ctx.osv
    seenFetch.nvd = ctx.nvd
    const files: [string, string][] = [['kev/known_exploited_vulnerabilities.json', '{}'], ['nvd/pages/0001.json', '{}'], ['nvd/state.json', '{}'], ['osv/npm/all.zip', 'zip'], ['osv/Maven/all.zip', 'zip']]
    for (const [file, text] of files) {
      mkdirSync(join(ctx.feedsDir, file, '..'), { recursive: true })
      writeFileSync(join(ctx.feedsDir, file), text)
    }
  }

  it('compiles only the configured sources, and names the ones it compiled', async () => {
    const seen = { feeds: [] as string[] }
    const seenFetch: { osv?: string[], nvd?: boolean } = {}
    const log = captureLog()
    const result = await runScheduledCveRebuild({ zav: 'zav', workDir, run: stubRunner(seen), fetchFeeds: ctx => staleMirror(ctx, seenFetch), nvd: false, osv: ['npm'], log })
    expect(result).toMatchObject({ status: 'published', sources: ['kev', 'osv'] })
    expect(seen.feeds).toEqual(['kev', 'osv', 'osv/npm'])
    // With nothing configured, zav's default ecosystems are named explicitly, and NVD is on.
    const saved = process.env.GUARDIAN_CVE_OSV_ECOSYSTEMS
    delete process.env.GUARDIAN_CVE_OSV_ECOSYSTEMS
    try {
      await runScheduledCveRebuild({ zav: 'zav', workDir, run: stubRunner(seen), fetchFeeds: ctx => staleMirror(ctx, seenFetch), log })
    }
    finally {
      if (saved !== undefined)
        process.env.GUARDIAN_CVE_OSV_ECOSYSTEMS = saved
    }
    expect(seenFetch).toEqual({ osv: [...DEFAULT_OSV_ECOSYSTEMS], nvd: true })
    expect(seen.feeds).toEqual(['kev', 'nvd', 'osv', 'osv/npm'])
  })

  it('fails loudly when a feed key is set but zav cannot be run, and skips quietly with no key', async () => {
    const saved = { zav: process.env[ZAV_BIN_ENV], key: process.env[SIGNING_KEY_ENV] }
    const notExecutable = artifactFile('not-zav', Buffer.from('#!/bin/sh\n'))
    try {
      for (const bin of [join(work, 'no-such-zav'), notExecutable]) {
        process.env[ZAV_BIN_ENV] = bin
        const log = captureLog()
        expect(await runScheduledCveRebuild({ workDir, log })).toMatchObject({ status: 'failed', code: 'config' })
        expect(log.lines).toHaveLength(1)
        expect(log.lines[0]).toStartWith('error: [feeds] CVE index rebuild failed (config)')
        expect(log.lines[0]).toContain(ZAV_BIN_ENV)
      }
      delete process.env[SIGNING_KEY_ENV]
      const log = captureLog()
      expect(await runScheduledCveRebuild({ workDir, log })).toMatchObject({ status: 'skipped' })
      expect(log.lines).toEqual([])
    }
    finally {
      for (const [name, value] of [[ZAV_BIN_ENV, saved.zav], [SIGNING_KEY_ENV, saved.key]] as const) {
        if (value === undefined)
          delete process.env[name]
        else
          process.env[name] = value
      }
    }
  })
})

describe('lock files', () => {
  const dir = join(work, 'locks')
  mkdirSync(dir, { recursive: true })
  const lockAt = (name: string) => join(dir, name)
  const fresh = (path: string, holder: Record<string, unknown> | string) => writeFileSync(path, typeof holder === 'string' ? holder : JSON.stringify(holder))

  it('is not removed by a holder that lost it', () => {
    const path = lockAt('lost')
    const release = acquireLock(path, 'a test')
    fresh(path, { pid: process.pid, host: hostname(), started: 1, token: 'someone-else' })
    release()
    expect(existsSync(path)).toBe(true)
  })

  it('takes over a lock of a dead process, of an earlier process with this pid, and debris', async () => {
    const child = Bun.spawn(['true'])
    await child.exited
    for (const [name, holder] of [
      ['dead', { pid: child.pid, host: hostname(), started: 1, token: 'a' }],
      ['reused-pid', { pid: process.pid, host: hostname(), started: 1, token: 'b' }],
      ['empty', ''],
      ['garbage', '{'],
    ] as const) {
      const path = lockAt(name)
      fresh(path, holder)
      const release = acquireLock(path, 'a test')
      expect(JSON.parse(readFileSync(path, 'utf8')).pid).toBe(process.pid)
      release()
      expect(existsSync(path)).toBe(false)
    }
  })

  it('refuses a live holder in this process, and any recent holder on another host', async () => {
    const path = lockAt('live')
    const release = acquireLock(path, 'a test')
    refusedSync(() => acquireLock(path, 'a test'), 'locked')
    release()
    // A pid on another host cannot be checked from here, even one that is dead on this one.
    const child = Bun.spawn(['true'])
    await child.exited
    fresh(path, { pid: child.pid, host: 'another-host', started: 1, token: 'c' })
    refusedSync(() => acquireLock(path, 'a test'), 'locked')
  })
})

describe('the feed key file', () => {
  const seedFile = join(work, 'seed')
  afterAll(() => {
    process.env[SIGNING_KEY_ENV] = seedFile
    delete process.env[PUBLIC_KEY_ENV]
  })

  it('is refused when others can read it or it is not 32 bytes, before it is read', () => {
    for (const [name, bytes, mode] of [['seed-open', seed, 0o640], ['seed-short', seed.subarray(0, 31), 0o600], ['seed-long', Buffer.concat([seed, Buffer.from([0])]), 0o600]] as const) {
      const path = join(work, name)
      writeFileSync(path, bytes)
      chmodSync(path, mode)
      process.env[SIGNING_KEY_ENV] = path
      refusedSync(() => loadFeedSigningKey(), 'config')
    }
    process.env[SIGNING_KEY_ENV] = seedFile
  })

  it('serves its public half without reading the seed again', () => {
    const path = join(work, 'seed-cached')
    writeFileSync(path, seed, { mode: 0o600 })
    process.env[SIGNING_KEY_ENV] = path
    const info = feedKeyInfo()
    expect(info).toEqual({ algorithm: 'ed25519', publicKey: PUBLIC, keyId: key.keyId })
    chmodSync(path, 0o000)
    try {
      expect(feedKeyInfo()).toEqual(info)
    }
    finally {
      chmodSync(path, 0o600)
      process.env[SIGNING_KEY_ENV] = seedFile
    }
  })

  it('can be replaced on serving processes by GUARDIAN_FEED_PUBLIC_KEY, which must match the seed', async () => {
    process.env[SIGNING_KEY_ENV] = join(work, 'no-seed-on-this-process')
    process.env[PUBLIC_KEY_ENV] = PUBLIC
    expect(feedKeyInfo()).toEqual({ algorithm: 'ed25519', publicKey: PUBLIC, keyId: key.keyId })
    expect(enrolHost({ token: createEnrolmentToken('pub-only'), name: 'pub-only', platform: 'linux' }).feedKey).toEqual({ algorithm: 'ed25519', publicKey: PUBLIC, keyId: key.keyId })
    process.env[SIGNING_KEY_ENV] = seedFile
    expect(requireFeedSigningKey().keyId).toBe(key.keyId)
    process.env[PUBLIC_KEY_ENV] = attacker.publicKey.toString('hex')
    refusedSync(() => requireFeedSigningKey(), 'config')
    delete process.env[PUBLIC_KEY_ENV]
  })
})

describe('the zav environment', () => {
  it('passes NVD_API_KEY only when it is configured, and none of the server\'s own secrets', () => {
    const base = { PATH: '/usr/bin', HOME: '/home/guardian', APP_KEY: 'base64:secret', DB_PASSWORD: 'secret', [SIGNING_KEY_ENV]: '/keys/seed' }
    expect(zavEnvironment(base)).toEqual({ PATH: '/usr/bin', HOME: '/home/guardian' })
    expect(zavEnvironment({ ...base, NVD_API_KEY: '' })).toEqual({ PATH: '/usr/bin', HOME: '/home/guardian' })
    expect(zavEnvironment({ ...base, NVD_API_KEY: ' nvd-key ' })).toEqual({ PATH: '/usr/bin', HOME: '/home/guardian', NVD_API_KEY: 'nvd-key' })
  })
})

describe('the default network step', () => {
  it('runs one zav cve fetch with NVD and the configured OSV ecosystems', async () => {
    const calls: string[][] = []
    await fetchWithZav({
      zav: '/opt/zav',
      feedsDir: '/f',
      stateDir: '/s',
      nvd: true,
      osv: ['npm', 'PyPI'],
      run: async (argv) => {
        calls.push(argv)
        return { exitCode: 0, stdout: '', stderr: '' }
      },
    })
    expect(calls).toEqual([['/opt/zav', 'cve', 'fetch', '--feeds', '/f', '--state', '/s', '--nvd', '--osv', 'npm', '--osv', 'PyPI']])
  })
})

describe('every blob served', () => {
  it('is a Guardian rule bundle or a CVE index', () => {
    expect(servedBlobs.length).toBeGreaterThan(0)
    for (const blob of servedBlobs) {
      const magic = blob.subarray(0, 8)
      expect(magic.equals(RULES_MAGIC) || magic.equals(CVE_MAGIC)).toBe(true)
    }
  })
})
