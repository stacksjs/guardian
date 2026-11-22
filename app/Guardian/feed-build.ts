/**
 * Building what app/Guardian/feed.ts publishes, with the zav binary:
 *
 * - `rebuildCveIndex`: `zav cve fetch` (CISA KEV, OSV exports, NVD), `zav cve compile
 *   --signing-key`, then publish. One run per server at a time, under a lock file, on top of the
 *   scheduler's own overlap and one-server guards. The feeds directory persists between runs, so
 *   zav's saved NVD progress makes each later sync incremental, and the whole fetch happens once
 *   per server instead of once per host. NVD gets `NVD_API_KEY` only when it is set, which raises
 *   its rate limit; without one zav paces itself to the public limit. A rebuild whose feeds did
 *   not change compiles the same content and publishes nothing, so hosts keep getting 304.
 * - `runScheduledCveRebuild`: the scheduled job's body. It logs the outcome, and on any failure
 *   (a configured feed key with no usable zav binary among them) logs it and leaves the
 *   published index exactly as it was.
 * - `publishRulePack`: `zav rule-pack` over the configured Guardian source directory, then publish
 *   (`buddy feed:publish-rules`, app/Commands/Feeds.ts).
 *
 * The zav binary is `GUARDIAN_ZAV_BIN`, else `zav` on PATH. zav runs with a small allowlisted
 * environment, never the server's own secrets. The network step and the command runner are
 * injectable, so tests run against fixtures with no network.
 */
import { accessSync, constants, existsSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs'
import { join } from 'node:path'
import process from 'node:process'
import { log as appLog } from '@stacksjs/logging'
import type { PublishResult } from './feed'
import { FEED_ROW_NAME, feedDirectory, feedSigningKeyFile, publishFeed } from './feed'
import { FeedError } from './feed-format'
import { acquireLock, removeQuietly } from './feed-files'

export const ZAV_BIN_ENV = 'GUARDIAN_ZAV_BIN'
export const RULES_SOURCE_ENV = 'GUARDIAN_RULES_SOURCE_DIR'
/** Comma-separated OSV ecosystems; unset means `DEFAULT_OSV_ECOSYSTEMS`. */
export const OSV_ECOSYSTEMS_ENV = 'GUARDIAN_CVE_OSV_ECOSYSTEMS'
/** Set to `false` to leave NVD out of the index. */
export const NVD_ENV = 'GUARDIAN_CVE_NVD'
/** zav's own default ecosystems (`zav cve fetch --help`), named explicitly so pruning can match. */
export const DEFAULT_OSV_ECOSYSTEMS = ['npm', 'PyPI', 'Go', 'crates.io'] as const

export interface CommandResult {
  exitCode: number
  stdout: string
  stderr: string
}

export type CommandRunner = (argv: string[], options?: { timeoutMs?: number }) => Promise<CommandResult>

/** NVD's API key. Passed to zav only when set; zav uses it for NVD requests and nothing else. */
export const NVD_API_KEY_ENV = 'NVD_API_KEY'

/** What zav needs from the environment: a path, a home and temp dir, locale, proxy and CA settings. */
const ZAV_ENV_ALLOWLIST = [
  'PATH',
  'HOME',
  'TMPDIR',
  'LANG',
  'LC_ALL',
  'HTTPS_PROXY',
  'HTTP_PROXY',
  'NO_PROXY',
  'https_proxy',
  'http_proxy',
  'no_proxy',
  'SSL_CERT_FILE',
  'SSL_CERT_DIR',
]

/**
 * The environment zav runs with: the allowlist above, plus `NVD_API_KEY` only when it is set and
 * not empty. Nothing else from the server's environment (its database, app and signing secrets)
 * reaches the child process.
 */
export function zavEnvironment(env: Record<string, string | undefined> = process.env): Record<string, string> {
  const out: Record<string, string> = {}
  for (const name of ZAV_ENV_ALLOWLIST) {
    const value = env[name]
    if (value)
      out[name] = value
  }
  const apiKey = env[NVD_API_KEY_ENV]?.trim()
  if (apiKey)
    out[NVD_API_KEY_ENV] = apiKey
  return out
}

/** Run a command with `zavEnvironment()`. */
export const runCommand: CommandRunner = async (argv, options = {}) => {
  const child = Bun.spawn(argv, { stdin: 'ignore', stdout: 'pipe', stderr: 'pipe', env: zavEnvironment() })
  const timer = options.timeoutMs ? setTimeout(() => child.kill(), options.timeoutMs) : null
  try {
    const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited])
    return { exitCode, stdout, stderr }
  }
  finally {
    if (timer)
      clearTimeout(timer)
  }
}

/**
 * The zav binary: `GUARDIAN_ZAV_BIN`, else `zav` on PATH, else null. A configured path that is
 * not an executable file is null too, never silently replaced by whatever PATH holds.
 */
export function resolveZav(): string | null {
  const configured = process.env[ZAV_BIN_ENV]
  if (configured) {
    try {
      accessSync(configured, constants.X_OK)
      return statSync(configured).isFile() ? configured : null
    }
    catch {
      return null
    }
  }
  return Bun.which('zav')
}

function requireZav(zav?: string): string {
  const bin = zav ?? resolveZav()
  if (!bin) {
    const configured = process.env[ZAV_BIN_ENV]
    throw new FeedError('config', configured
      ? `${ZAV_BIN_ENV} names ${configured}, which is not an executable file`
      : `no zav binary: set ${ZAV_BIN_ENV} or put zav on PATH`)
  }
  return bin
}

function requireKeyFile(): string {
  const file = feedSigningKeyFile()
  if (!file)
    throw new FeedError('config', 'GUARDIAN_FEED_SIGNING_KEY_FILE is not set, so feeds cannot be published')
  return file
}

async function zavStep(run: CommandRunner, argv: string[], what: string, timeoutMs: number): Promise<CommandResult> {
  const result = await run(argv, { timeoutMs })
  if (result.exitCode !== 0)
    throw new FeedError('artifact', `${what} failed (exit ${result.exitCode}): ${result.stderr.trim().slice(0, 2000)}`)
  return result
}

export interface FetchContext {
  zav: string
  feedsDir: string
  stateDir: string
  nvd: boolean
  osv: string[]
  run: CommandRunner
}

/** The default network step: one `zav cve fetch` into the persistent feeds directory. */
export async function fetchWithZav(ctx: FetchContext): Promise<void> {
  const argv = [ctx.zav, 'cve', 'fetch', '--feeds', ctx.feedsDir, '--state', ctx.stateDir]
  if (ctx.nvd)
    argv.push('--nvd')
  for (const ecosystem of ctx.osv)
    argv.push('--osv', ecosystem)
  await zavStep(ctx.run, argv, 'zav cve fetch', 6 * 3_600_000)
}

export interface RebuildOptions {
  zav?: string
  /** Persistent working directory; defaults to `<feed dir>/work/cve`. */
  workDir?: string
  /** Replace the network step (tests copy fixtures in). */
  fetchFeeds?: (ctx: FetchContext) => Promise<void>
  run?: CommandRunner
  nvd?: boolean
  osv?: string[]
}

export type RebuildResult = PublishResult & { sources: string[] }

/**
 * Make the feeds directory hold only what is configured, and name what it holds. zav compiles
 * every feed file it finds, so an NVD mirror left from before `GUARDIAN_CVE_NVD=false`, or an OSV
 * export of an ecosystem no longer configured, would otherwise stay in every index, unrefreshed.
 * Removing `nvd/` removes zav's NVD progress (`nvd/state.json`) with it, so turning NVD back on
 * starts a clean mirror.
 */
export function pruneFeeds(feedsDir: string, nvd: boolean, osv: readonly string[]): string[] {
  if (!nvd)
    rmSync(join(feedsDir, 'nvd'), { recursive: true, force: true })
  const osvDir = join(feedsDir, 'osv')
  const present = existsSync(osvDir) ? readdirSync(osvDir, { withFileTypes: true }) : []
  for (const entry of present) {
    if (!osv.includes(entry.name))
      rmSync(join(osvDir, entry.name), { recursive: true, force: true })
  }
  const sources: string[] = []
  if (existsSync(join(feedsDir, 'kev', 'known_exploited_vulnerabilities.json')))
    sources.push('kev')
  if (osv.some(eco => existsSync(join(osvDir, eco, 'all.zip'))))
    sources.push('osv')
  const pages = join(feedsDir, 'nvd', 'pages')
  if (existsSync(pages) && readdirSync(pages).some(n => n.endsWith('.json')))
    sources.push('nvd')
  return sources
}

/**
 * Fetch, compile and publish the CVE index. The index is always signed with the feed key
 * (`zav cve compile --signing-key`); publish refuses an unsigned one. Any failure leaves the
 * published index as it was: nothing is published until the new index has been compiled and
 * checked.
 */
export async function rebuildCveIndex(options: RebuildOptions = {}): Promise<RebuildResult> {
  const zav = requireZav(options.zav)
  const keyFile = requireKeyFile()
  const run = options.run ?? runCommand
  const workDir = options.workDir ?? join(feedDirectory(), 'work', 'cve')
  const feedsDir = join(workDir, 'feeds')
  const stateDir = join(workDir, 'state')
  mkdirSync(feedsDir, { recursive: true, mode: 0o750 })
  mkdirSync(stateDir, { recursive: true, mode: 0o750 })
  const nvd = options.nvd ?? process.env[NVD_ENV] !== 'false'
  const configuredOsv = (process.env[OSV_ECOSYSTEMS_ENV] ?? '').split(',').map(s => s.trim()).filter(Boolean)
  const osv = options.osv ?? (configuredOsv.length > 0 ? configuredOsv : [...DEFAULT_OSV_ECOSYSTEMS])

  const release = acquireLock(join(workDir, 'rebuild.lock'), 'a CVE index rebuild')
  const out = join(workDir, `cve-${process.pid}.zavcve`)
  try {
    await (options.fetchFeeds ?? fetchWithZav)({ zav, feedsDir, stateDir, nvd, osv, run })
    const sources = pruneFeeds(feedsDir, nvd, osv)
    if (sources.length === 0)
      throw new FeedError('artifact', 'the fetch left no KEV, OSV or NVD data to compile')
    removeQuietly(out)
    await zavStep(run, [zav, 'cve', 'compile', '--feeds', feedsDir, '--state', stateDir, '--out', out, '--signing-key', keyFile], 'zav cve compile', 3_600_000)
    const result = publishFeed({ kind: 'cve', file: out, sources })
    return { ...result, sources }
  }
  finally {
    removeQuietly(out)
    release()
  }
}

export interface FeedLogger {
  info: (message: string) => unknown
  error: (message: string) => unknown
}

export type ScheduledRebuildResult =
  | { status: 'skipped', reason: string }
  | { status: 'published' | 'unchanged', version: number, sha256: string, sources: string[] }
  | { status: 'failed', code: string, message: string }

/**
 * The scheduled rebuild (app/Jobs/RebuildCveIndex.ts). A server with no feed key does not publish
 * feeds, and a run that finds another one holding the lock leaves it alone: both are skips. A
 * server with a feed key but no usable zav binary (unset, a wrong `GUARDIAN_ZAV_BIN`, a PATH
 * without zav) is misconfigured, so that is a logged failure, as is any other. The previously
 * published index, its manifest and its ETags stay exactly as they were, so hosts keep it.
 */
export async function runScheduledCveRebuild(options: RebuildOptions & { log?: FeedLogger } = {}): Promise<ScheduledRebuildResult> {
  const log = options.log ?? appLog
  if (!feedSigningKeyFile())
    return { status: 'skipped', reason: 'GUARDIAN_FEED_SIGNING_KEY_FILE is not set' }
  try {
    const result = await rebuildCveIndex(options)
    const { version, sha256 } = result.manifest
    await log.info(result.published
      ? `[feeds] CVE index version ${version} published (${sha256.slice(0, 16)}, from ${result.sources.join(', ')})`
      : result.restored
        ? `[feeds] CVE index version ${version} was missing or damaged on disk and has been restored`
        : `[feeds] CVE index unchanged; version ${version} stays published`)
    return { status: result.published ? 'published' : 'unchanged', version, sha256, sources: result.sources }
  }
  catch (error) {
    const code = error instanceof FeedError ? error.code : 'error'
    const message = error instanceof Error ? error.message : String(error)
    if (code === 'locked') {
      await log.info(`[feeds] CVE index rebuild skipped: ${message}`)
      return { status: 'skipped', reason: message }
    }
    await log.error(`[feeds] CVE index rebuild failed (${code}): ${message}. The previously published index is still served.`)
    return { status: 'failed', code, message }
  }
}

export interface RulePackOptions {
  /** Guardian source directory; defaults to `GUARDIAN_RULES_SOURCE_DIR`. */
  source?: string
  /** Pack version; defaults to the published version plus one. Unchanged sources publish nothing. */
  version?: number
  zav?: string
  run?: CommandRunner
  workDir?: string
}

/** Sign the Guardian rule source with `zav rule-pack` and publish it. */
export async function publishRulePack(options: RulePackOptions = {}): Promise<PublishResult> {
  const zav = requireZav(options.zav)
  const keyFile = requireKeyFile()
  const source = options.source ?? process.env[RULES_SOURCE_ENV]
  if (!source)
    throw new FeedError('config', `no rule source: pass one or set ${RULES_SOURCE_ENV}`)
  const current = SignatureFeed.where('name', FEED_ROW_NAME.rules).first()
  const version = options.version ?? (current?.kind === 'rules' ? Number(current.version) + 1 : 1)
  if (!Number.isSafeInteger(version) || version < 1 || version > 0xFFFFFFFF)
    throw new FeedError('artifact', 'a rule pack version is a positive 32-bit integer')
  const workDir = options.workDir ?? join(feedDirectory(), 'work', 'rules')
  mkdirSync(workDir, { recursive: true, mode: 0o750 })
  const out = join(workDir, `guardian-${process.pid}-${version}.zavrules`)
  try {
    removeQuietly(out)
    await zavStep(options.run ?? runCommand, [zav, 'rule-pack', '--source', source, '--version', String(version), '--signing-key', keyFile, '--out', out], 'zav rule-pack', 600_000)
    return publishFeed({ kind: 'rules', file: out, sources: ['guardian'] })
  }
  finally {
    removeQuietly(out)
  }
}
