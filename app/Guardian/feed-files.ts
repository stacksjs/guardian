/**
 * Durable file steps for feed artifacts, shared by the publish path and the host updater: write
 * to a temporary file beside the target, fsync it, rename it into place, fsync the directory.
 * A crash at any point leaves either the old file or the new one, never a partial one.
 */
import { createHash, randomBytes } from 'node:crypto'
import { closeSync, fstatSync, fsyncSync, linkSync, openSync, readFileSync, readSync, renameSync, statSync, unlinkSync, writeFileSync, writeSync } from 'node:fs'
import { hostname } from 'node:os'
import { basename, dirname, join } from 'node:path'
import process from 'node:process'
import { FeedError } from './feed-format'

/** A temporary path in the same directory as `target`, so the final rename never crosses filesystems. */
export function tempPathBeside(target: string): string {
  return join(dirname(target), `.${basename(target)}.tmp-${randomBytes(6).toString('hex')}`)
}

/** Flush a directory entry change (a rename) to disk. Windows has no directory fsync. */
export function fsyncDirectory(dir: string): void {
  if (process.platform === 'win32')
    return
  const fd = openSync(dir, 'r')
  try {
    fsyncSync(fd)
  }
  finally {
    closeSync(fd)
  }
}

export function removeQuietly(path: string): void {
  try {
    unlinkSync(path)
  }
  catch {}
}

export interface WrittenFile {
  size: number
  sha256: string
}

/**
 * Stream `body` into a new file at `path` (created exclusively, mode 0644), hashing as it goes,
 * then fsync it. More than `maxBytes` is refused with `size` and the partial file removed.
 */
export async function writeStreamDurably(body: ReadableStream<Uint8Array>, path: string, maxBytes: number): Promise<WrittenFile> {
  const fd = openSync(path, 'wx', 0o644)
  const hash = createHash('sha256')
  let size = 0
  const reader = body.getReader()
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done)
        break
      size += value.byteLength
      if (size > maxBytes)
        throw new FeedError('size', `more than ${maxBytes} bytes`)
      hash.update(value)
      let offset = 0
      while (offset < value.byteLength)
        offset += writeSync(fd, value, offset, value.byteLength - offset)
    }
    fsyncSync(fd)
  }
  catch (error) {
    await reader.cancel().catch(() => {})
    closeSync(fd)
    removeQuietly(path)
    throw error
  }
  closeSync(fd)
  return { size, sha256: hash.digest('hex') }
}

/** Copy a local file into a new durable file, hashing it on the way. */
export function copyFileDurably(source: string, path: string, maxBytes: number): WrittenFile {
  const input = openSync(source, 'r')
  let output: number | null = null
  try {
    if (fstatSync(input).size > maxBytes)
      throw new FeedError('size', `${source} is larger than ${maxBytes} bytes`)
    output = openSync(path, 'wx', 0o644)
    const hash = createHash('sha256')
    const buffer = Buffer.allocUnsafe(1024 * 1024)
    let size = 0
    while (true) {
      const read = readSync(input, buffer, 0, buffer.length, null)
      if (read === 0)
        break
      size += read
      if (size > maxBytes)
        throw new FeedError('size', `${source} is larger than ${maxBytes} bytes`)
      hash.update(buffer.subarray(0, read))
      let offset = 0
      while (offset < read)
        offset += writeSync(output, buffer, offset, read - offset)
    }
    fsyncSync(output)
    return { size, sha256: hash.digest('hex') }
  }
  catch (error) {
    if (output !== null) {
      closeSync(output)
      output = null
      removeQuietly(path)
    }
    throw error
  }
  finally {
    if (output !== null)
      closeSync(output)
    closeSync(input)
  }
}

/** The first `length` bytes of a file (fewer if it is shorter). */
export function readHead(path: string, length: number): Buffer {
  const fd = openSync(path, 'r')
  try {
    const buffer = Buffer.alloc(length)
    let total = 0
    while (total < length) {
      const read = readSync(fd, buffer, total, length - total, total)
      if (read === 0)
        break
      total += read
    }
    return buffer.subarray(0, total)
  }
  finally {
    closeSync(fd)
  }
}

/** Rename a finished temporary file over `target` and make the rename durable. */
export function commitFile(temp: string, target: string): void {
  renameSync(temp, target)
  fsyncDirectory(dirname(target))
}

/** SHA-256 of an open file's first `size` bytes, streamed. */
export function sha256OfFd(fd: number, size: number): string {
  const hash = createHash('sha256')
  const buffer = Buffer.allocUnsafe(1024 * 1024)
  let position = 0
  while (position < size) {
    const read = readSync(fd, buffer, 0, Math.min(buffer.length, size - position), position)
    if (read === 0)
      break
    hash.update(buffer.subarray(0, read))
    position += read
  }
  return hash.digest('hex')
}

// --- lock files -----------------------------------------------------------------------------

const STALE_LOCK_MS = 12 * 3_600_000
/** When this process started, so a lock left by an earlier process that had our PID is stale. */
const PROCESS_STARTED = Math.round(performance.timeOrigin)

interface LockHolder {
  pid?: number
  host?: string
  started?: number
  token?: string
}

/** The lock's holder; null when it is unreadable as a lock, undefined when there is no lock. */
function readLock(path: string): LockHolder | null | undefined {
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  }
  catch {
    return undefined
  }
  try {
    const parsed = JSON.parse(text) as unknown
    return parsed && typeof parsed === 'object' ? parsed as LockHolder : null
  }
  catch {
    return null
  }
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  }
  catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM'
  }
}

function lockIsStale(path: string, holder: LockHolder | null): boolean {
  let age: number
  try {
    age = Date.now() - statSync(path).mtimeMs
  }
  catch {
    return false
  }
  // A lock is written whole before it appears (see acquireLock), so one that does not parse is
  // debris, not a lock being written.
  if (age >= STALE_LOCK_MS || holder === null || typeof holder.pid !== 'number')
    return true
  if (holder.host !== undefined && holder.host !== hostname())
    return false
  if (holder.pid === process.pid)
    return holder.started !== PROCESS_STARTED
  return !processAlive(holder.pid)
}

/**
 * Take an exclusive lock file, or throw `locked`. Returns the release function.
 *
 * The lock is written to a temporary file and hard-linked into place, so it never exists without
 * its holder (pid, host, process start time and a random token). A lock is stale, and taken over,
 * when it is twelve hours old, does not parse, or names a dead process on this host or an earlier
 * process that had this one's pid. A takeover first renames the stale lock aside and checks it is
 * still the one judged stale, so a lock another process took in the meantime is put back rather
 * than deleted. Release removes the lock only while it still carries this holder's token.
 */
export function acquireLock(path: string, what: string): () => void {
  const token = randomBytes(16).toString('hex')
  const body = JSON.stringify({ pid: process.pid, host: hostname(), started: PROCESS_STARTED, token, at: new Date().toISOString() })
  for (let attempt = 0; attempt < 3; attempt++) {
    const temp = tempPathBeside(path)
    writeFileSync(temp, body, { mode: 0o600, flag: 'wx' })
    try {
      linkSync(temp, path)
      return () => {
        if (readLock(path)?.token === token)
          removeQuietly(path)
      }
    }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST')
        throw error
    }
    finally {
      removeQuietly(temp)
    }
    const holder = readLock(path)
    if (holder === undefined)
      continue
    if (!lockIsStale(path, holder))
      break
    const aside = tempPathBeside(path)
    try {
      renameSync(path, aside)
    }
    catch {
      continue
    }
    const moved = readLock(aside)
    if (moved === null ? holder === null : moved?.token === holder?.token) {
      removeQuietly(aside)
      continue
    }
    // Someone took the lock between our read and the rename: give it back.
    try {
      linkSync(aside, path)
    }
    catch {}
    removeQuietly(aside)
    break
  }
  throw new FeedError('locked', `${what} is already running (lock file ${path})`)
}
