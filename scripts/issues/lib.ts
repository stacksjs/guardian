// Shared parsing for the multi-repository issue graph.
//
// OUTLINE.txt holds keys, repositories, titles, labels and dependencies; bodies-*.json hold the
// goal, scope and acceptance criteria; outline.config.ts holds the repository aliases and the label
// vocabularies. Generalised from zig-utils/zig-routing's single-repository tooling.
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { AREAS, REPOS, SIZES, TYPES } from './outline.config'

export const DIR = import.meta.dir

export interface Phase { id: string, n: number, milestone: string, goal: string }
export interface Issue {
  key: string
  phase: string
  /** owner/name the issue lives in. */
  repo: string
  /** Set when the outline points at an issue that already exists instead of creating one. */
  existing?: number
  title: string
  area: string
  type: string
  size: string
  blockers: string[]
  flags: string[]
}
export interface Body {
  key: string
  goal: string
  refs?: string[]
  scope?: string[]
  out_of_scope?: string[]
  notes?: string[]
  accept?: string[]
}

/** Resolve an outline repository cell: `alias`, `owner/name`, or either followed by `#N`. */
export function parseRepoCell(cell: string): { repo: string, existing?: number } {
  const [name, number] = cell.split('#')
  const repo = REPOS[name!] ?? name!
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error(`Unknown repository "${cell}"`)
  return number ? { repo, existing: Number(number) } : { repo }
}

export function loadOutline(): { phases: Phase[], issues: Issue[] } {
  const phases: Phase[] = []
  const issues: Issue[] = []
  const seen = new Set<string>()
  for (const raw of readFileSync(join(DIR, 'OUTLINE.txt'), 'utf8').split('\n')) {
    const line = raw.trim()
    if (!line) continue
    if (line.startsWith('## ')) {
      const [id, milestone, goal] = line.slice(3).split('|').map(part => part.trim())
      phases.push({ id: id!, n: Number(id!.slice(1)), milestone: milestone!, goal: goal ?? '' })
      continue
    }
    if (line.startsWith('#')) continue
    const parts = line.split('|').map(part => part.trim())
    const [key, repoCell, title, area, type, size, blocked, flags] = parts
    if (!key || !repoCell || !title || !area || !type || !size) throw new Error(`Bad outline line: ${line}`)
    if (!/^P\d+\.\d+$/.test(key)) throw new Error(`Bad key ${key}`)
    if (seen.has(key)) throw new Error(`Duplicate key ${key}`)
    if (!(area in AREAS)) throw new Error(`${key}: unknown area ${area}`)
    if (!(type in TYPES)) throw new Error(`${key}: unknown type ${type}`)
    if (!SIZES.includes(size)) throw new Error(`${key}: unknown size ${size}`)
    const phase = key.split('.')[0]!
    if (!phases.some(candidate => candidate.id === phase)) throw new Error(`${key}: phase ${phase} has no header above it`)
    const blockers = !blocked || blocked === '-' ? [] : blocked.split(/\s+/)
    for (const blocker of blockers) {
      if (!seen.has(blocker)) throw new Error(`${key} is blocked by ${blocker}, which is not above it`)
    }
    seen.add(key)
    const { repo, existing } = parseRepoCell(repoCell)
    issues.push({ key, phase, repo, existing, title, area, type, size, blockers, flags: flags ? flags.split(/\s+/) : [] })
  }
  return { phases, issues }
}

export function loadBodies(): Map<string, Body> {
  const bodies = new Map<string, Body>()
  for (const file of readdirSync(DIR).filter(name => /^bodies-.*\.json$/.test(name)).sort()) {
    for (const body of JSON.parse(readFileSync(join(DIR, file), 'utf8')) as Body[]) {
      if (bodies.has(body.key)) throw new Error(`Duplicate body for ${body.key} (${file})`)
      bodies.set(body.key, body)
    }
  }
  return bodies
}

/** `owner/name#N` references, as stored in created.json. */
export type Ref = string
export const ref = (repo: string, number: number): Ref => `${repo}#${number}`
export function splitRef(value: Ref): { repo: string, number: number } {
  const at = value.lastIndexOf('#')
  return { repo: value.slice(0, at), number: Number(value.slice(at + 1)) }
}

export function gh(args: string[], input?: string): string {
  const result = Bun.spawnSync(['gh', ...args], { stdin: input === undefined ? undefined : new TextEncoder().encode(input) })
  const out = result.stdout.toString()
  if (result.exitCode !== 0) throw new Error(`gh ${args.slice(0, 3).join(' ')} failed: ${result.stderr.toString().trim()}`)
  return out
}

export const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

export async function withRetry<T>(what: string, run: () => T): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return run()
    }
    catch (error) {
      if (attempt >= 6) throw error
      const wait = 60_000 * attempt
      console.error(`${what}: ${(error as Error).message}. Waiting ${wait / 1000}s (attempt ${attempt}).`)
      await sleep(wait)
    }
  }
}
