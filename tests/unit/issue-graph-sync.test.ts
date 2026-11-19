import { afterEach, describe, expect, test } from 'bun:test'
import { chmodSync, copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

// Exercise the CLI and its gh process boundary. This catches unsafe label writes and failure
// handling; GitHub token permissions and scheduled delivery still need live workflow validation.
const fixtures: string[] = []
afterEach(() => {
  for (const dir of fixtures.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function runSync(args: string[], fixture: { failRepo?: string, nullIssue?: string, available?: boolean, failEdit?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-issue-graph-'))
  fixtures.push(dir)
  for (const file of ['sync-ready.ts', 'lib.ts', 'outline.config.ts'])
    copyFileSync(resolve('scripts/issues', file), join(dir, file))
  writeFileSync(join(dir, 'OUTLINE.txt'), `## P0 | Setup | Fixture
P0.01 | zig-utils/zig-anti-virus | Closed blocker | graph | infra | S | -
P0.02 | guardian | Known ready | graph | infra | S | P0.01
P0.03 | stacksjs/attic | Unknown blocker | graph | infra | S | -
P0.04 | guardian | Unknown blocked | graph | infra | S | P0.03
P0.05 | zig-utils/zig-anti-virus | Remote ready | graph | infra | S | -
`)
  writeFileSync(join(dir, 'created.json'), JSON.stringify({
    'P0.01': 'zig-utils/zig-anti-virus#1',
    'P0.02': 'stacksjs/guardian#2',
    'P0.03': 'stacksjs/attic#3',
    'P0.04': 'stacksjs/guardian#4',
    'P0.05': 'zig-utils/zig-anti-virus#5',
  }))
  const calls = join(dir, 'calls.jsonl')
  writeFileSync(join(dir, 'gh'), `#!${process.execPath}
const args = process.argv.slice(2)
if (args[0] !== 'api') {
  if (process.env.GRAPH_TEST_FAIL_EDIT === '1') process.exit(1)
  require('node:fs').appendFileSync(process.env.GH_CALLS, JSON.stringify(args) + '\\n')
  process.exit(0)
}
const query = args.at(-1)
const repo = query.match(/owner: "([^"]+)", name: "([^"]+)"/).slice(1).join('/')
if ((repo === 'stacksjs/attic' && process.env.GRAPH_TEST_AVAILABLE !== '1') || repo === process.env.GRAPH_TEST_FAIL_REPO) {
  console.error('Could not resolve to a Repository with the name ' + repo)
  process.exit(1)
}
const labels = names => ({ nodes: names.map(name => ({ name })) })
const repository = repo === 'stacksjs/guardian'
  ? { i2: { state: 'OPEN', labels: labels(['blocked']) }, i4: { state: 'OPEN', labels: labels(['ready']) } }
  : repo === 'stacksjs/attic'
    ? { i3: { state: 'CLOSED', labels: labels([]) } }
    : { i1: { state: 'CLOSED', labels: labels([]) }, i5: { state: 'OPEN', labels: labels(['blocked']) } }
if (process.env.GRAPH_TEST_NULL_ISSUE) repository[process.env.GRAPH_TEST_NULL_ISSUE] = null
console.log(JSON.stringify({ data: { repository } }))
`)
  chmodSync(join(dir, 'gh'), 0o755)
  const result = Bun.spawnSync([process.execPath, 'sync-ready.ts', ...args], {
    cwd: dir,
    env: {
      ...process.env,
      PATH: `${dir}:${process.env.PATH}`,
      GH_CALLS: calls,
      GRAPH_TEST_FAIL_REPO: fixture.failRepo ?? '',
      GRAPH_TEST_NULL_ISSUE: fixture.nullIssue ?? '',
      GRAPH_TEST_AVAILABLE: fixture.available ? '1' : '',
      GRAPH_TEST_FAIL_EDIT: fixture.failEdit ? '1' : '',
    },
  })
  let edits: string[][] = []
  try {
    edits = readFileSync(calls, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line))
  }
  catch {}
  return { exitCode: result.exitCode, stdout: result.stdout.toString(), stderr: result.stderr.toString(), edits }
}

describe('issue graph readiness CLI', () => {
  test('hub fallback reads public blockers and keeps unavailable blockers blocked', () => {
    const result = runSync(['--repo', 'stacksjs/guardian', '--allow-unavailable-blockers'])
    expect(result.exitCode).toBe(0)
    expect(result.edits).toEqual([
      ['issue', 'edit', '2', '-R', 'stacksjs/guardian', '--add-label', 'ready', '--remove-label', 'blocked'],
      ['issue', 'edit', '4', '-R', 'stacksjs/guardian', '--add-label', 'blocked', '--remove-label', 'ready'],
    ])
    expect(result.stderr).toContain('stacksjs/attic')
    expect(result.stderr).toContain('unknown')
  })

  test('full graph sync fails before writing when an external repository cannot be read', () => {
    const result = runSync([])
    expect(result.exitCode).not.toBe(0)
    expect(result.edits).toEqual([])
    expect(result.stderr).toContain('stacksjs/attic')
  })

  test('fallback still fails when the selected write repository cannot be read', () => {
    const result = runSync(['--repo', 'stacksjs/guardian', '--allow-unavailable-blockers'], { failRepo: 'stacksjs/guardian' })
    expect(result.exitCode).not.toBe(0)
    expect(result.edits).toEqual([])
  })

  test('an unavailable external issue cannot unblock a dependent', () => {
    const result = runSync(['--repo', 'stacksjs/guardian', '--allow-unavailable-blockers'], { available: true, nullIssue: 'i3' })
    expect(result.exitCode).toBe(0)
    expect(result.edits[1]).toEqual(['issue', 'edit', '4', '-R', 'stacksjs/guardian', '--add-label', 'blocked', '--remove-label', 'ready'])
    expect(result.stderr).toContain('stacksjs/attic#3 state is unknown')
  })

  test('full graph sync rejects unavailable issue states', () => {
    const result = runSync([], { available: true, nullIssue: 'i3' })
    expect(result.exitCode).not.toBe(0)
    expect(result.edits).toEqual([])
    expect(result.stderr).toContain('Issue state is unavailable')
  })

  test('full graph sync relabels non-hub issues when all reads succeed', () => {
    const result = runSync([], { available: true })
    expect(result.exitCode).toBe(0)
    expect(result.edits).toContainEqual(['issue', 'edit', '5', '-R', 'zig-utils/zig-anti-virus', '--add-label', 'ready', '--remove-label', 'blocked'])
  })

  test('dry run reports changes without writing labels', () => {
    const result = runSync(['--dry-run', '--repo', 'stacksjs/guardian', '--allow-unavailable-blockers'])
    expect(result.exitCode).toBe(0)
    expect(result.edits).toEqual([])
    expect(result.stdout).toContain('P0.04 -> blocked (dry run)')
  })

  test('label write failures remain fatal during fallback', () => {
    const result = runSync(['--repo', 'stacksjs/guardian', '--allow-unavailable-blockers'], { failEdit: true })
    expect(result.exitCode).not.toBe(0)
  })

  test('unavailable blockers require an explicit write scope', () => {
    const result = runSync(['--allow-unavailable-blockers'])
    expect(result.exitCode).not.toBe(0)
    expect(result.edits).toEqual([])
    expect(result.stderr).toContain('requires --repo')
  })
})
