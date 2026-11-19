#!/usr/bin/env bun
// Keeps the `ready` / `blocked` labels true across every repository in the graph: an open issue is
// `ready` when every blocker in OUTLINE.txt is closed, `blocked` otherwise. Issue states are read in
// batched GraphQL queries per repository, so large repositories are never paged through.
//
//   bun scripts/issues/sync-ready.ts [--dry-run] [--repo owner/name [--allow-unavailable-blockers]]
// --repo limits writes, while blockers are still read across the graph. The explicit fallback
// flag permits unavailable external blockers to stay unknown (and therefore blocked).
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { parseArgs } from 'node:util'
import { DIR, gh, loadOutline, splitRef } from './lib'

const { values } = parseArgs({
  args: process.argv.slice(2),
  options: {
    'dry-run': { type: 'boolean' },
    'repo': { type: 'string' },
    'allow-unavailable-blockers': { type: 'boolean' },
  },
})
const dryRun = values['dry-run']
const writeRepo = values.repo
const allowUnavailable = values['allow-unavailable-blockers']
if (allowUnavailable && !writeRepo) throw new Error('--allow-unavailable-blockers requires --repo')
const created: Record<string, string | number> = JSON.parse(readFileSync(join(DIR, 'created.json'), 'utf8'))
const { issues } = loadOutline()

interface State { state: string, labels: string[] }
const states = new Map<string, State>()
const wanted = new Map<string, number[]>()
for (const issue of issues) {
  const value = created[issue.key]
  if (typeof value !== 'string') continue
  const { repo, number } = splitRef(value)
  wanted.set(repo, [...(wanted.get(repo) ?? []), number])
}
if (writeRepo && !wanted.has(writeRepo)) throw new Error(`Repository ${writeRepo} is not in the issue graph`)

for (const [repo, numbers] of wanted) {
  const [owner, name] = repo.split('/')
  for (let i = 0; i < numbers.length; i += 80) {
    const chunk = numbers.slice(i, i + 80)
    const fields = chunk.map(number => `i${number}: issue(number: ${number}) { state labels(first: 50) { nodes { name } } }`).join('\n')
    const query = `query { repository(owner: "${owner}", name: "${name}") { ${fields} } }`
    let repository: Record<string, { state: string, labels: { nodes: Array<{ name: string }> } } | null>
    try {
      const data = JSON.parse(gh(['api', 'graphql', '-f', `query=${query}`]))
      if (!data.data?.repository || data.errors?.length) throw new Error(`Incomplete issue state response for ${repo}`)
      repository = data.data.repository
    }
    catch (error) {
      if (!allowUnavailable || repo === writeRepo) throw error
      console.error(`Warning: ${repo} issue states are unknown; their dependents remain blocked. ${(error as Error).message}`)
      continue
    }
    for (const number of chunk) {
      const node = repository[`i${number}`]
      if (!node || !['OPEN', 'CLOSED'].includes(node.state)) {
        if (!allowUnavailable || repo === writeRepo) throw new Error(`Issue state is unavailable for ${repo}#${number}`)
        console.error(`Warning: ${repo}#${number} state is unknown; its dependents remain blocked.`)
        continue
      }
      states.set(`${repo}#${number}`, { state: node.state, labels: node.labels.nodes.map(label => label.name) })
    }
  }
}

let changed = 0
for (const issue of issues) {
  const value = created[issue.key]
  if (typeof value !== 'string') continue
  const { repo, number } = splitRef(value)
  if (writeRepo && repo !== writeRepo) continue
  const current = states.get(value)
  if (!current || current.state !== 'OPEN') continue
  const open = issue.blockers.filter(key => states.get(String(created[key]))?.state !== 'CLOSED')
  const want = open.length ? 'blocked' : 'ready'
  const drop = open.length ? 'ready' : 'blocked'
  if (current.labels.includes(want) && !current.labels.includes(drop)) continue
  const edit = ['issue', 'edit', String(number), '-R', repo, '--add-label', want]
  if (current.labels.includes(drop)) edit.push('--remove-label', drop)
  if (!dryRun) gh(edit)
  changed++
  console.log(`${value} ${issue.key} -> ${want}${dryRun ? ' (dry run)' : ''}`)
}
console.log(`${changed} issue(s) relabelled`)
