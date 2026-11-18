#!/usr/bin/env bun
// Keeps the `ready` / `blocked` labels true across every repository in the graph: an open issue is
// `ready` when every blocker in OUTLINE.txt is closed, `blocked` otherwise. Issue states are read in
// batched GraphQL queries per repository, so large repositories are never paged through.
//
//   bun scripts/issues/sync-ready.ts [--dry-run]
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { DIR, gh, loadOutline, splitRef } from './lib'

const dryRun = process.argv.includes('--dry-run')
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

for (const [repo, numbers] of wanted) {
  const [owner, name] = repo.split('/')
  for (let i = 0; i < numbers.length; i += 80) {
    const chunk = numbers.slice(i, i + 80)
    const fields = chunk.map(number => `i${number}: issue(number: ${number}) { state labels(first: 50) { nodes { name } } }`).join('\n')
    const query = `query { repository(owner: "${owner}", name: "${name}") { ${fields} } }`
    const data = JSON.parse(gh(['api', 'graphql', '-f', `query=${query}`])) as { data: { repository: Record<string, { state: string, labels: { nodes: Array<{ name: string }> } } | null> } }
    for (const number of chunk) {
      const node = data.data.repository[`i${number}`]
      if (node) states.set(`${repo}#${number}`, { state: node.state, labels: node.labels.nodes.map(label => label.name) })
    }
  }
}

let changed = 0
for (const issue of issues) {
  const value = created[issue.key]
  if (typeof value !== 'string') continue
  const current = states.get(value)
  if (!current || current.state !== 'OPEN') continue
  const open = issue.blockers.filter(key => states.get(String(created[key]))?.state !== 'CLOSED')
  const want = open.length ? 'blocked' : 'ready'
  const drop = open.length ? 'ready' : 'blocked'
  if (current.labels.includes(want) && !current.labels.includes(drop)) continue
  const { repo, number } = splitRef(value)
  const edit = ['issue', 'edit', String(number), '-R', repo, '--add-label', want]
  if (current.labels.includes(drop)) edit.push('--remove-label', drop)
  if (!dryRun) gh(edit)
  changed++
  console.log(`${value} ${issue.key} -> ${want}${dryRun ? ' (dry run)' : ''}`)
}
console.log(`${changed} issue(s) relabelled`)
