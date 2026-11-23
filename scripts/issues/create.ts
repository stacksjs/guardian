#!/usr/bin/env bun
// Creates the Guardian issue graph across every repository it spans, from OUTLINE.txt,
// bodies-*.json and outline.config.ts.
//
//   bun scripts/issues/create.ts --dry-run [--show P3.07] [--repo-summary]
//   bun scripts/issues/create.ts --preflight     check every repository exists and has issues enabled
//   bun scripts/issues/create.ts                 create (resumable; never duplicates)
//
// Issues are created in outline order, so numbers ascend in execution order inside each repository.
// Progress is written to created.json (key -> owner/name#N) after every step, so a rerun resumes.
// Outline lines whose repository cell ends in #N point at an existing issue: it is labelled and
// linked into the graph with one comment, never recreated.
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { AGENTS_URL, AREAS, HUB, PLAN_URL, TYPES } from './outline.config'
import { type Body, DIR, gh, type Issue, loadBodies, loadOutline, type Phase, ref, type Ref, sleep, splitRef, withRetry } from './lib'

const args = process.argv.slice(2)
const flag = (name: string) => args.includes(name)
const value = (name: string) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined)
const PAUSE_MS = Number(value('--pause') ?? 2500)

const { phases, issues } = loadOutline()
const bodies = loadBodies()
const byKey = new Map(issues.map(issue => [issue.key, issue]))
const phaseOf = (issue: Issue) => phases.find(phase => phase.id === issue.phase)!
const missing = issues.filter(issue => !issue.existing && !bodies.has(issue.key)).map(issue => issue.key)
const unknown = [...bodies.keys()].filter(key => !byKey.has(key))
if (missing.length || unknown.length) {
  console.error(`Bodies missing for: ${missing.join(' ') || 'none'}\nBodies with no outline key: ${unknown.join(' ') || 'none'}`)
  process.exit(1)
}

const createdPath = join(DIR, 'created.json')
const created: Record<string, Ref | number> = existsSync(createdPath) ? JSON.parse(readFileSync(createdPath, 'utf8')) : {}
const save = () => writeFileSync(createdPath, `${JSON.stringify(created, null, 2)}\n`)
const refOf = (key: string): string => (typeof created[key] === 'string' ? created[key] as string : `?${key}`)

const repos = [...new Set([HUB, ...issues.map(issue => issue.repo)])]
const milestoneTitle = (phase: Phase) => `Guardian ${phase.milestone}`
const titleOf = (issue: Issue) => `[Guardian ${issue.key}] ${issue.title}`

const list = (title: string, items: string[] | undefined, render: (item: string) => string = item => `- ${item}`) =>
  items && items.length ? `## ${title}\n\n${items.map(render).join('\n')}\n\n` : ''

function blockerLines(issue: Issue): string[] {
  return issue.blockers.map(key => `- ${refOf(key)} \`${key}\` ${byKey.get(key)!.title}`)
}

function leafBody(issue: Issue, body: Body): string {
  const phase = phaseOf(issue)
  const blockers = blockerLines(issue)
  return [
    `> **Guardian ${phase.milestone}** · key \`${issue.key}\` · size ${issue.size}${issue.flags.includes('needs-human') ? ' · needs the maintainer' : ''} · epic ${refOf(`EPIC-${phase.id}`)}\n\n`,
    `## Goal\n\n${body.goal}\n\n`,
    list('References', body.refs, item => `- \`${item}\``),
    list('Scope', body.scope),
    list('Out of scope', body.out_of_scope),
    list('Design notes', body.notes),
    list('Acceptance criteria', body.accept, item => `- [ ] ${item}`),
    blockers.length ? `## Blocked by\n\n${blockers.join('\n')}\n\n` : '## Blocked by\n\nNothing. This issue can start now.\n\n',
    `---\nPart of the Guardian program: an anti-malware engine, host protection and web firewall for the Stacks ecosystem. The plan is in [docs/PLAN.md](${PLAN_URL}); working rules in [AGENTS.md](${AGENTS_URL}).\n`,
  ].join('')
}

function existingComment(issue: Issue): string {
  const phase = phaseOf(issue)
  const blockers = blockerLines(issue)
  return [
    `This issue is now part of the Guardian program's issue graph as \`${issue.key}\` (**${phase.milestone}**, epic ${refOf(`EPIC-${phase.id}`)}).\n\n`,
    `Guardian treats zig-waf as its web-application-firewall layer. This issue stays as written; the graph only orders it and links what it waits on.\n\n`,
    blockers.length ? `Waits on:\n\n${blockers.join('\n')}\n\n` : 'It waits on nothing in the graph.\n\n',
    `Plan: [docs/PLAN.md](${PLAN_URL})\n`,
  ].join('')
}

function leafLabels(issue: Issue): string[] {
  const labels = ['guardian', `phase:${phaseOf(issue).n}`, issue.blockers.length ? 'blocked' : 'ready']
  if (!issue.existing) labels.push(`area:${issue.area}`, `type:${issue.type}`, `size:${issue.size}`)
  if (issue.flags.includes('needs-human')) labels.push('needs-human')
  return labels
}

function epicBody(phase: Phase): string {
  const tasks = issues.filter(issue => issue.phase === phase.id).map(issue => `- [ ] ${refOf(issue.key)} \`${issue.key}\` ${issue.title}`)
  return `${phase.goal}\n\nThis is a tracking issue. Work the leaf issues below in order; the last one is the phase gate. They live in the repositories that own the code.\n\n## Issues\n\n${tasks.join('\n')}\n\nSee [docs/PLAN.md](${PLAN_URL}) for the phase description and gates.\n`
}

function repoTrackerBody(repo: string): string {
  const mine = issues.filter(issue => issue.repo === repo)
  const tasks = mine.map(issue => `- [ ] ${refOf(issue.key)} \`${issue.key}\` ${issue.title}`)
  return `Guardian is an anti-malware engine, host protection and web firewall for the Stacks ecosystem. These are the parts of it that belong to this repository, in execution order. The whole graph and its rules are in ${refOf('START')}.\n\n## Issues here\n\n${tasks.join('\n')}\n\nPlan: [docs/PLAN.md](${PLAN_URL})\n`
}

function startBody(): string {
  const epics = phases.map(phase => `- ${refOf(`EPIC-${phase.id}`)} ${phase.milestone}`)
  const trackers = repos.filter(repo => repo !== HUB).map(repo => `- ${refOf(`REPO-${repo}`)} ${repo}`)
  return `Guardian is a low-memory anti-malware engine (\`zig-utils/zig-anti-virus\`), host protection with CVE automation, and the zig-waf web firewall, wired into every place the Stacks ecosystem accepts untrusted bytes. This hub tracks the whole plan as issues in the repositories that own the code.

## How to pick work

1. Take the **lowest open issue labelled \`ready\` and \`guardian\`**, in the order of the phase epics below. Skip \`epic\` trackers, and skip \`needs-human\` issues unless the maintainer has supplied what they ask for.
2. Read [AGENTS.md](${AGENTS_URL}) and the issue's design notes. Its Scope is the work and its Acceptance criteria are the definition of done.
3. Small conventional commits, each naming the issue (\`Closes owner/repo#N\`). Comment the decisions on the issue when closing it.
4. After closing, run \`bun scripts/issues/sync-ready.ts\` (a scheduled workflow also does it) so dependents flip from \`blocked\` to \`ready\`. Never start a \`blocked\` issue.

## Phases

${epics.join('\n')}

## Per-repository trackers

${trackers.join('\n')}

## Reference

- [docs/PLAN.md](${PLAN_URL}): goals, decisions, phases and gates
- [zig-anti-virus docs/DESIGN.md](https://github.com/zig-utils/zig-anti-virus/blob/main/docs/DESIGN.md): engine performance and memory design
`
}

if (flag('--dry-run')) {
  const per = phases.map(phase => `${phase.id}=${issues.filter(issue => issue.phase === phase.id).length}`).join(' ')
  const fresh = issues.filter(issue => !issue.existing).length
  console.log(`${issues.length} leaves (${fresh} new, ${issues.length - fresh} existing), ${phases.length} epics, ${repos.length - 1} repo trackers, 1 start issue. ${per}`)
  console.log(`ready at creation: ${issues.filter(issue => !issue.blockers.length).map(issue => issue.key).join(' ')}`)
  if (flag('--repo-summary')) {
    for (const repo of repos) console.log(`${repo}: ${issues.filter(issue => issue.repo === repo).length}`)
  }
  const show = value('--show')
  if (show) {
    const issue = byKey.get(show)!
    console.log(`\n${issue.repo} ${titleOf(issue)}\nlabels: ${leafLabels(issue).join(', ')}\n\n${issue.existing ? existingComment(issue) : leafBody(issue, bodies.get(show)!)}`)
  }
  process.exit(0)
}

if (flag('--preflight')) {
  let bad = 0
  for (const repo of repos) {
    try {
      const info = JSON.parse(gh(['repo', 'view', repo, '--json', 'hasIssuesEnabled,viewerPermission,visibility'])) as { hasIssuesEnabled: boolean, viewerPermission: string, visibility: string }
      const ok = info.hasIssuesEnabled && ['ADMIN', 'MAINTAIN', 'WRITE'].includes(info.viewerPermission)
      if (!ok) bad++
      console.log(`${ok ? 'ok ' : 'BAD'} ${repo} issues=${info.hasIssuesEnabled} permission=${info.viewerPermission} ${info.visibility}`)
    }
    catch (error) {
      bad++
      console.log(`BAD ${repo} ${(error as Error).message}`)
    }
  }
  for (const issue of issues.filter(candidate => candidate.existing)) {
    const state = JSON.parse(gh(['issue', 'view', String(issue.existing), '-R', issue.repo, '--json', 'state,title'])) as { state: string, title: string }
    console.log(`existing ${issue.key} ${issue.repo}#${issue.existing} ${state.state} ${state.title}`)
  }
  process.exit(bad ? 1 : 0)
}

// Labels: only those a repository uses, and never overwrite a label that already exists there.
// The marker records which labels were ensured, so an outline change that gives a repository a new
// area, type, size or phase label ensures it again instead of failing at issue creation.
for (const repo of repos) {
  const mine = issues.filter(issue => issue.repo === repo)
  const wanted: Array<[string, string, string]> = [
    ['guardian', '0b3d91', 'Part of the Guardian program'],
    ['ready', '0e8a16', 'All blockers closed: can be started'],
    ['blocked', 'b60205', 'Waiting on another issue'],
    ['epic', '5319e7', 'Tracking issue'],
    ['needs-human', 'fbca04', 'Needs a decision, access or approval from the maintainer'],
    ...[...new Set((repo === HUB ? issues : mine).map(issue => phaseOf(issue)))].map(phase => [`phase:${phase.n}`, '1d76db', milestoneTitle(phase)] as [string, string, string]),
    ...[...new Set(mine.filter(issue => !issue.existing).map(issue => issue.area))].map(area => [`area:${area}`, 'c5def5', AREAS[area]!] as [string, string, string]),
    ...[...new Set(mine.filter(issue => !issue.existing).map(issue => issue.type))].map(type => [`type:${type}`, 'd4c5f9', TYPES[type]!] as [string, string, string]),
    ...[...new Set(mine.filter(issue => !issue.existing).map(issue => issue.size))].map(size => [`size:${size}`, 'ededed', `Size ${size}`] as [string, string, string]),
  ]
  const ensured = wanted.map(([name]) => name).sort().join(',')
  if (created[`__labels:${repo}`] === ensured) continue
  const have = new Set((JSON.parse(gh(['label', 'list', '-R', repo, '--limit', '500', '--json', 'name'])) as Array<{ name: string }>).map(label => label.name))
  for (const [name, color, description] of wanted) {
    if (have.has(name)) continue
    await withRetry(`label ${repo} ${name}`, () => gh(['label', 'create', name, '--color', color, '--description', description, '-R', repo]))
    await sleep(300)
  }
  created[`__labels:${repo}`] = ensured
  save()
  console.log(`labels: ${repo}`)
}

// Milestones: one per phase a repository takes part in, prefixed so shared repositories stay tidy.
// Same marker rule as labels: a repository that joins a new phase gets that phase's milestone.
for (const repo of repos) {
  const used = [...new Set((repo === HUB ? issues : issues.filter(issue => issue.repo === repo && !issue.existing)).map(issue => phaseOf(issue)))]
  const ensured = used.map(phase => phase.id).sort().join(',')
  if (created[`__milestones:${repo}`] === ensured) continue
  const existing = new Set((JSON.parse(gh(['api', `repos/${repo}/milestones?state=all&per_page=100`])) as Array<{ title: string }>).map(milestone => milestone.title))
  for (const phase of used) {
    if (existing.has(milestoneTitle(phase))) continue
    await withRetry(`milestone ${repo} ${phase.id}`, () => gh(['api', `repos/${repo}/milestones`, '-f', `title=${milestoneTitle(phase)}`, '-f', `description=${phase.goal}`]))
    await sleep(300)
  }
  created[`__milestones:${repo}`] = ensured
  save()
  console.log(`milestones: ${repo}`)
}

async function createIssue(key: string, repo: string, title: string, body: string, issueLabels: string[], milestone?: string): Promise<void> {
  if (created[key]) return
  const cmd = ['issue', 'create', '-R', repo, '--title', title, '--body-file', '-', '--label', issueLabels.join(',')]
  if (milestone) cmd.push('--milestone', milestone)
  const url = await withRetry(key, () => gh(cmd, body))
  const number = Number(url.trim().split('/').pop())
  if (!Number.isInteger(number)) throw new Error(`Could not read the issue number for ${key} from: ${url}`)
  created[key] = ref(repo, number)
  save()
  console.log(`${created[key]} ${key} ${title}`)
  await sleep(PAUSE_MS)
}

async function linkExisting(issue: Issue): Promise<void> {
  if (!created[issue.key]) {
    created[issue.key] = ref(issue.repo, issue.existing!)
    save()
  }
  if (created[`__linked:${issue.key}`]) return
  const number = String(issue.existing)
  await withRetry(`label ${issue.key}`, () => gh(['issue', 'edit', number, '-R', issue.repo, '--add-label', leafLabels(issue).join(',')]))
  await withRetry(`comment ${issue.key}`, () => gh(['issue', 'comment', number, '-R', issue.repo, '--body-file', '-'], existingComment(issue)))
  created[`__linked:${issue.key}`] = 1
  save()
  console.log(`${created[issue.key]} ${issue.key} linked`)
  await sleep(PAUSE_MS)
}

await createIssue('START', HUB, 'Start here: how the Guardian issue graph works', startBody(), ['epic', 'guardian'])
for (const phase of phases) {
  await createIssue(`EPIC-${phase.id}`, HUB, `[Guardian ${phase.id}] Epic: ${phase.milestone}`, epicBody(phase), ['epic', 'guardian', `phase:${phase.n}`], milestoneTitle(phase))
}
for (const issue of issues) {
  if (issue.existing) await linkExisting(issue)
  else await createIssue(issue.key, issue.repo, titleOf(issue), leafBody(issue, bodies.get(issue.key)!), leafLabels(issue), milestoneTitle(phaseOf(issue)))
}
for (const repo of repos.filter(candidate => candidate !== HUB)) {
  await createIssue(`REPO-${repo}`, repo, 'Guardian: tracking issue for this repository', repoTrackerBody(repo), ['epic', 'guardian'])
}

// Every number is known now: fill the trackers and the start issue, then pin it.
if (!created.__finalized) {
  const edit = async (key: string, body: string) => {
    const { repo, number } = splitRef(created[key] as string)
    await withRetry(`edit ${key}`, () => gh(['issue', 'edit', String(number), '-R', repo, '--body-file', '-'], body))
    await sleep(800)
  }
  for (const phase of phases) await edit(`EPIC-${phase.id}`, epicBody(phase))
  for (const repo of repos.filter(candidate => candidate !== HUB)) await edit(`REPO-${repo}`, repoTrackerBody(repo))
  await edit('START', startBody())
  try {
    gh(['issue', 'pin', String(splitRef(created.START as string).number), '-R', HUB])
  }
  catch (error) {
    console.error(`pin: ${(error as Error).message}`)
  }
  created.__finalized = 1
  save()
}
console.log(`done: ${issues.length} leaves, ${phases.length} epics, start ${created.START}`)
