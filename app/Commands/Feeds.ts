// `buddy feed:publish-rules` and `buddy feed:rebuild-cve`: publish Guardian's own artifacts to
// enrolled hosts (app/Guardian/feed-build.ts, docs/FEEDS.md).
import process from 'node:process'
import { defineCommand } from '@stacksjs/cli'
import { publishRulePack, runScheduledCveRebuild } from '../Guardian/feed-build'
import { FeedError } from '../Guardian/feed-format'

interface PublishRulesOptions {
  source?: string
  packVersion?: string
}

export default defineCommand((cli) => {
  cli
    .command('feed:publish-rules', 'Sign the Guardian rule source with zav rule-pack and publish it to hosts')
    .option('--source <dir>', 'Guardian rule source directory (default GUARDIAN_RULES_SOURCE_DIR)')
    .option('--pack-version <n>', 'Pack version (default: the published version plus one)')
    .action(async (options: PublishRulesOptions) => {
      try {
        const version = options.packVersion === undefined ? undefined : Number(options.packVersion)
        const result = await publishRulePack({ source: options.source, version })
        const { manifest } = result
        console.log(result.published
          ? `Published rule pack version ${manifest.version} (sha256 ${manifest.sha256}, ${manifest.size} bytes).`
          : result.restored
            ? `Rule pack version ${manifest.version} was missing or damaged on disk and has been restored.`
            : `Rule pack unchanged: version ${manifest.version} stays published.`)
        process.exitCode = 0
      }
      catch (error) {
        const code = error instanceof FeedError ? ` (${error.code})` : ''
        console.error(`Rule pack not published${code}: ${error instanceof Error ? error.message : String(error)}`)
        console.error('The previously published rule pack is still served.')
        process.exitCode = 1
      }
    })

  cli
    .command('feed:rebuild-cve', 'Fetch KEV, OSV and NVD, compile the signed CVE index and publish it now')
    .action(async () => {
      const result = await runScheduledCveRebuild()
      if (result.status === 'skipped')
        console.log(`CVE index rebuild skipped: ${result.reason}.`)
      else if (result.status === 'failed')
        console.error(`CVE index rebuild failed (${result.code}): ${result.message}`)
      else
        console.log(result.status === 'published' ? `Published CVE index version ${result.version}.` : `CVE index unchanged: version ${result.version} stays published.`)
      process.exitCode = result.status === 'failed' ? 1 : 0
    })
})
