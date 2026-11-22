import process from 'node:process'
import { schedule } from '@stacksjs/scheduler'

/**
 * **Scheduler**
 *
 * Define your scheduled tasks here. Jobs, actions, and shell commands
 * can all be scheduled with a fluent, expressive API.
 *
 * @see https://docs.stacksjs.com/scheduling
 */
export default function (): void {
  // Run the Inspire job every hour. An example, so it ships commented out
  // like the others: live, it put an always-on scheduler daemon on every
  // deploy of every new app, and `buddy new --minimal` (which removes
  // app/Jobs) left it naming a job that no longer exists.
  // schedule.job('Inspire').hourly().setTimeZone('America/Los_Angeles')

  // Rebuild and publish the CVE index for enrolled hosts (app/Guardian/feed-build.ts). It skips
  // itself on a server with no feed signing key; a key without a usable zav binary is a failure.
  //
  // Every six hours, at minute 17 so it does not join the top-of-the-hour crowd upstream. NVD asks
  // API users to sync no more often than every two hours and to use incremental lastModified
  // windows, which zav does with its saved progress; CISA KEV changes a few times a week and OSV
  // rebuilds its exports through the day, so six hours keeps hosts current within a working day
  // while fetching each feed four times a day from one server, never once per host. A full first
  // NVD mirror can run for hours without an API key, hence the eight-hour overlap guard.
  schedule.job('RebuildCveIndex').cron('17 */6 * * *').withoutOverlapping(8 * 60).onOneServer()

  // Run a custom action every five minutes
  // schedule.action('CleanupTempFiles').everyFiveMinutes()

  // Run a shell command daily at midnight
  // schedule.command('echo "Daily maintenance complete"').daily()
}

process.on('SIGINT', () => {
  schedule.gracefulShutdown().then(() => process.exit(0))
})
