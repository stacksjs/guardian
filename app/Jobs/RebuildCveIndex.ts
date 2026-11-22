import { Job } from '@stacksjs/queue'
import { runScheduledCveRebuild } from '../Guardian/feed-build'

/**
 * Rebuild the CVE index from CISA KEV, OSV and NVD and publish it to enrolled hosts (see
 * app/Guardian/feed-build.ts). Scheduled in app/Scheduler.ts on one server, never overlapping.
 *
 * The scheduler runs this in its own process (`schedule.job()` with no queue), so there are no
 * queue retries or timeouts here: the only time bounds are the zav steps' own (six hours for the
 * fetch, one for the compile). A server with no feed signing key does not publish feeds, so the
 * run is a skip. Any failure, a missing zav binary included, is logged by the rebuild and then
 * thrown, so the scheduler logs and reports it too; the previously published index keeps being
 * served either way.
 */
export default new Job({
  name: 'RebuildCveIndex',
  description: 'Fetch KEV, OSV and NVD, compile the signed CVE index and publish it to hosts',

  handle: async (): Promise<Record<string, unknown>> => {
    const result = await runScheduledCveRebuild()
    if (result.status === 'failed')
      throw new Error(`RebuildCveIndex failed (${result.code}): ${result.message}`)
    return result
  },
})
