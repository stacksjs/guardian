import type { RouteRegistry } from '@stacksjs/router'

/**
 * Route files and their prefixes. `routes/guardian.ts` is the host API (enrolment and ingest),
 * mounted under `/api` next to `routes/api.ts`.
 */
export default {
  'api': 'api',
  'guardian': { path: 'guardian', prefix: 'api' },
} satisfies RouteRegistry
