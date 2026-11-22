import { refreshDatabase } from '@stacksjs/testing/database'

const state = globalThis as typeof globalThis & { __guardianDatabaseRefreshed?: Promise<void> }

/**
 * `refreshDatabase()` at most once per test process.
 *
 * Its SQLite fast path copies the migrated snapshot over the live database file while the
 * connection is open. The first call in a process is fine; a second one (the next test file in
 * the same `bun test` run) leaves the open connection on a replaced file, and on macOS every
 * later query fails with SQLITE_IOERR_VNODE. So every file shares one refresh, and each test
 * keeps to rows it created itself (its own host names, its own feed kinds).
 */
export function freshDatabase(): Promise<void> {
  state.__guardianDatabaseRefreshed ??= refreshDatabase()
  return state.__guardianDatabaseRefreshed
}
