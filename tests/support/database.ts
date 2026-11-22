import { config } from '@stacksjs/config'
import { db, runDatabaseMigration } from '@stacksjs/database'
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
  state.__guardianDatabaseRefreshed ??= config.database?.default === 'postgres' ? refreshPostgres() : refreshDatabase()
  return state.__guardianDatabaseRefreshed
}

/**
 * Migrate and empty a Postgres test database.
 *
 * `refreshDatabase()` resets SQLite and MySQL only: on Postgres it returns without migrating or
 * truncating, so a fresh database had no tables and a reused one kept the last run's rows. This
 * applies `database/migrations/postgres` and then truncates every table but the migrations
 * ledger. It refuses a database without `test` or `testing` as a word of its name (`guardian_test`,
 * not `guardian_latest`), because it empties whatever the connection names.
 *
 * Remove this once `refreshDatabase()` resets Postgres itself (stacksjs/stacks#3355).
 */
async function refreshPostgres(): Promise<void> {
  const name = String(config.database?.connections?.postgres?.name ?? '')
  if (!/(?:^|[_-])test(?:ing)?(?:$|[_-])/i.test(name))
    throw new Error(`Refusing to empty Postgres database "${name}": run the suite against one named like guardian_test`)

  const migrated = await runDatabaseMigration()
  if (migrated.isErr)
    throw migrated.error

  const tables = (await db.unsafe(
    `SELECT tablename FROM pg_tables WHERE schemaname = current_schema() AND tablename <> 'migrations'`,
  ).execute()) as Array<{ tablename: string }>
  if (tables.length > 0)
    await db.unsafe(`TRUNCATE TABLE ${tables.map(t => `"${t.tablename.replaceAll('"', '""')}"`).join(', ')} RESTART IDENTITY CASCADE`).execute()
}
