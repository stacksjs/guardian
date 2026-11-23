import { beforeAll, describe, expect, it } from 'bun:test'
import { assignRole, createRole, findRole } from '@stacksjs/auth/rbac'
import { config } from '@stacksjs/config'
import User from '@stacksjs/defaults/app/Models/User'
import { http } from '@stacksjs/testing'
import { authenticateHost, createEnrolmentToken } from '../../app/Guardian/ingest'
import { freshDatabase } from '../support/database'

/**
 * Who may call the operator routes: mint enrolment tokens, rotate and revoke host credentials.
 *
 * Operators are the accounts holding `config.auth.adminRole`, the role `./buddy seed:admins`
 * grants to `config.auth.admins`. Being signed in is not enough, and nobody can sign themselves
 * up: `/register` is closed.
 *
 * The Postgres migrations hold only Guardian's own tables, not the framework's `users` or role
 * tables (production stays on SQLite), so these tests run on SQLite only.
 */
const onPostgres = config.database?.default === 'postgres'
if (onPostgres)
  console.warn('operator auth tests: skipped on Postgres, whose migrations have no users or role tables')

describe.skipIf(onPostgres)('operator routes', () => {
  const role = config.auth?.adminRole === false ? null : { name: config.auth?.adminRole?.name ?? 'admin', guard: config.auth?.adminRole?.guard ?? 'web' }
  let operator: { id: number }
  let member: { id: number }
  let hostId = 0

  beforeAll(async () => {
    await freshDatabase()
    operator = await User.create({ name: 'Operator Test', email: 'operator-auth-operator@example.com', password: 'Correct-horse-9-battery' }) as { id: number }
    member = await User.create({ name: 'Member Test', email: 'operator-auth-member@example.com', password: 'Correct-horse-9-battery' }) as { id: number }
    if (role) {
      if (!await findRole(role.name, role.guard))
        await createRole(role.name, role.guard)
      await assignRole(operator.id, role.name, role.guard)
    }

    const minted = await http.post('/api/hosts/enrolment-tokens', { actingAs: operator, body: { label: 'operator-auth' } })
    const { token } = await minted.json<{ token: string }>()
    const enrolled = await http.post('/api/hosts/enrol', { body: { token, name: 'operator-auth-host', platform: 'linux' } })
    expect(enrolled.status).toBe(201)
    hostId = (await enrolled.json<{ hostId: number }>()).hostId
  })

  it('lets an operator mint an enrolment token', async () => {
    expect(role).not.toBeNull()
    const res = await http.post('/api/hosts/enrolment-tokens', { actingAs: operator, body: { label: 'operator-auth' } })
    expect(res.status).toBe(201)
    expect((await res.json<{ token: string }>()).token).toStartWith('gde_')
  })

  it('lets an operator rotate a host credential', async () => {
    expect(hostId).toBeGreaterThan(0)
    const res = await http.post(`/api/hosts/${hostId}/rotate`, { actingAs: operator })
    expect(res.status).toBe(200)
  })

  for (const [what, path] of [['mint an enrolment token', '/api/hosts/enrolment-tokens'], ['rotate a host credential', '/api/hosts/{id}/rotate'], ['revoke a host', '/api/hosts/{id}/revoke']] as const) {
    it(`refuses a signed-in account without the operator role the right to ${what}`, async () => {
      const res = await http.post(path.replace('{id}', String(hostId)), { actingAs: member, body: {} })
      expect(res.status).toBe(403)
    })

    it(`refuses an anonymous caller the right to ${what}`, async () => {
      const res = await http.post(path.replace('{id}', String(hostId)), { body: {} })
      expect(res.status).toBe(401)
    })
  }

  it('refuses an account holding a role of the same name under another guard', async () => {
    expect(role).not.toBeNull()
    const otherGuard = role!.guard === 'api' ? 'web' : 'api'
    const lookalike = await User.create({ name: 'Lookalike Test', email: 'operator-auth-lookalike@example.com', password: 'Correct-horse-9-battery' }) as { id: number }
    if (!await findRole(role!.name, otherGuard))
      await createRole(role!.name, otherGuard)
    await assignRole(lookalike.id, role!.name, otherGuard)
    const res = await http.post('/api/hosts/enrolment-tokens', { actingAs: lookalike, body: { label: 'operator-auth' } })
    expect(res.status).toBe(403)
  })

  it('refuses even an operator when no operator role is configured', async () => {
    const auth = config.auth as { adminRole?: unknown }
    const saved = Object.getOwnPropertyDescriptor(auth, 'adminRole')
    auth.adminRole = false
    try {
      const res = await http.post('/api/hosts/enrolment-tokens', { actingAs: operator, body: { label: 'operator-auth' } })
      expect(res.status).toBe(403)
    }
    finally {
      if (saved)
        Object.defineProperty(auth, 'adminRole', saved)
      else
        delete auth.adminRole
    }
  })

  it('keeps the host enrolled after the refused revokes', async () => {
    const res = await http.post(`/api/hosts/${hostId}/rotate`, { actingAs: operator })
    expect(res.status).toBe(200)
    // A revoked host's fresh credential is refused, so this fails if any revoke above got through.
    expect(authenticateHost((await res.json<{ credential: string }>()).credential)?.id).toBe(hostId)
  })
})

describe('host enrolment over HTTP', () => {
  beforeAll(async () => {
    await freshDatabase()
  })

  // An agent posts its enrolment token with no CSRF cookie: it is not a browser. Before the route
  // skipped the CSRF check, every agent got 403 "CSRF token mismatch" here.
  it('needs no CSRF token', async () => {
    const res = await http.post('/api/hosts/enrol', { body: { token: createEnrolmentToken('operator-auth-csrf', 1), name: 'operator-auth-csrf', platform: 'linux' } })
    expect(res.status).toBe(201)
    expect((await res.json<{ credential: string }>()).credential).toStartWith('gdh_')
  })

  it('still refuses a bad enrolment token', async () => {
    const res = await http.post('/api/hosts/enrol', { body: { token: 'gde_not-a-real-token', name: 'operator-auth-csrf', platform: 'linux' } })
    expect(res.status).toBeGreaterThanOrEqual(400)
    expect(res.status).toBeLessThan(500)
  })
})

describe('self-registration', () => {
  it('is closed', async () => {
    const res = await http.post('/register', { body: { name: 'Walk In', email: 'operator-auth-walk-in@example.com', password: 'Correct-horse-9-battery' } })
    expect(res.status).toBe(404)
  })
})
