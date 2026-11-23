import { config } from '@stacksjs/config'
import { authenticatedUser } from '@stacksjs/auth/middleware'
import { hasAnyRole } from '@stacksjs/auth/rbac'
import { HttpError } from '@stacksjs/error-handling'
import { Middleware } from '@stacksjs/router'

/**
 * Admits Guardian's operators: signed-in accounts holding `config.auth.adminRole`, the role
 * `./buddy seed:admins` grants to the addresses in `config.auth.admins`.
 *
 * Use it after `auth`, which signs the caller in. Being signed in is not enough: any account
 * that exists could otherwise mint enrolment tokens and rotate or revoke hosts. With
 * `adminRole: false` there is no operator role, so everyone is refused.
 *
 * To make an operator without committing an address, run `./buddy user:add <email> --role admin`
 * where the app runs. It grants the default role, `admin` under the `web` guard.
 */
export default new Middleware({
  name: 'Operator',
  priority: 3,

  async handle(request: any) {
    const user = await authenticatedUser(request)
    if (!user)
      throw new HttpError(401, 'Unauthenticated.')

    const role = config.auth?.adminRole
    if (role === false || !await hasAnyRole(user, [role?.name ?? 'admin'], role?.guard ?? 'web'))
      throw new HttpError(403, 'Only Guardian operators may do this.')
  },
})
