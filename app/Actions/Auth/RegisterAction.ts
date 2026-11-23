import { Action } from '@stacksjs/actions/runtime'
import { HttpError } from '@stacksjs/error-handling'

/**
 * Self-registration is closed: this replaces the framework's `RegisterAction`, which `POST
 * /register` and any other route naming `Actions/Auth/RegisterAction` resolve to.
 *
 * Guardian has no public accounts. Operators are the addresses in `config.auth.admins`, which
 * `./buddy seed:admins` creates and grants `config.auth.adminRole`. An open sign-up would only
 * hand out accounts the operator routes then refuse.
 *
 * `skipCsrf` so the answer is the 404 a closed route gives, not a CSRF refusal that suggests the
 * route would work with a token. Nothing is read or written.
 */
export default new Action({
  name: 'RegisterAction',
  description: 'Self-registration is closed',
  method: 'POST',
  skipCsrf: true,

  handle() {
    throw new HttpError(404, 'Not Found')
  },
})
