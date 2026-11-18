import { HttpError } from '@stacksjs/error-handling'
import { Middleware, parseBearerToken } from '@stacksjs/router'
import { authenticateHost } from '../Guardian/ingest'

/**
 * Authenticates an enrolled host by its bearer credential and attaches it to the request as
 * `request.guardianHost`. Unknown, malformed and revoked credentials are refused alike.
 */
export default new Middleware({
  name: 'HostAuth',
  priority: 1,

  handle(request: any) {
    const header = (typeof request.header === 'function' && request.header('authorization'))
      || request.headers?.get?.('authorization')
    const host = authenticateHost(parseBearerToken(typeof header === 'string' ? header : null))
    if (!host)
      throw new HttpError(401, 'Unknown or revoked host credential')
    request.guardianHost = host
  },
})
