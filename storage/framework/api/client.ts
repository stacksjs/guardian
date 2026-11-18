/* eslint-disable */
/**
 * Stacks API client, generated from OpenAPI.
 * Do not edit; run buddy generate:openapi.
 * No imports or dependencies.
 */


export type ApiResult<T> =
  | { ok: true, status: number, data: T, headers: Headers }
  | { ok: false, status: number, error: unknown, headers: Headers }

export interface ClientConfig {
  baseUrl: string
  token?: string
  headers?: Record<string, string>
  fetch?: typeof fetch
}
export interface RequestOptions {
  signal?: AbortSignal
  headers?: Record<string, string>
  /** Select one of the operation's declared request media types. */
  contentType?: string
}
interface Parameter {
  name: string
  in: string
  required: boolean
  group?: string
  style?: string
  explode?: boolean
}
interface BodyDescription { required: boolean, content: string[] }

function parameterValue(input: Record<string, unknown>, parameter: Parameter): unknown {
  const fields = parameter.group ? input[parameter.group] : input
  if (parameter.in === 'header' && fields && typeof fields === 'object') {
    const entries = Object.entries(fields).filter(([key]) => key.toLowerCase() === parameter.name.toLowerCase())
    return entries.at(-1)?.[1]
  }
  return fields && typeof fields === 'object' && Object.hasOwn(fields, parameter.name)
    ? (fields as Record<string, unknown>)[parameter.name] : undefined
}
function scalar(value: unknown): string {
  if (typeof value === 'object' && value !== null) throw new TypeError('Nested parameter values require an explicit supported serialization')
  return String(value)
}
function queryParameter(url: URL, parameter: Parameter, value: unknown): void {
  const style = parameter.style ?? 'form'
  const explode = parameter.explode ?? style === 'form'
  if (style === 'deepObject') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('deepObject requires an object')
    for (const [key, item] of Object.entries(value)) url.searchParams.append(parameter.name + '[' + key + ']', scalar(item))
  }
  else if (Array.isArray(value)) {
    if (style === 'form' && explode) {
      for (const item of value) url.searchParams.append(parameter.name, scalar(item))
    }
    else url.searchParams.append(parameter.name, value.map(scalar).join(style === 'spaceDelimited' ? ' ' : style === 'pipeDelimited' ? '|' : ','))
  }
  else if (value && typeof value === 'object') {
    if (style !== 'form') throw new TypeError('Object queries require form or deepObject style')
    if (explode) for (const [key, item] of Object.entries(value)) url.searchParams.append(key, scalar(item))
    else url.searchParams.append(parameter.name, Object.entries(value).flatMap(([key, item]) => [key, scalar(item)]).join(','))
  }
  else url.searchParams.append(parameter.name, scalar(value))
}
function simpleParameter(value: unknown, explode: boolean, encode: (value: string) => string): string {
  if (Array.isArray(value)) return value.map(item => encode(scalar(item))).join(',')
  if (value && typeof value === 'object') return Object.entries(value).map(([key, item]) => encode(key) + (explode ? '=' : ',') + encode(scalar(item))).join(',')
  return encode(scalar(value))
}
function buildUrl(config: ClientConfig, route: string, input: Record<string, unknown>, parameters: Parameter[], headers: Headers): string {
  const path = new Map<string, string>()
  for (const parameter of parameters) {
    const value = parameterValue(input, parameter)
    if (value === undefined || value === null) {
      if (parameter.required) throw new TypeError('Missing required ' + parameter.in + ' parameter: ' + parameter.name)
      continue
    }
    if (parameter.in === 'path') {
      const segment = simpleParameter(value, parameter.explode ?? false, encodeURIComponent)
      if (segment === '.' || segment === '..') throw new TypeError('Dot-only path parameters are not allowed')
      path.set(parameter.name, segment)
    }
    else if (parameter.in === 'header') headers.set(parameter.name, simpleParameter(value, parameter.explode ?? false, value => value))
  }
  const filled = route.replace(/\{([^{}]+)\}/g, (_, key: string) => {
    const value = path.get(key)
    if (value === undefined) throw new TypeError('Missing path parameter: ' + key)
    return value
  })
  const url = new URL(filled.replace(/^\/+/, '/'), config.baseUrl.endsWith('/') ? config.baseUrl : config.baseUrl + '/')
  for (const parameter of parameters) {
    const value = parameterValue(input, parameter)
    if (parameter.in === 'query' && value !== undefined && value !== null) queryParameter(url, parameter, value)
  }
  return url.toString()
}
function isJson(type: string): boolean { return type === 'application/json' || type.endsWith('+json') }
function mediaType(type: string): string { return type.split(';')[0]!.trim().toLowerCase() }
function requestBody(value: unknown, description: BodyDescription | null, headers: Headers, options?: RequestOptions): BodyInit | undefined {
  if (!description) return undefined
  if (value === undefined) {
    if (description.required) throw new TypeError('Missing required request body')
    return undefined
  }
  const declared = description.content
  const selected = options?.contentType ?? headers.get('content-type') ?? declared.find(isJson) ?? declared[0]
  if (!selected || !declared.some(type => mediaType(type) === mediaType(selected))) throw new TypeError('Request media type is not declared by this operation')
  const type = mediaType(selected)
  headers.set('content-type', selected)
  if (isJson(type)) return JSON.stringify(value)
  if (type === 'application/x-www-form-urlencoded' || type === 'multipart/form-data') {
    if (type === 'multipart/form-data' && value instanceof FormData) { headers.delete('content-type'); return value }
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Form bodies require an object')
    if (type === 'application/x-www-form-urlencoded') {
      const form = new URLSearchParams()
      for (const [name, field] of Object.entries(value)) {
        for (const item of Array.isArray(field) ? field : [field]) if (item != null) form.append(name, scalar(item))
      }
      return form.toString()
    }
    const form = new FormData()
    for (const [name, field] of Object.entries(value)) {
      for (const item of Array.isArray(field) ? field : [field]) {
        if (item == null) continue
        form.append(name, item instanceof Blob ? item : typeof item === 'object' ? JSON.stringify(item) : String(item))
      }
    }
    headers.delete('content-type')
    return form
  }
  if (value instanceof Blob || value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return value as BodyInit
  if (typeof value === 'string') return value
  throw new TypeError('Non-JSON request bodies require text or binary data')
}
async function request<T>(config: ClientConfig, method: string, route: string, input: Record<string, unknown>, parameters: Parameter[], description: BodyDescription | null, accept: string, binary: string[], options?: RequestOptions): Promise<ApiResult<T>> {
  const headers = new Headers({ Accept: accept })
  for (const [name, value] of Object.entries(config.headers ?? {})) headers.set(name, value)
  if (config.token) headers.set('authorization', 'Bearer ' + config.token)
  for (const [name, value] of Object.entries(options?.headers ?? {})) headers.set(name, value)
  const url = buildUrl(config, route, input, parameters, headers)
  const body = requestBody(input.body, description, headers, options)
  const response = await (config.fetch ?? fetch)(url, { method, headers, body, signal: options?.signal })
  const type = mediaType(response.headers.get('content-type') ?? '')
  let parsed: unknown
  if (method === 'HEAD' || response.status === 204 || response.status === 205) parsed = null
  else if (binary.includes(type)) parsed = await response.blob()
  else {
    const text = await response.text()
    // Keep malformed JSON available as evidence, without parsing other media as JSON.
    if (!text.length) parsed = type.startsWith('text/') ? '' : null
    else if (isJson(type)) { try { parsed = JSON.parse(text) } catch { parsed = text } }
    else parsed = text
  }
  return response.ok
    ? { ok: true, status: response.status, data: parsed as T, headers: response.headers }
    : { ok: false, status: response.status, error: parsed, headers: response.headers }
}

export interface components {
  schemas: {

  }
  requestSchemas: {

  }
}

export function createClient(config: ClientConfig) {
  return {
    config,
  /**
   * GET /.well-known/oauth-authorization-server
   */
  getWellKnownOauthAuthorizationServer(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/.well-known/oauth-authorization-server", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /_stacks/email/unsubscribe/{token}
   */
  getStacksEmailUnsubscribeToken(input: { "token": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/_stacks/email/unsubscribe/{token}", input ?? {}, [{"name":"token","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /_stacks/email/unsubscribe/{token}
   */
  postStacksEmailUnsubscribeToken(input: { "token": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/_stacks/email/unsubscribe/{token}", input ?? {}, [{"name":"token","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /_stacks/mail/preview
   */
  getStacksMailPreview(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/_stacks/mail/preview", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /_stacks/mail/preview/{name}
   */
  getStacksMailPreviewName(input: { "name": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/_stacks/mail/preview/{name}", input ?? {}, [{"name":"name","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /_stacks/mail/preview/{name}/raw
   */
  getStacksMailPreviewNameRaw(input: { "name": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/_stacks/mail/preview/{name}/raw", input ?? {}, [{"name":"name","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /ai/ask
   */
  postAiAsk(input: { body: { "question": string } }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/ai/ask", input ?? {}, [], {"required":true,"content":["application/json"]}, "application/json", [], options)
  },

  /**
   * POST /ai/complete
   */
  postAiComplete(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/ai/complete", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /ai/summary
   */
  postAiSummary(input: { body: { "text": string } }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/ai/summary", input ?? {}, [], {"required":true,"content":["application/json"]}, "application/json", [], options)
  },

  /**
   * GET /api/analytics/blog
   */
  getAnalyticsBlog(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/analytics/blog", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/analytics/browsers
   */
  getAnalyticsBrowsers(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/analytics/browsers", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/analytics/countries
   */
  getAnalyticsCountries(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/analytics/countries", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/analytics/devices
   */
  getAnalyticsDevices(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/analytics/devices", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/analytics/events
   */
  getAnalyticsEvents(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/analytics/events", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/analytics/marketing
   */
  getAnalyticsMarketing(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/analytics/marketing", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/analytics/pages
   */
  getAnalyticsPages(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/analytics/pages", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/analytics/referrers
   */
  getAnalyticsReferrers(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/analytics/referrers", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/analytics/web
   */
  getAnalyticsWeb(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/analytics/web", {}, [], null, "application/json", [], options)
  },

  /**
   * contact.send
   */
  contactSend(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/contact", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/activity
   */
  getDashboardActivity(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/activity", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/analytics/marketing
   */
  getDashboardAnalyticsMarketing(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/analytics/marketing", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/analytics/web
   */
  getDashboardAnalyticsWeb(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/analytics/web", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/auth/me
   */
  getDashboardAuthMe(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/auth/me", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/blog
   */
  getDashboardBlog(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/blog", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/blog
   */
  postDashboardBlog(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/blog", {}, [], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/blog/{slug}
   */
  patchDashboardBlogSlug(input: { "slug": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/blog/{slug}", input ?? {}, [{"name":"slug","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/buddy/chat
   */
  getDashboardBuddyChat(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/buddy/chat", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/buddy/chat
   */
  postDashboardBuddyChat(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/buddy/chat", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/buddy/chat/clear
   */
  postDashboardBuddyChatClear(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/buddy/chat/clear", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/ci/repos/{owner}/{name}/runs
   */
  getDashboardCiReposOwnerNameRuns(input: { "owner": string; "name": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/ci/repos/{owner}/{name}/runs", input ?? {}, [{"name":"owner","in":"path","required":true},{"name":"name","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/ci/repos/{owner}/{name}/runs/{runId}/jobs
   */
  getDashboardCiReposOwnerNameRunsRunIdJobs(input: { "owner": string; "name": string; "runId": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/ci/repos/{owner}/{name}/runs/{runId}/jobs", input ?? {}, [{"name":"owner","in":"path","required":true},{"name":"name","in":"path","required":true},{"name":"runId","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/ci/runner-history
   */
  getDashboardCiRunnerHistory(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/ci/runner-history", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/ci/status
   */
  getDashboardCiStatus(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/ci/status", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/cloud
   */
  getDashboardCloud(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/cloud", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/data/activity
   */
  getDashboardDataActivity(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/data/activity", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/data/subscribers
   */
  getDashboardDataSubscribers(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/data/subscribers", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/data/teams
   */
  getDashboardDataTeams(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/data/teams", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/data/users
   */
  getDashboardDataUsers(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/data/users", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/deployments
   */
  getDashboardDeployments(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/deployments", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/deployments
   */
  postDashboardDeployments(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/deployments", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/deployments/avg-time
   */
  getDashboardDeploymentsAvgTime(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/deployments/avg-time", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/deployments/count
   */
  getDashboardDeploymentsCount(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/deployments/count", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/deployments/preview
   */
  postDashboardDeploymentsPreview(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/deployments/preview", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/deployments/recent
   */
  getDashboardDeploymentsRecent(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/deployments/recent", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/deployments/rollback
   */
  postDashboardDeploymentsRollback(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/deployments/rollback", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/deployments/rollback/preview
   */
  postDashboardDeploymentsRollbackPreview(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/deployments/rollback/preview", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/deployments/script
   */
  getDashboardDeploymentsScript(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/deployments/script", {}, [], null, "application/json", [], options)
  },

  /**
   * PUT /api/dashboard/deployments/script
   */
  putDashboardDeploymentsScript(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PUT", "/api/dashboard/deployments/script", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/deployments/terminal
   */
  getDashboardDeploymentsTerminal(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/deployments/terminal", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/deployments/{id}
   */
  getDashboardDeploymentsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/deployments/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/dns
   */
  getDashboardDns(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/dns", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/email/activity
   */
  getDashboardEmailActivity(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/email/activity", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/email/captured
   */
  getDashboardEmailCaptured(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/email/captured", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/email/captured/{id}
   */
  getDashboardEmailCapturedId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/email/captured/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/email/inbox
   */
  getDashboardEmailInbox(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/email/inbox", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/email/inbox/{id}
   */
  getDashboardEmailInboxId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/email/inbox/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/email/inbox/{id}
   */
  deleteDashboardEmailInboxId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/email/inbox/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/email/inbox/{id}/attachments/{attachmentId}
   */
  getDashboardEmailInboxIdAttachmentsAttachmentId(input: { "id": string; "attachmentId": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/email/inbox/{id}/attachments/{attachmentId}", input ?? {}, [{"name":"id","in":"path","required":true},{"name":"attachmentId","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/email/preferences
   */
  getDashboardEmailPreferences(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/email/preferences", {}, [], null, "application/json", [], options)
  },

  /**
   * PUT /api/dashboard/email/preferences
   */
  putDashboardEmailPreferences(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PUT", "/api/dashboard/email/preferences", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/email/read
   */
  postDashboardEmailRead(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/email/read", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/email/send
   */
  postDashboardEmailSend(input: { body: { "to": string; "subject": string; "body": string } }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/email/send", input ?? {}, [], {"required":true,"content":["application/json"]}, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/email/stats
   */
  getDashboardEmailStats(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/email/stats", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/email/unread
   */
  postDashboardEmailUnread(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/email/unread", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/environment
   */
  getDashboardEnvironment(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/environment", {}, [], null, "application/json", [], options)
  },

  /**
   * PUT /api/dashboard/environment
   */
  putDashboardEnvironment(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PUT", "/api/dashboard/environment", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/event-metrics
   */
  getDashboardEventMetrics(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/event-metrics", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/files
   */
  getDashboardFiles(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/files", {}, [], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/files
   */
  deleteDashboardFiles(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/files", {}, [], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/files
   */
  patchDashboardFiles(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/files", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/files/directories
   */
  postDashboardFilesDirectories(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/files/directories", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/files/duplicates
   */
  postDashboardFilesDuplicates(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/files/duplicates", {}, [], null, "application/json", [], options)
  },

  /**
   * PUT /api/dashboard/files/favorite
   */
  putDashboardFilesFavorite(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PUT", "/api/dashboard/files/favorite", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/files/reprocess
   */
  postDashboardFilesReprocess(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/files/reprocess", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/files/uploads
   */
  postDashboardFilesUploads(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/files/uploads", {}, [], null, "application/json", [], options)
  },

  /**
   * PUT /api/dashboard/files/visibility
   */
  putDashboardFilesVisibility(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PUT", "/api/dashboard/files/visibility", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/health
   */
  getDashboardHealth(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/health", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/insights
   */
  getDashboardInsights(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/insights", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/jobs
   */
  getDashboardJobs(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/jobs", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/jobs/definitions
   */
  getDashboardJobsDefinitions(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/jobs/definitions", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/jobs/stats
   */
  getDashboardJobsStats(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/jobs/stats", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/jobs/{id}
   */
  getDashboardJobsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/jobs/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/jobs/{id}/retry
   */
  postDashboardJobsIdRetry(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/jobs/{id}/retry", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/kanban/boards
   */
  getDashboardKanbanBoards(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/kanban/boards", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/kanban/boards
   */
  postDashboardKanbanBoards(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/kanban/boards", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/kanban/boards/reorder
   */
  postDashboardKanbanBoardsReorder(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/kanban/boards/reorder", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/kanban/boards/{id}
   */
  getDashboardKanbanBoardsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/kanban/boards/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/kanban/boards/{id}
   */
  deleteDashboardKanbanBoardsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/kanban/boards/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/kanban/boards/{id}
   */
  patchDashboardKanbanBoardsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/kanban/boards/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/kanban/cards
   */
  postDashboardKanbanCards(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/kanban/cards", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/kanban/cards/reorder
   */
  postDashboardKanbanCardsReorder(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/kanban/cards/reorder", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/kanban/cards/{id}
   */
  getDashboardKanbanCardsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/kanban/cards/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/kanban/cards/{id}
   */
  deleteDashboardKanbanCardsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/kanban/cards/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/kanban/cards/{id}
   */
  patchDashboardKanbanCardsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/kanban/cards/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/kanban/cards/{id}/assignees
   */
  postDashboardKanbanCardsIdAssignees(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/kanban/cards/{id}/assignees", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/kanban/cards/{id}/labels
   */
  postDashboardKanbanCardsIdLabels(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/kanban/cards/{id}/labels", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/kanban/columns
   */
  postDashboardKanbanColumns(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/kanban/columns", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/kanban/columns/reorder
   */
  postDashboardKanbanColumnsReorder(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/kanban/columns/reorder", {}, [], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/kanban/columns/{id}
   */
  deleteDashboardKanbanColumnsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/kanban/columns/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/kanban/columns/{id}
   */
  patchDashboardKanbanColumnsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/kanban/columns/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/kanban/labels
   */
  postDashboardKanbanLabels(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/kanban/labels", {}, [], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/kanban/labels/{id}
   */
  deleteDashboardKanbanLabelsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/kanban/labels/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/kanban/labels/{id}
   */
  patchDashboardKanbanLabelsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/kanban/labels/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/kanban/users
   */
  getDashboardKanbanUsers(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/kanban/users", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/library/components
   */
  getDashboardLibraryComponents(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/library/components", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/library/components
   */
  postDashboardLibraryComponents(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/library/components", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/library/dependencies
   */
  getDashboardLibraryDependencies(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/library/dependencies", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/library/functions
   */
  getDashboardLibraryFunctions(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/library/functions", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/library/functions
   */
  postDashboardLibraryFunctions(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/library/functions", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/library/packages
   */
  getDashboardLibraryPackages(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/library/packages", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/logs
   */
  getDashboardLogs(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/logs", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/mail-settings
   */
  getDashboardMailSettings(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/mail-settings", {}, [], null, "application/json", [], options)
  },

  /**
   * PUT /api/dashboard/mail-settings
   */
  putDashboardMailSettings(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PUT", "/api/dashboard/mail-settings", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/mailboxes
   */
  getDashboardMailboxes(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/mailboxes", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/markdown
   */
  postDashboardMarkdown(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/markdown", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/marketing/abandoned-carts/campaign
   */
  postDashboardMarketingAbandonedCartsCampaign(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/marketing/abandoned-carts/campaign", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/marketing/campaigns
   */
  getDashboardMarketingCampaigns(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/marketing/campaigns", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/marketing/campaigns
   */
  postDashboardMarketingCampaigns(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/marketing/campaigns", {}, [], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/marketing/campaigns/{id}
   */
  deleteDashboardMarketingCampaignsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/marketing/campaigns/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/marketing/campaigns/{id}
   */
  patchDashboardMarketingCampaignsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/marketing/campaigns/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/marketing/campaigns/{id}/cancel
   */
  postDashboardMarketingCampaignsIdCancel(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/marketing/campaigns/{id}/cancel", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/marketing/campaigns/{id}/schedule
   */
  postDashboardMarketingCampaignsIdSchedule(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/marketing/campaigns/{id}/schedule", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/marketing/campaigns/{id}/send
   */
  postDashboardMarketingCampaignsIdSend(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/marketing/campaigns/{id}/send", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/marketing/lists
   */
  getDashboardMarketingLists(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/marketing/lists", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/marketing/lists
   */
  postDashboardMarketingLists(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/marketing/lists", {}, [], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/marketing/lists/{id}
   */
  deleteDashboardMarketingListsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/marketing/lists/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/marketing/lists/{id}
   */
  patchDashboardMarketingListsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/marketing/lists/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/marketing/social-posts
   */
  getDashboardMarketingSocialPosts(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/marketing/social-posts", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/marketing/social-posts
   */
  postDashboardMarketingSocialPosts(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/marketing/social-posts", {}, [], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/marketing/social-posts/{id}
   */
  deleteDashboardMarketingSocialPostsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/marketing/social-posts/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/marketing/social-posts/{id}
   */
  patchDashboardMarketingSocialPostsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/marketing/social-posts/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/models
   */
  getDashboardModels(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/models", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/models/{dashboardModel}/{id}/actions/{dashboardAction}
   */
  postDashboardModelsDashboardModelIdActionsDashboardAction(input: { "dashboardModel": string; "id": string; "dashboardAction": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/models/{dashboardModel}/{id}/actions/{dashboardAction}", input ?? {}, [{"name":"dashboardModel","in":"path","required":true},{"name":"id","in":"path","required":true},{"name":"dashboardAction","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/models/{slug}
   */
  getDashboardModelsSlug(input: { "slug": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/models/{slug}", input ?? {}, [{"name":"slug","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/models/{slug}
   */
  postDashboardModelsSlug(input: { "slug": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/models/{slug}", input ?? {}, [{"name":"slug","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/models/{slug}/options
   */
  getDashboardModelsSlugOptions(input: { "slug": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/models/{slug}/options", input ?? {}, [{"name":"slug","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/models/{slug}/uploads
   */
  postDashboardModelsSlugUploads(input: { "slug": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/models/{slug}/uploads", input ?? {}, [{"name":"slug","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/models/{slug}/{id}
   */
  deleteDashboardModelsSlugId(input: { "slug": string; "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/models/{slug}/{id}", input ?? {}, [{"name":"slug","in":"path","required":true},{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/models/{slug}/{id}
   */
  patchDashboardModelsSlugId(input: { "slug": string; "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/models/{slug}/{id}", input ?? {}, [{"name":"slug","in":"path","required":true},{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/models/{slug}/{id}/related
   */
  getDashboardModelsSlugIdRelated(input: { "slug": string; "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/models/{slug}/{id}/related", input ?? {}, [{"name":"slug","in":"path","required":true},{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/models/{slug}/{id}/save
   */
  patchDashboardModelsSlugIdSave(input: { "slug": string; "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/models/{slug}/{id}/save", input ?? {}, [{"name":"slug","in":"path","required":true},{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/monitoring/errors
   */
  getDashboardMonitoringErrors(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/monitoring/errors", {}, [], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/monitoring/errors
   */
  deleteDashboardMonitoringErrors(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/monitoring/errors", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/monitoring/errors/group
   */
  getDashboardMonitoringErrorsGroup(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/monitoring/errors/group", {}, [], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/monitoring/errors/ignore
   */
  patchDashboardMonitoringErrorsIgnore(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/monitoring/errors/ignore", {}, [], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/monitoring/errors/resolve
   */
  patchDashboardMonitoringErrorsResolve(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/monitoring/errors/resolve", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/monitoring/errors/stats
   */
  getDashboardMonitoringErrorsStats(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/monitoring/errors/stats", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/monitoring/errors/timeline
   */
  getDashboardMonitoringErrorsTimeline(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/monitoring/errors/timeline", {}, [], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/monitoring/errors/unresolve
   */
  patchDashboardMonitoringErrorsUnresolve(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/monitoring/errors/unresolve", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/monitoring/errors/{id}
   */
  getDashboardMonitoringErrorsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/monitoring/errors/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/notification-deliveries
   */
  getDashboardNotificationDeliveries(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/notification-deliveries", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/notification-deliveries/history
   */
  getDashboardNotificationDeliveriesHistory(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/notification-deliveries/history", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/notification-deliveries/overview
   */
  getDashboardNotificationDeliveriesOverview(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/notification-deliveries/overview", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/notification-deliveries/{id}/retry
   */
  postDashboardNotificationDeliveriesIdRetry(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/notification-deliveries/{id}/retry", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/operations/audit
   */
  getDashboardOperationsAudit(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/operations/audit", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/operations/changes
   */
  getDashboardOperationsChanges(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/operations/changes", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/operations/changes/releases/{id}/decision
   */
  postDashboardOperationsChangesReleasesIdDecision(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/operations/changes/releases/{id}/decision", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/operations/incidents
   */
  getDashboardOperationsIncidents(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/operations/incidents", {}, [], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/operations/incidents/{id}
   */
  patchDashboardOperationsIncidentsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/operations/incidents/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/operations/migrations
   */
  getDashboardOperationsMigrations(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/operations/migrations", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/operations/migrations/apply
   */
  postDashboardOperationsMigrationsApply(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/operations/migrations/apply", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/operations/migrations/reconcile
   */
  postDashboardOperationsMigrationsReconcile(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/operations/migrations/reconcile", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/operations/recovery
   */
  getDashboardOperationsRecovery(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/operations/recovery", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/operations/recovery/destinations
   */
  postDashboardOperationsRecoveryDestinations(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/operations/recovery/destinations", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/operations/recovery/destinations/{id}/test
   */
  postDashboardOperationsRecoveryDestinationsIdTest(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/operations/recovery/destinations/{id}/test", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/operations/recovery/points/{id}/protection
   */
  patchDashboardOperationsRecoveryPointsIdProtection(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/operations/recovery/points/{id}/protection", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/operations/recovery/points/{id}/restore
   */
  postDashboardOperationsRecoveryPointsIdRestore(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/operations/recovery/points/{id}/restore", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/operations/recovery/points/{id}/verify
   */
  postDashboardOperationsRecoveryPointsIdVerify(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/operations/recovery/points/{id}/verify", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/operations/recovery/policies
   */
  postDashboardOperationsRecoveryPolicies(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/operations/recovery/policies", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/operations/recovery/policies/{id}/run
   */
  postDashboardOperationsRecoveryPoliciesIdRun(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/operations/recovery/policies/{id}/run", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/operations/recovery/retention
   */
  postDashboardOperationsRecoveryRetention(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/operations/recovery/retention", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/operations/scheduler
   */
  getDashboardOperationsScheduler(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/operations/scheduler", {}, [], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/operations/scheduler/{name}
   */
  patchDashboardOperationsSchedulerName(input: { "name": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/operations/scheduler/{name}", input ?? {}, [{"name":"name","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/operations/scheduler/{name}/run
   */
  postDashboardOperationsSchedulerNameRun(input: { "name": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/operations/scheduler/{name}/run", input ?? {}, [{"name":"name","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/queries
   */
  getDashboardQueries(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/queries", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/queries/{id}
   */
  getDashboardQueriesId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/queries/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/queue/retry-failed
   */
  postDashboardQueueRetryFailed(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/queue/retry-failed", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/queue/stats
   */
  getDashboardQueueStats(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/queue/stats", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/queue/workers
   */
  getDashboardQueueWorkers(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/queue/workers", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/rbac/permissions
   */
  getDashboardRbacPermissions(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/rbac/permissions", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/rbac/permissions
   */
  postDashboardRbacPermissions(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/rbac/permissions", {}, [], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/rbac/permissions/{name}
   */
  deleteDashboardRbacPermissionsName(input: { "name": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/rbac/permissions/{name}", input ?? {}, [{"name":"name","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/rbac/roles
   */
  getDashboardRbacRoles(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/rbac/roles", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/rbac/roles
   */
  postDashboardRbacRoles(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/rbac/roles", {}, [], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/rbac/roles/{name}
   */
  deleteDashboardRbacRolesName(input: { "name": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/rbac/roles/{name}", input ?? {}, [{"name":"name","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/rbac/roles/{name}/permissions
   */
  getDashboardRbacRolesNamePermissions(input: { "name": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/rbac/roles/{name}/permissions", input ?? {}, [{"name":"name","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/rbac/roles/{name}/permissions
   */
  postDashboardRbacRolesNamePermissions(input: { "name": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/rbac/roles/{name}/permissions", input ?? {}, [{"name":"name","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/rbac/users
   */
  getDashboardRbacUsers(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/rbac/users", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/rbac/users/{id}/roles
   */
  getDashboardRbacUsersIdRoles(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/rbac/users/{id}/roles", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/rbac/users/{id}/roles
   */
  postDashboardRbacUsersIdRoles(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/rbac/users/{id}/roles", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/realtime
   */
  getDashboardRealtime(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/realtime", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/releases
   */
  getDashboardReleases(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/releases", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/remote/commands
   */
  getDashboardRemoteCommands(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/remote/commands", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/remote/run
   */
  postDashboardRemoteRun(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/remote/run", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/remote/terminals
   */
  postDashboardRemoteTerminals(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/remote/terminals", {}, [], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/remote/terminals/{id}
   */
  deleteDashboardRemoteTerminalsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/remote/terminals/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/remote/terminals/{id}/input
   */
  postDashboardRemoteTerminalsIdInput(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/remote/terminals/{id}/input", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/remote/terminals/{id}/resize
   */
  postDashboardRemoteTerminalsIdResize(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/remote/terminals/{id}/resize", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/remote/terminals/{id}/stream
   */
  getDashboardRemoteTerminalsIdStream(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/remote/terminals/{id}/stream", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/requests
   */
  getDashboardRequests(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/requests", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/search-engine
   */
  getDashboardSearchEngine(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/search-engine", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/serverless
   */
  getDashboardServerless(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/serverless", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/servers
   */
  getDashboardServers(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/servers", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/servers/{id}
   */
  getDashboardServersId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/servers/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/sidebar-order
   */
  getDashboardSidebarOrder(options?: RequestOptions): Promise<ApiResult<{ [key: string]: unknown }>> {
    return request(config, "GET", "/api/dashboard/sidebar-order", {}, [], null, "application/json", [], options)
  },

  /**
   * PUT /api/dashboard/sidebar-order
   */
  putDashboardSidebarOrder(input: { body: { "order": Record<string, unknown>; "scope": string } }, options?: RequestOptions): Promise<ApiResult<{ [key: string]: unknown }>> {
    return request(config, "PUT", "/api/dashboard/sidebar-order", input ?? {}, [], {"required":true,"content":["application/json"]}, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/source/actions
   */
  getDashboardSourceActions(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/source/actions", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/source/commands
   */
  getDashboardSourceCommands(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/source/commands", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/teams/{id}/invitations
   */
  postDashboardTeamsIdInvitations(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/teams/{id}/invitations", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/teams/{id}/invitations/{invitationId}
   */
  deleteDashboardTeamsIdInvitationsInvitationId(input: { "id": string; "invitationId": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/teams/{id}/invitations/{invitationId}", input ?? {}, [{"name":"id","in":"path","required":true},{"name":"invitationId","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/teams/{id}/invitations/{invitationId}/resend
   */
  postDashboardTeamsIdInvitationsInvitationIdResend(input: { "id": string; "invitationId": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/teams/{id}/invitations/{invitationId}/resend", input ?? {}, [{"name":"id","in":"path","required":true},{"name":"invitationId","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * DELETE /api/dashboard/teams/{id}/members/{memberId}
   */
  deleteDashboardTeamsIdMembersMemberId(input: { "id": string; "memberId": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/dashboard/teams/{id}/members/{memberId}", input ?? {}, [{"name":"id","in":"path","required":true},{"name":"memberId","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * PATCH /api/dashboard/teams/{id}/members/{memberId}
   */
  patchDashboardTeamsIdMembersMemberId(input: { "id": string; "memberId": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/dashboard/teams/{id}/members/{memberId}", input ?? {}, [{"name":"id","in":"path","required":true},{"name":"memberId","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/dashboard/teams/{id}/people
   */
  getDashboardTeamsIdPeople(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/dashboard/teams/{id}/people", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/dashboard/users/invitations
   */
  postDashboardUsersInvitations(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/dashboard/users/invitations", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/data/activity
   */
  getDataActivity(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/data/activity", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/data/subscribers
   */
  getDataSubscribers(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/data/subscribers", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/data/teams
   */
  getDataTeams(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/data/teams", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/data/users
   */
  getDataUsers(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/data/users", {}, [], null, "application/json", [], options)
  },

  /**
   * email.subscribe
   */
  emailSubscribe(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/email/subscribe", {}, [], null, "application/json", [], options)
  },

  /**
   * email.unsubscribe
   */
  emailUnsubscribe(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/email/unsubscribe", {}, [], null, "application/json", [], options)
  },

  /**
   * email.unsubscribe
   */
  emailUnsubscribePost(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/email/unsubscribe", {}, [], null, "application/json", [], options)
  },

  /**
   * feedback.store
   */
  feedbackStore(input: { "token": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/feedback/{token}", input ?? {}, [{"name":"token","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/hello
   */
  getHello(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/hello", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/hosts/enrol
   */
  postHostsEnrol(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/hosts/enrol", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/hosts/enrolment-tokens
   */
  postHostsEnrolmentTokens(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/hosts/enrolment-tokens", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/hosts/{id}/revoke
   */
  postHostsIdRevoke(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/hosts/{id}/revoke", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/hosts/{id}/rotate
   */
  postHostsIdRotate(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/hosts/{id}/rotate", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/ingest/cve
   */
  postIngestCve(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/ingest/cve", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/ingest/findings
   */
  postIngestFindings(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/ingest/findings", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/ingest/heartbeat
   */
  postIngestHeartbeat(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/ingest/heartbeat", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/ingest/scans
   */
  postIngestScans(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/ingest/scans", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/ingest/waf
   */
  postIngestWaf(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/ingest/waf", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/marketing/campaigns
   */
  getMarketingCampaigns(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/marketing/campaigns", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/marketing/lists
   */
  getMarketingLists(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/marketing/lists", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/marketing/social-posts
   */
  getMarketingSocialPosts(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/marketing/social-posts", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/monitoring/errors
   */
  getMonitoringErrors(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/monitoring/errors", {}, [], null, "application/json", [], options)
  },

  /**
   * DELETE /api/monitoring/errors
   */
  deleteMonitoringErrors(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/api/monitoring/errors", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/monitoring/errors/group
   */
  getMonitoringErrorsGroup(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/monitoring/errors/group", {}, [], null, "application/json", [], options)
  },

  /**
   * PATCH /api/monitoring/errors/ignore
   */
  patchMonitoringErrorsIgnore(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/monitoring/errors/ignore", {}, [], null, "application/json", [], options)
  },

  /**
   * PATCH /api/monitoring/errors/resolve
   */
  patchMonitoringErrorsResolve(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/monitoring/errors/resolve", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/monitoring/errors/stats
   */
  getMonitoringErrorsStats(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/monitoring/errors/stats", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/monitoring/errors/timeline
   */
  getMonitoringErrorsTimeline(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/monitoring/errors/timeline", {}, [], null, "application/json", [], options)
  },

  /**
   * PATCH /api/monitoring/errors/unresolve
   */
  patchMonitoringErrorsUnresolve(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/api/monitoring/errors/unresolve", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/monitoring/errors/{id}
   */
  getMonitoringErrorsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/monitoring/errors/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/notifications/dashboard
   */
  getNotificationsDashboard(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/notifications/dashboard", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/notifications/email
   */
  getNotificationsEmail(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/notifications/email", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/notifications/history
   */
  getNotificationsHistory(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/notifications/history", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/notifications/sms
   */
  getNotificationsSms(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/notifications/sms", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/queries/dashboard
   */
  getQueriesDashboard(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/queries/dashboard", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/queries/frequent
   */
  getQueriesFrequent(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/queries/frequent", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /api/queries/prune
   */
  postQueriesPrune(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/queries/prune", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/queries/recent
   */
  getQueriesRecent(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/queries/recent", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/queries/slow
   */
  getQueriesSlow(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/queries/slow", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/queries/stats
   */
  getQueriesStats(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/queries/stats", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/queries/timeline
   */
  getQueriesTimeline(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/queries/timeline", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/queries/{id}
   */
  getQueriesId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/queries/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /api/serverless
   */
  getServerless(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/serverless", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/settings/mail
   */
  getSettingsMail(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/settings/mail", {}, [], null, "application/json", [], options)
  },

  /**
   * PUT /api/settings/mail
   */
  putSettingsMail(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PUT", "/api/settings/mail", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /api/team-invitation-links/{token}
   */
  getTeamInvitationLinksToken(input: { "token": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/api/team-invitation-links/{token}", input ?? {}, [{"name":"token","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /api/team-invitations/{token}/accept
   */
  postTeamInvitationsTokenAccept(input: { "token": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/api/team-invitations/{token}/accept", input ?? {}, [{"name":"token","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /auth/abilities
   */
  getAuthAbilities(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/auth/abilities", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /auth/magic-link
   */
  postAuthMagicLink(input: { body: { "email": string } }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/auth/magic-link", input ?? {}, [], {"required":true,"content":["application/json"]}, "application/json", [], options)
  },

  /**
   * POST /auth/magic-link/consume
   */
  postAuthMagicLinkConsume(input: { body: { "token": string } }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/auth/magic-link/consume", input ?? {}, [], {"required":true,"content":["application/json"]}, "application/json", [], options)
  },

  /**
   * GET /auth/oauth/clients
   */
  getAuthOauthClients(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/auth/oauth/clients", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /auth/oauth/clients
   */
  postAuthOauthClients(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/auth/oauth/clients", {}, [], null, "application/json", [], options)
  },

  /**
   * PATCH /auth/oauth/clients/{id}
   */
  patchAuthOauthClientsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/auth/oauth/clients/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /auth/oauth/clients/{id}/disable
   */
  postAuthOauthClientsIdDisable(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/auth/oauth/clients/{id}/disable", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /auth/oauth/clients/{id}/rotate-secret
   */
  postAuthOauthClientsIdRotateSecret(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/auth/oauth/clients/{id}/rotate-secret", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /auth/oauth/connections
   */
  getAuthOauthConnections(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/auth/oauth/connections", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /auth/oauth/connections/{id}/disconnect
   */
  postAuthOauthConnectionsIdDisconnect(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/auth/oauth/connections/{id}/disconnect", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /auth/passkeys
   */
  getAuthPasskeys(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/auth/passkeys", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /auth/passkeys/authentication
   */
  postAuthPasskeysAuthentication(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/auth/passkeys/authentication", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /auth/passkeys/authentication/options
   */
  postAuthPasskeysAuthenticationOptions(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/auth/passkeys/authentication/options", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /auth/passkeys/registration
   */
  postAuthPasskeysRegistration(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/auth/passkeys/registration", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /auth/passkeys/registration/options
   */
  postAuthPasskeysRegistrationOptions(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/auth/passkeys/registration/options", {}, [], null, "application/json", [], options)
  },

  /**
   * DELETE /auth/passkeys/{id}
   */
  deleteAuthPasskeysId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/auth/passkeys/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /auth/refresh
   */
  postAuthRefresh(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/auth/refresh", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /auth/token
   */
  postAuthToken(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/auth/token", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /auth/tokens
   */
  getAuthTokens(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/auth/tokens", {}, [], null, "application/json", [], options)
  },

  /**
   * DELETE /auth/tokens/{id}
   */
  deleteAuthTokensId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/auth/tokens/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /dashboard/activity
   */
  getDashboardActivity2(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/dashboard/activity", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /dashboard/buddy
   */
  getDashboardBuddy(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/dashboard/buddy", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /dashboard/health
   */
  getDashboardHealth2(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/dashboard/health", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /dashboard/services
   */
  getDashboardServices(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/dashboard/services", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /dashboard/settings
   */
  getDashboardSettings(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/dashboard/settings", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /deployments/
   */
  getDeployments(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/deployments/", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /deployments/
   */
  postDeployments(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/deployments/", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /deployments/avg-time
   */
  getDeploymentsAvgTime(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/deployments/avg-time", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /deployments/count
   */
  getDeploymentsCount(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/deployments/count", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /deployments/preview
   */
  postDeploymentsPreview(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/deployments/preview", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /deployments/recent
   */
  getDeploymentsRecent(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/deployments/recent", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /deployments/script
   */
  getDeploymentsScript(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/deployments/script", {}, [], null, "application/json", [], options)
  },

  /**
   * PUT /deployments/script
   */
  putDeploymentsScript(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PUT", "/deployments/script", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /deployments/terminal
   */
  getDeploymentsTerminal(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/deployments/terminal", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /disable-two-factor
   */
  postDisableTwoFactor(input: { body: { "password": string } }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/disable-two-factor", input ?? {}, [], {"required":true,"content":["application/json"]}, "application/json", [], options)
  },

  /**
   * POST /enable-two-factor
   */
  postEnableTwoFactor(input: { body: { "code": string } }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/enable-two-factor", input ?? {}, [], {"required":true,"content":["application/json"]}, "application/json", [], options)
  },

  /**
   * GET /generate-authentication-options
   */
  getGenerateAuthenticationOptions(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/generate-authentication-options", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /generate-registration-options
   */
  getGenerateRegistrationOptions(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/generate-registration-options", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /generate-two-factor-secret
   */
  postGenerateTwoFactorSecret(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/generate-two-factor-secret", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /infrastructure/cloud
   */
  getInfrastructureCloud(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/infrastructure/cloud", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /infrastructure/dns
   */
  getInfrastructureDns(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/infrastructure/dns", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /infrastructure/environment
   */
  getInfrastructureEnvironment(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/infrastructure/environment", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /infrastructure/insights
   */
  getInfrastructureInsights(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/infrastructure/insights", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /infrastructure/logs
   */
  getInfrastructureLogs(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/infrastructure/logs", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /infrastructure/mailboxes
   */
  getInfrastructureMailboxes(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/infrastructure/mailboxes", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /infrastructure/permissions
   */
  getInfrastructurePermissions(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/infrastructure/permissions", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /infrastructure/servers
   */
  getInfrastructureServers(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/infrastructure/servers", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /install
   */
  getInstall(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/install", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /jobs/
   */
  getJobs(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/jobs/", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /jobs/stats
   */
  getJobsStats(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/jobs/stats", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /jobs/{id}/retry
   */
  postJobsIdRetry(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/jobs/{id}/retry", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /library/components
   */
  getLibraryComponents(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/library/components", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /library/components
   */
  postLibraryComponents(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/library/components", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /library/components/downloads
   */
  getLibraryComponentsDownloads(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/library/components/downloads", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /library/dependencies
   */
  getLibraryDependencies(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/library/dependencies", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /library/downloads
   */
  getLibraryDownloads(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/library/downloads", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /library/functions
   */
  getLibraryFunctions(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/library/functions", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /library/functions
   */
  postLibraryFunctions(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/library/functions", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /library/functions/downloads
   */
  getLibraryFunctionsDownloads(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/library/functions/downloads", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /library/packages
   */
  getLibraryPackages(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/library/packages", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /library/releases
   */
  getLibraryReleases(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/library/releases", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /library/releases/avg-time
   */
  getLibraryReleasesAvgTime(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/library/releases/avg-time", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /library/releases/count
   */
  getLibraryReleasesCount(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/library/releases/count", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /locale/{locale}
   */
  getLocaleLocale(input: { "locale": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/locale/{locale}", input ?? {}, [{"name":"locale","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /login
   */
  postLogin(input: { body: { "email": string; "password": string } }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/login", input ?? {}, [], {"required":true,"content":["application/json"]}, "application/json", [], options)
  },

  /**
   * POST /logout
   */
  postLogout(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/logout", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /logout-all
   */
  postLogoutAll(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/logout-all", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /me
   */
  getMe(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/me", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /me/data-export
   */
  getMeDataExport(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/me/data-export", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /models/
   */
  getModels(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/models/", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /models/subscriber-count
   */
  getModelsSubscriberCount(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/models/subscriber-count", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /models/user-count
   */
  getModelsUserCount(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/models/user-count", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /oauth/authorize
   */
  getOauthAuthorize(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/oauth/authorize", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /oauth/authorize
   */
  postOauthAuthorize(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/oauth/authorize", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /oauth/introspect
   */
  postOauthIntrospect(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/oauth/introspect", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /oauth/revoke
   */
  postOauthRevoke(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/oauth/revoke", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /oauth/token
   */
  postOauthToken(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/oauth/token", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /password/forgot
   */
  postPasswordForgot(input: { body: { "email": string } }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/password/forgot", input ?? {}, [], {"required":true,"content":["application/json"]}, "application/json", [], options)
  },

  /**
   * POST /password/reset
   */
  postPasswordReset(input: { body: { "email": string; "token": string; "password": string } }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/password/reset", input ?? {}, [], {"required":true,"content":["application/json"]}, "application/json", [], options)
  },

  /**
   * POST /password/verify-token
   */
  postPasswordVerifyToken(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/password/verify-token", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /payments/checkout/{id}
   */
  postPaymentsCheckoutId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/payments/checkout/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /payments/create-setup-intent/{id}
   */
  getPaymentsCreateSetupIntentId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/payments/create-setup-intent/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /payments/default-payment-method/{id}
   */
  getPaymentsDefaultPaymentMethodId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/payments/default-payment-method/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * DELETE /payments/delete-payment-method/{id}
   */
  deletePaymentsDeletePaymentMethodId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "DELETE", "/payments/delete-payment-method/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /payments/fetch-active-subscription/{id}
   */
  getPaymentsFetchActiveSubscriptionId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/payments/fetch-active-subscription/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /payments/fetch-customer/{id}
   */
  getPaymentsFetchCustomerId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/payments/fetch-customer/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /payments/fetch-user-subscriptions/{id}
   */
  getPaymentsFetchUserSubscriptionsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/payments/fetch-user-subscriptions/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /payments/payment-method/{id}
   */
  postPaymentsPaymentMethodId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/payments/payment-method/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * GET /payments/payment-methods/{id}
   */
  getPaymentsPaymentMethodsId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/payments/payment-methods/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /payments/set-default-payment-method/{id}
   */
  postPaymentsSetDefaultPaymentMethodId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/payments/set-default-payment-method/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /payments/store-transaction/{id}
   */
  postPaymentsStoreTransactionId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/payments/store-transaction/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * PATCH /payments/update-customer/{id}
   */
  patchPaymentsUpdateCustomerId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PATCH", "/payments/update-customer/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * PUT /payments/update-default-payment-method/{id}
   */
  putPaymentsUpdateDefaultPaymentMethodId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "PUT", "/payments/update-default-payment-method/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /payments/user-default-payment-method/{id}
   */
  postPaymentsUserDefaultPaymentMethodId(input: { "id": string }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/payments/user-default-payment-method/{id}", input ?? {}, [{"name":"id","in":"path","required":true}], null, "application/json", [], options)
  },

  /**
   * POST /queue/retry-failed
   */
  postQueueRetryFailed(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/queue/retry-failed", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /queue/stats
   */
  getQueueStats(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/queue/stats", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /queue/workers
   */
  getQueueWorkers(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/queue/workers", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /queues/
   */
  getQueues(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/queues/", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /realtime/stats
   */
  getRealtimeStats(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/realtime/stats", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /realtime/websockets
   */
  getRealtimeWebsockets(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/realtime/websockets", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /referrals
   */
  getReferrals(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/referrals", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /referrals/code
   */
  postReferralsCode(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/referrals/code", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /register
   */
  postRegister(input: { body: { "email": string; "password": string; "name": string } }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/register", input ?? {}, [], {"required":true,"content":["application/json"]}, "application/json", [], options)
  },

  /**
   * GET /releases/
   */
  getReleases(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/releases/", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /releases/stats
   */
  getReleasesStats(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/releases/stats", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /robots.txt
   */
  getRobotsTxt(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/robots.txt", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /verify-authentication
   */
  postVerifyAuthentication(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/verify-authentication", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /verify-registration
   */
  postVerifyRegistration(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/verify-registration", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /verify-two-factor-login
   */
  postVerifyTwoFactorLogin(input: { body: { "challenge_token": string; "code": string } }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/verify-two-factor-login", input ?? {}, [], {"required":true,"content":["application/json"]}, "application/json", [], options)
  },

  /**
   * POST /voide/browse
   */
  postVoideBrowse(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/voide/browse", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /voide/cancel
   */
  postVoideCancel(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/voide/cancel", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /voide/commit
   */
  postVoideCommit(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/voide/commit", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /voide/github/connect
   */
  postVoideGithubConnect(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/voide/github/connect", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /voide/github/disconnect
   */
  postVoideGithubDisconnect(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/voide/github/disconnect", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /voide/process
   */
  postVoideProcess(input: { body: { "command": string } }, options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/voide/process", input ?? {}, [], {"required":true,"content":["application/json"]}, "application/json", [], options)
  },

  /**
   * POST /voide/process/stream
   */
  postVoideProcessStream(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/voide/process/stream", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /voide/push
   */
  postVoidePush(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/voide/push", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /voide/repo
   */
  postVoideRepo(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/voide/repo", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /voide/repo/validate
   */
  postVoideRepoValidate(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/voide/repo/validate", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /voide/settings
   */
  getVoideSettings(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/voide/settings", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /voide/settings
   */
  postVoideSettings(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/voide/settings", {}, [], null, "application/json", [], options)
  },

  /**
   * GET /voide/state
   */
  getVoideState(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "GET", "/voide/state", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /voide/title
   */
  postVoideTitle(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/voide/title", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /webhooks/email/mailgun
   */
  postWebhooksEmailMailgun(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/webhooks/email/mailgun", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /webhooks/email/postmark
   */
  postWebhooksEmailPostmark(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/webhooks/email/postmark", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /webhooks/email/sendgrid
   */
  postWebhooksEmailSendgrid(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/webhooks/email/sendgrid", {}, [], null, "application/json", [], options)
  },

  /**
   * POST /webhooks/email/ses
   */
  postWebhooksEmailSes(options?: RequestOptions): Promise<ApiResult<Record<string, unknown>>> {
    return request(config, "POST", "/webhooks/email/ses", {}, [], null, "application/json", [], options)
  },
  }
}
export type Client = ReturnType<typeof createClient>
