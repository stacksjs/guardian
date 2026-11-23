import { rateLimit, response, route } from '@stacksjs/router'
import { readJsonBody, readTextBody } from '@stacksjs/router/body'
import { feedBlobResponse, feedKeyInfo, feedManifestResponse } from '../app/Guardian/feed'
import type { EnrolInput } from '../app/Guardian/ingest'
import {
  createEnrolmentToken,
  enrolHost,
  heartbeat,
  ingestCveExposure,
  ingestFindings,
  ingestScans,
  ingestWafEvents,
  parseOcsf,
  parseWafEvents,
  revokeHost,
  rotateCredential,
} from '../app/Guardian/ingest'

/**
 * Guardian's host API, mounted under `/api` (see app/Routes.ts).
 *
 * Hosts authenticate with their bearer credential (`host` middleware). Bodies are read with byte
 * limits; every batch endpoint is idempotent (see app/Guardian/ingest.ts). Feed distribution
 * (rule pack and CVE index, signed manifests, conditional requests) is in app/Guardian/feed.ts.
 */

const SMALL = 64 * 1024
const BATCH = 16 * 1024 * 1024

// Enrolment: exchange a single-use token for a host credential. The enrolment token in the body is
// the credential, and an agent is not a browser holding a CSRF cookie, so the CSRF check is off.
route.post('/hosts/enrol', async (request: any) => {
  return response.json(enrolHost(await readJsonBody(request, SMALL) as EnrolInput), 201)
}).parseBody(false).skipCsrf().rateLimit(10, 'minute')

// Operator actions: signed-in accounts holding the operator role (app/Middleware/Operator.ts).
route.post('/hosts/enrolment-tokens', async (request: any) => {
  const body = await readJsonBody(request, SMALL).catch(() => ({})) as { label?: string, ttlHours?: number }
  return response.json({ token: createEnrolmentToken(body.label ?? null, body.ttlHours ?? 24) }, 201)
}).parseBody(false).middleware('auth').middleware('operator')

route.post('/hosts/{id}/rotate', (request: any) => {
  return response.json({ credential: rotateCredential(Number(request.params.id)) })
}).middleware('auth').middleware('operator')

route.post('/hosts/{id}/revoke', (request: any) => {
  revokeHost(Number(request.params.id))
  return response.json({ revoked: true })
}).middleware('auth').middleware('operator')

// Ingest (enrolled hosts).
route.post('/ingest/heartbeat', async (request: any) => {
  heartbeat(request.guardianHost, await readJsonBody(request, SMALL) as Record<string, unknown>)
  return response.json({ ok: true })
}).parseBody(false).middleware('host').rateLimit(120, 'minute')

route.post('/ingest/scans', async (request: any) => {
  const body = await readJsonBody(request, BATCH) as { scans?: unknown }
  return response.json(ingestScans(request.guardianHost, body.scans))
}).parseBody(false).middleware('host').rateLimit(600, 'minute')

route.post('/ingest/findings', async (request: any) => {
  const body = await readJsonBody(request, BATCH) as { findings?: unknown }
  return response.json(ingestFindings(request.guardianHost, body.findings))
}).parseBody(false).middleware('host').rateLimit(120, 'minute')

route.post('/ingest/cve', async (request: any) => {
  return response.json(ingestCveExposure(request.guardianHost, await readJsonBody(request, BATCH) as Record<string, unknown>))
}).parseBody(false).middleware('host').rateLimit(60, 'minute')

// WAF events: Guardian JSON (`{ "events": [...] }`) or zig-waf OCSF lines from ts-cloud's forwarder.
route.post('/ingest/waf', async (request: any) => {
  const type = String(request.headers?.get?.('content-type') ?? '')
  if (type.includes('ndjson')) {
    const { events, skipped } = parseOcsf(await readTextBody(request, BATCH))
    return response.json({ ...ingestWafEvents(request.guardianHost, events), skipped })
  }
  const body = await readJsonBody(request, BATCH) as { events?: unknown }
  return response.json(ingestWafEvents(request.guardianHost, parseWafEvents(body.events)))
}).parseBody(false).middleware('host').rateLimit(600, 'minute')

// Feed distribution (enrolled hosts). Only the kinds `rules` and `cve` exist; anything else is 404.
//
// Each route has two limits. The route-level one runs before the `host` middleware, so it can
// only count by client address: it is a coarse flood guard, set high enough that a fleet behind
// one NAT never reaches it. The real limit is per host credential, taken in the handler once the
// middleware has authenticated the host (see FEED_LIMITS).
const FEED_LIMITS = { key: 30, manifest: 60, blob: 30 } as const
const FEED_ADDRESS_LIMIT = 1200

async function limitPerHost(request: any, endpoint: keyof typeof FEED_LIMITS): Promise<void> {
  await rateLimit(`feeds:${endpoint}`, FEED_LIMITS[endpoint], { identity: `host:${request.guardianHost.id}` }).per('minute')
}

function header(request: any, name: string): string | null {
  return request.headers?.get?.(name) ?? null
}

// The key a host pinned at enrolment, repeated so an agent can notice a rotation.
route.get('/feeds/key', async (request: any) => {
  await limitPerHost(request, 'key')
  const key = feedKeyInfo()
  return key ? response.json(key) : response.json({ error: 'Feed signing is not configured' }, 404)
}).middleware('host').rateLimit(FEED_ADDRESS_LIMIT, 'minute')

route.get('/feeds/{kind}/manifest', async (request: any) => {
  await limitPerHost(request, 'manifest')
  return feedManifestResponse(request.params?.kind, header(request, 'if-none-match'))
}).middleware('host').rateLimit(FEED_ADDRESS_LIMIT, 'minute')

route.get('/feeds/{kind}/blob', async (request: any) => {
  await limitPerHost(request, 'blob')
  return feedBlobResponse(request.params?.kind, header(request, 'if-none-match'), header(request, 'if-match'))
}).middleware('host').rateLimit(FEED_ADDRESS_LIMIT, 'minute')
