import { response, route } from '@stacksjs/router'
import { readJsonBody, readTextBody } from '@stacksjs/router/body'
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
 * limits; every batch endpoint is idempotent (see app/Guardian/ingest.ts).
 */

const SMALL = 64 * 1024
const BATCH = 16 * 1024 * 1024

// Enrolment: exchange a single-use token for a host credential.
route.post('/hosts/enrol', async (request: any) => {
  return response.json(enrolHost(await readJsonBody(request, SMALL) as EnrolInput), 201)
}).parseBody(false).rateLimit(10, 'minute')

// Operator actions (signed-in users).
route.post('/hosts/enrolment-tokens', async (request: any) => {
  const body = await readJsonBody(request, SMALL).catch(() => ({})) as { label?: string, ttlHours?: number }
  return response.json({ token: createEnrolmentToken(body.label ?? null, body.ttlHours ?? 24) }, 201)
}).parseBody(false).middleware('auth')

route.post('/hosts/{id}/rotate', (request: any) => {
  return response.json({ credential: rotateCredential(Number(request.params.id)) })
}).middleware('auth')

route.post('/hosts/{id}/revoke', (request: any) => {
  revokeHost(Number(request.params.id))
  return response.json({ revoked: true })
}).middleware('auth')

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
