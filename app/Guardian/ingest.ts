/**
 * Host enrolment and report ingest.
 *
 * Hosts (Stacks boxes running zavd, desktops running the Guardian app) enrol once with a
 * single-use token an operator created, and receive a long-lived credential. Only SHA-256 hashes
 * of tokens and credentials are stored. Every ingest batch is idempotent, so an agent that lost a
 * response can resend it safely:
 *
 * - scans: keyed by the client's `scanKey`; a replayed scan is skipped with its detections
 * - findings: upserted by `findingKey`, so a repeated check moves `lastSeenAt` forward
 * - CVE exposure: each inventory run replaces the host's whole set
 * - WAF events: appended, deduplicated by the engine's event id
 *
 * Quarantined samples are never uploaded: hashes and metadata only.
 */
import { HttpError } from '@stacksjs/error-handling'
import { SEVERITIES, type Severity } from './severity'

export const ENROLMENT_PREFIX = 'gde_'
export const CREDENTIAL_PREFIX = 'gdh_'
/** Largest batch any ingest endpoint accepts. */
export const MAX_BATCH = 10_000

function randomSecret(prefix: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return prefix + Buffer.from(bytes).toString('base64url')
}

export function hashSecret(secret: string): string {
  return new Bun.CryptoHasher('sha256').update(secret).digest('hex')
}

function now(): string {
  return new Date().toISOString()
}

function fail(status: number, message: string): never {
  throw new HttpError(status, message)
}

function text(value: unknown, field: string, max: number, required = true): string | null {
  if (value === undefined || value === null || value === '') {
    if (required)
      fail(422, `${field} is required`)
    return null
  }
  if (typeof value !== 'string')
    fail(422, `${field} must be a string`)
  if (value.length > max)
    fail(422, `${field} is longer than ${max} characters`)
  return value
}

function int(value: unknown, field: string, fallback = 0): number {
  if (value === undefined || value === null)
    return fallback
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0)
    fail(422, `${field} must be a non-negative integer`)
  return value
}

function oneOf<T extends string>(value: unknown, field: string, allowed: readonly T[], fallback?: T): T {
  if ((value === undefined || value === null) && fallback !== undefined)
    return fallback
  if (typeof value !== 'string' || !allowed.includes(value as T))
    fail(422, `${field} must be one of ${allowed.join(', ')}`)
  return value as T
}

function list(value: unknown, field: string): unknown[] {
  if (!Array.isArray(value))
    fail(422, `${field} must be an array`)
  if (value.length > MAX_BATCH)
    fail(413, `${field} has more than ${MAX_BATCH} entries`)
  return value
}

/** Create a single-use enrolment token. The plaintext is returned once and never stored. */
export function createEnrolmentToken(label: string | null = null, ttlHours = 24): string {
  const token = randomSecret(ENROLMENT_PREFIX)
  EnrolmentToken.create({
    tokenHash: hashSecret(token),
    label,
    expiresAt: new Date(Date.now() + ttlHours * 3_600_000).toISOString(),
  })
  return token
}

export interface EnrolInput {
  token: unknown
  name: unknown
  platform: unknown
  role?: unknown
  agentVersion?: unknown
  nodeId?: unknown
}

/** Exchange an enrolment token for a host and its credential (shown once). */
export function enrolHost(input: EnrolInput): { hostId: number, nodeId: string, credential: string } {
  const token = text(input.token, 'token', 128)!
  const name = text(input.name, 'name', 255)!
  const platform = oneOf(input.platform, 'platform', ['linux', 'macos', 'windows'] as const)
  const role = oneOf(input.role, 'role', ['server', 'desktop'] as const, 'server')
  const agentVersion = text(input.agentVersion, 'agentVersion', 40, false)
  const nodeId = text(input.nodeId, 'nodeId', 64, false) ?? crypto.randomUUID()

  const credential = randomSecret(CREDENTIAL_PREFIX)
  return db.transaction(() => {
    const record = EnrolmentToken.where('token_hash', hashSecret(token)).first()
    if (!record || record.usedAt)
      fail(401, 'Enrolment token is not valid')
    if (new Date(record.expiresAt as string).getTime() < Date.now())
      fail(401, 'Enrolment token has expired')
    if (Host.where('name', name).first())
      fail(409, `A host named ${name} is already enrolled`)

    const host = Host.create({
      name,
      platform,
      role,
      nodeId,
      agentVersion,
      enrolmentState: 'active',
      credentialHash: hashSecret(credential),
      credentialRotatedAt: now(),
      lastSeenAt: now(),
    })
    record.update({ usedAt: now(), hostId: host.id })
    return { hostId: host.id as number, nodeId, credential }
  })
}

/** The active host a bearer credential belongs to, or null (unknown, revoked or malformed). */
export function authenticateHost(credential: string | null | undefined): ReturnType<typeof Host.find> | null {
  if (!credential || !credential.startsWith(CREDENTIAL_PREFIX) || credential.length > 128)
    return null
  const host = Host.where('credential_hash', hashSecret(credential)).first()
  if (!host || host.revokedAt || host.enrolmentState !== 'active')
    return null
  return host
}

/** Issue a new credential; the old one stops working immediately. */
export function rotateCredential(hostId: number): string {
  const credential = randomSecret(CREDENTIAL_PREFIX)
  const host = Host.find(hostId) ?? fail(404, 'Host not found')
  host.update({ credentialHash: hashSecret(credential), credentialRotatedAt: now() })
  return credential
}

export function revokeHost(hostId: number): void {
  const host = Host.find(hostId) ?? fail(404, 'Host not found')
  host.update({ revokedAt: now(), enrolmentState: 'revoked' })
}

type HostRow = NonNullable<ReturnType<typeof authenticateHost>>

export function heartbeat(host: HostRow, body: { agentVersion?: unknown, databaseVersion?: unknown, protection?: unknown }): void {
  host.update({
    agentVersion: text(body.agentVersion, 'agentVersion', 40, false) ?? host.agentVersion,
    databaseVersion: text(body.databaseVersion, 'databaseVersion', 40, false) ?? host.databaseVersion,
    protection: body.protection === undefined ? host.protection : JSON.stringify(body.protection),
    lastSeenAt: now(),
  })
}

/** Scans with their detections. Returns how many were stored and how many were replays. */
export function ingestScans(host: HostRow, scans: unknown): { created: number, replayed: number } {
  const items = list(scans, 'scans')
  let created = 0
  let replayed = 0
  db.transaction(() => {
    for (const raw of items as Record<string, unknown>[]) {
      const scanKey = text(raw.scanKey, 'scanKey', 64)!
      if (Scan.where('host_id', host.id).where('scan_key', scanKey).first()) {
        replayed++
        continue
      }
      const detections = list(raw.detections ?? [], 'detections') as Record<string, unknown>[]
      const scan = Scan.create({
        hostId: host.id,
        scanKey,
        target: text(raw.target, 'target', 1024)!,
        trigger: oneOf(raw.trigger, 'trigger', ['manual', 'scheduled', 'upload', 'realtime', 'mail'] as const, 'manual'),
        startedAt: text(raw.startedAt, 'startedAt', 40)!,
        finishedAt: text(raw.finishedAt, 'finishedAt', 40, false),
        files: int(raw.files, 'files'),
        bytes: int(raw.bytes, 'bytes'),
        infected: detections.length,
        limited: int(raw.limited, 'limited'),
        errors: int(raw.errors, 'errors'),
        engineVersion: text(raw.engineVersion, 'engineVersion', 40, false),
        databaseVersion: text(raw.databaseVersion, 'databaseVersion', 40, false),
      })
      for (const d of detections) {
        Detection.create({
          scanId: scan.id,
          path: text(d.path, 'path', 4096)!,
          containerPath: text(d.containerPath, 'containerPath', 4096, false),
          signature: text(d.signature, 'signature', 255)!,
          source: oneOf(d.source, 'source', ['clamav', 'guardian', 'malwarebazaar', 'heuristic'] as const, 'clamav'),
          severity: oneOf<Severity>(d.severity, 'severity', SEVERITIES, 'high'),
          sha256: text(d.sha256, 'sha256', 64, false),
          action: oneOf(d.action, 'action', ['reported', 'blocked', 'quarantined', 'deleted'] as const, 'reported'),
        })
      }
      created++
    }
  })
  host.update({ lastSeenAt: now() })
  return { created, replayed }
}

/** Upsert host findings by their stable key. */
export function ingestFindings(host: HostRow, findings: unknown): { created: number, updated: number } {
  const items = list(findings, 'findings')
  let created = 0
  let updated = 0
  db.transaction(() => {
    for (const raw of items as Record<string, unknown>[]) {
      const findingKey = text(raw.findingKey, 'findingKey', 255)!
      const fields = {
        check: text(raw.check, 'check', 120)!,
        category: oneOf(raw.category, 'category', ['malware', 'network', 'kernel', 'persistence', 'privilege', 'hardening', 'integrity'] as const),
        severity: oneOf<Severity>(raw.severity, 'severity', SEVERITIES),
        title: text(raw.title, 'title', 255)!,
        remediation: text(raw.remediation, 'remediation', 10_000, false),
        details: raw.details === undefined ? null : JSON.stringify(raw.details),
        lastSeenAt: text(raw.seenAt, 'seenAt', 40, false) ?? now(),
      }
      const existing = Finding.where('host_id', host.id).where('finding_key', findingKey).first()
      if (existing) {
        existing.update(fields)
        updated++
      }
      else {
        Finding.create({ hostId: host.id, findingKey, firstSeenAt: fields.lastSeenAt, suppressed: false, ...fields })
        created++
      }
    }
  })
  return { created, updated }
}

/** Replace the host's CVE exposure with this inventory run's set. */
export function ingestCveExposure(host: HostRow, body: { inventoryRun?: unknown, exposures?: unknown }): { stored: number } {
  const run = text(body.inventoryRun, 'inventoryRun', 64)!
  const items = list(body.exposures, 'exposures') as Record<string, unknown>[]
  const rows = items.map(raw => ({
    host_id: host.id,
    inventory_run: run,
    package: text(raw.package, 'package', 255)!,
    ecosystem: oneOf(raw.ecosystem, 'ecosystem', ['dpkg', 'rpm', 'apk', 'homebrew', 'pantry', 'npm', 'pypi', 'go', 'cargo', 'macos-app'] as const),
    installed_version: text(raw.installedVersion, 'installedVersion', 120)!,
    fixed_version: text(raw.fixedVersion, 'fixedVersion', 120, false),
    cve_id: text(raw.cveId, 'cveId', 32)!,
    cvss: raw.cvss === undefined || raw.cvss === null ? null : Number(raw.cvss),
    severity: oneOf<Severity>(raw.severity, 'severity', SEVERITIES, 'medium'),
    kev: raw.kev === true ? 1 : 0,
    kev_due_date: text(raw.kevDueDate, 'kevDueDate', 10, false),
    uuid: crypto.randomUUID(),
    created_at: now(),
  }))
  db.transaction(() => {
    db.deleteFrom('cve_exposures').where('host_id', '=', host.id).execute()
    if (rows.length > 0)
      db.insertOrIgnore('cve_exposures', rows)
  })
  return { stored: rows.length }
}

export interface WafEventInput {
  eventId: string
  occurredAt: string
  site: string
  ruleId: number | null
  anomalyScore: number
  action: 'passed' | 'logged' | 'blocked'
  clientIp: string
  method: string
  path: string
  messages: string[]
}

/** Append WAF events, skipping any event id already stored for this host. */
export function ingestWafEvents(host: HostRow, events: WafEventInput[]): { stored: number, duplicates: number } {
  if (events.length > MAX_BATCH)
    fail(413, `more than ${MAX_BATCH} events`)
  const created = now()
  const rows = events.map(e => ({
    host_id: host.id,
    event_id: e.eventId,
    occurred_at: e.occurredAt,
    site: e.site,
    rule_id: e.ruleId,
    anomaly_score: e.anomalyScore,
    action: e.action,
    client_ip: e.clientIp,
    method: e.method,
    path: e.path,
    messages: JSON.stringify(e.messages.slice(0, 20)),
    uuid: crypto.randomUUID(),
    created_at: created,
  }))
  let stored = 0
  db.transaction(() => {
    for (let i = 0; i < rows.length; i += 500)
      stored += db.insertOrIgnore('waf_events', rows.slice(i, i + 500))
  })
  return { stored, duplicates: rows.length - stored }
}

/** Validate WAF events sent as JSON objects in Guardian's own shape. */
export function parseWafEvents(value: unknown): WafEventInput[] {
  return (list(value, 'events') as Record<string, unknown>[]).map(raw => ({
    eventId: text(raw.eventId, 'eventId', 128)!,
    occurredAt: text(raw.occurredAt, 'occurredAt', 40)!,
    site: text(raw.site, 'site', 255)!,
    ruleId: raw.ruleId === undefined || raw.ruleId === null ? null : int(raw.ruleId, 'ruleId'),
    anomalyScore: int(raw.anomalyScore, 'anomalyScore'),
    action: oneOf(raw.action, 'action', ['passed', 'logged', 'blocked'] as const),
    clientIp: text(raw.clientIp, 'clientIp', 45)!,
    method: text(raw.method, 'method', 10)!,
    path: text(raw.path, 'path', 2048)!,
    messages: Array.isArray(raw.messages) ? raw.messages.filter((m): m is string => typeof m === 'string') : [],
  }))
}

/**
 * Convert zig-waf OCSF (class 6004, Web Resources Activity) audit lines, as ts-cloud's forwarder
 * ships them (one JSON object per line), into Guardian events. Lines that are not OCSF web
 * activity are skipped and counted.
 */
export function parseOcsf(ndjson: string): { events: WafEventInput[], skipped: number } {
  const events: WafEventInput[] = []
  let skipped = 0
  for (const line of ndjson.split('\n')) {
    if (line.trim() === '')
      continue
    let record: any
    try {
      record = JSON.parse(line)
    }
    catch {
      skipped++
      continue
    }
    if (record?.class_uid !== 6004) {
      skipped++
      continue
    }
    const request = record.http_request ?? {}
    const url = request.url ?? {}
    const enrichments: any[] = Array.isArray(record.enrichments) ? record.enrichments : []
    const ruleIds = enrichments.map(e => Number(e?.data?.id ?? e?.data?.rule_id ?? e?.value)).filter(n => Number.isInteger(n) && n > 0)
    const score = Number(record.unmapped?.anomaly_score ?? record.risk_score ?? 0)
    const denied = record.disposition_id === 2 || record.action_id === 2 || record.disposition === 'Blocked'
    const time = typeof record.time === 'number' ? new Date(record.time).toISOString() : String(record.time ?? now())
    events.push({
      eventId: String(record.metadata?.uid ?? record.uid ?? `${time}-${url.path ?? ''}`).slice(0, 128),
      occurredAt: time,
      site: String(url.hostname ?? record.dst_endpoint?.hostname ?? 'unknown').slice(0, 255),
      ruleId: ruleIds[0] ?? null,
      anomalyScore: Number.isFinite(score) && score >= 0 ? Math.trunc(score) : 0,
      action: denied ? 'blocked' : 'logged',
      clientIp: String(record.src_endpoint?.ip ?? '0.0.0.0').slice(0, 45),
      method: String(request.http_method ?? 'GET').slice(0, 10),
      path: String(url.path ?? '/').slice(0, 2048),
      messages: enrichments.map(e => String(e?.name ?? e?.value ?? '')).filter(Boolean).slice(0, 20),
    })
  }
  return { events, skipped }
}
