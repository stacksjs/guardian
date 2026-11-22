import { beforeAll, describe, expect, it } from 'bun:test'
import { freshDatabase } from '../support/database'
import {
  authenticateHost,
  createEnrolmentToken,
  enrolHost,
  ingestCveExposure,
  ingestFindings,
  ingestScans,
  ingestWafEvents,
  parseInstant,
  parseOcsf,
  parseWafEvents,
  revokeHost,
  rotateCredential,
} from '../../app/Guardian/ingest'

beforeAll(async () => {
  await freshDatabase()
})

/**
 * The instant a stored datetime names. SQLite hands back text holding UTC without a zone suffix;
 * Postgres hands back a Date.
 */
function utc(value: unknown): number {
  if (value instanceof Date)
    return value.getTime()
  const text = String(value).replace(' ', 'T')
  return Date.parse(/(?:Z|[+-]\d{2}:?\d{2})$/.test(text) ? text : `${text}Z`)
}

function enrol(name: string) {
  return enrolHost({ token: createEnrolmentToken('test'), name, platform: 'linux', role: 'server', agentVersion: '0.1.0' })
}

describe('host enrolment', () => {
  it('exchanges a token for a credential that authenticates the host', () => {
    const { hostId, credential } = enrol('box-1')
    expect(credential.startsWith('gdh_')).toBe(true)
    expect(authenticateHost(credential)?.id).toBe(hostId)
    // Only the hash is stored.
    expect(JSON.stringify(Host.find(hostId))).not.toContain(credential)
  })

  it('refuses a token that was already used', () => {
    const token = createEnrolmentToken()
    enrolHost({ token, name: 'box-2', platform: 'linux' })
    expect(() => enrolHost({ token, name: 'box-3', platform: 'linux' })).toThrow('not valid')
  })

  it('refuses an expired or unknown token and a duplicate name', () => {
    expect(() => enrolHost({ token: createEnrolmentToken(null, -1), name: 'box-4', platform: 'linux' })).toThrow('expired')
    expect(() => enrolHost({ token: 'gde_nope', name: 'box-5', platform: 'linux' })).toThrow('not valid')
    expect(() => enrolHost({ token: createEnrolmentToken(), name: 'box-1', platform: 'linux' })).toThrow('already enrolled')
  })

  it('stops honouring a rotated or revoked credential', () => {
    const { hostId, credential } = enrol('box-6')
    const next = rotateCredential(hostId)
    expect(authenticateHost(credential)).toBeNull()
    expect(authenticateHost(next)?.id).toBe(hostId)
    revokeHost(hostId)
    expect(authenticateHost(next)).toBeNull()
    expect(authenticateHost('not-a-credential')).toBeNull()
  })
})

describe('ingest is idempotent', () => {
  it('stores a scan once and skips its replay', () => {
    const host = authenticateHost(enrol('scan-host').credential)!
    const batch = [{ scanKey: 's-1', target: '/var/www', startedAt: '2026-11-17T10:00:00Z', files: 10, bytes: 1000, detections: [{ path: '/var/www/x.php', signature: 'Php.Webshell.X-1-0', severity: 'critical', action: 'quarantined' }] }]
    expect(ingestScans(host, batch)).toEqual({ created: 1, replayed: 0 })
    expect(ingestScans(host, batch)).toEqual({ created: 0, replayed: 1 })
    const scan = Scan.where('host_id', host.id).where('scan_key', 's-1').first()!
    expect(scan.infected).toBe(1)
    expect(Detection.where('scan_id', scan.id).count()).toBe(1)
  })

  it('stores a scan larger than 2 GiB', () => {
    const host = authenticateHost(enrol('big-scan-host').credential)!
    ingestScans(host, [{ scanKey: 's-big', target: '/', startedAt: '2026-11-17T10:00:00Z', files: 1, bytes: 3_000_000_000, detections: [] }])
    expect(Number(Scan.where('host_id', host.id).where('scan_key', 's-big').first()!.bytes)).toBe(3_000_000_000)
  })

  it('updates a repeated finding instead of duplicating it', () => {
    const host = authenticateHost(enrol('finding-host').credential)!
    const finding = { findingKey: 'process.tmp_executable:/tmp/x', check: 'process.tmp_executable', category: 'malware', severity: 'high', title: 'Executable running from /tmp', seenAt: '2026-11-17T10:00:00Z' }
    expect(ingestFindings(host, [finding])).toEqual({ created: 1, updated: 0 })
    expect(ingestFindings(host, [{ ...finding, seenAt: '2026-11-17T11:00:00Z' }])).toEqual({ created: 0, updated: 1 })
    const rows = Finding.where('host_id', host.id).get()
    expect(rows.length).toBe(1)
    expect(utc(rows[0]!.lastSeenAt)).toBe(Date.parse('2026-11-17T11:00:00Z'))
    expect(utc(rows[0]!.firstSeenAt)).toBe(Date.parse('2026-11-17T10:00:00Z'))
    // One stored form, whichever write produced it.
    expect(String(rows[0]!.lastSeenAt).length).toBe(String(rows[0]!.firstSeenAt).length)
  })

  it('replaces CVE exposure per inventory run', () => {
    const host = authenticateHost(enrol('cve-host').credential)!
    const exposure = { package: 'openssl', ecosystem: 'dpkg', installedVersion: '3.0.1', cveId: 'CVE-2026-0001', severity: 'high', kev: true }
    ingestCveExposure(host, { inventoryRun: 'r1', exposures: [exposure, { ...exposure, cveId: 'CVE-2026-0002' }] })
    ingestCveExposure(host, { inventoryRun: 'r1', exposures: [exposure, { ...exposure, cveId: 'CVE-2026-0002' }] })
    expect(CveExposure.where('host_id', host.id).count()).toBe(2)
    ingestCveExposure(host, { inventoryRun: 'r2', exposures: [exposure] })
    expect(CveExposure.where('host_id', host.id).count()).toBe(1)
  })

  it('stores the KEV flag and a fractional CVSS score as sent', () => {
    const host = authenticateHost(enrol('cve-values-host').credential)!
    const exposure = { package: 'openssl', ecosystem: 'dpkg', installedVersion: '3.0.1', severity: 'critical' }
    ingestCveExposure(host, { inventoryRun: 'r1', exposures: [{ ...exposure, cveId: 'CVE-2026-0003', cvss: 9.8, kev: true }, { ...exposure, cveId: 'CVE-2026-0004', cvss: 4.3, kev: false }] })
    const rows = CveExposure.where('host_id', host.id).orderBy('cve_id', 'asc').get()
    expect(rows.map(row => [Boolean(row.kev), Number(row.cvss)])).toEqual([[true, 9.8], [false, 4.3]])
  })

  it('deduplicates WAF events by event id, and ingests 10k in under 2 seconds', () => {
    const host = authenticateHost(enrol('waf-host').credential)!
    const events = parseWafEvents(Array.from({ length: 10_000 }, (_, i) => ({
      eventId: `e-${i}`,
      occurredAt: '2026-11-17T10:00:00Z',
      site: 'example.test',
      ruleId: 942100,
      anomalyScore: 5,
      action: 'logged',
      clientIp: '203.0.113.7',
      method: 'GET',
      path: `/search?q=${i}`,
      messages: ['SQL Injection Attack Detected'],
    })))
    const started = performance.now()
    expect(ingestWafEvents(host, events)).toEqual({ stored: 10_000, duplicates: 0 })
    const elapsed = performance.now() - started
    expect(elapsed).toBeLessThan(2000)
    expect(ingestWafEvents(host, events.slice(0, 100))).toEqual({ stored: 0, duplicates: 100 })
  })

  it('accepts zig-waf OCSF lines from the ts-cloud forwarder', () => {
    const line = JSON.stringify({
      class_uid: 6004,
      time: 1763373600000,
      metadata: { uid: 'tx-1' },
      disposition_id: 2,
      http_request: { http_method: 'POST', url: { hostname: 'shop.example.test', path: '/login' } },
      src_endpoint: { ip: '198.51.100.4' },
      enrichments: [{ name: 'SQL Injection Attack Detected', data: { id: 942100 } }],
      unmapped: { anomaly_score: 10 },
    })
    const { events, skipped } = parseOcsf(`${line}\nnot json\n${JSON.stringify({ class_uid: 1 })}\n`)
    expect(skipped).toBe(2)
    expect(events).toEqual([{
      eventId: 'tx-1',
      occurredAt: new Date(1763373600000).toISOString(),
      site: 'shop.example.test',
      ruleId: 942100,
      anomalyScore: 10,
      action: 'blocked',
      clientIp: '198.51.100.4',
      method: 'POST',
      path: '/login',
      messages: ['SQL Injection Attack Detected'],
    }])
  })
})

describe('client timestamps', () => {
  it('reads an RFC 3339 date-time with a zone as the UTC instant it names', () => {
    expect(parseInstant('2026-11-17T16:30:00+05:30')).toBe('2026-11-17T11:00:00.000Z')
    expect(parseInstant('2026-11-17T06:00:00-0500')).toBe('2026-11-17T11:00:00.000Z')
    expect(parseInstant('2026-11-17 11:00:00.123456789z')).toBe('2026-11-17T11:00:00.123Z')
    expect(parseInstant('2026-11-17T11:00Z')).toBe('2026-11-17T11:00:00.000Z')
    expect(parseInstant('2024-02-29T00:00:00Z')).toBe('2024-02-29T00:00:00.000Z')
  })

  it('refuses a time without a zone, a date that does not exist, and anything else', () => {
    for (const value of ['2026-11-17T11:00:00', '2026-02-30T00:00:00Z', '2025-02-29T00:00:00Z', '2026-11-17T24:00:00Z', '2026-11-17T11:60:00Z', '2026-11-17T11:00:60Z', '2026-11-17T11:00:00+24:00', '0050-01-01T00:00:00Z', 'yesterday', '1763373600000', ''])
      expect(parseInstant(value)).toBeNull()
  })

  // Findings go through the model, which already converted offsets; this keeps it that way.
  it('stores a finding seen at an offset time as the same instant on every database', () => {
    const host = authenticateHost(enrol('offset-host').credential)!
    ingestFindings(host, [{ findingKey: 'k', check: 'c', category: 'hardening', severity: 'low', title: 't', seenAt: '2026-11-17T16:00:00+05:00' }])
    expect(utc(Finding.where('host_id', host.id).first()!.lastSeenAt)).toBe(Date.parse('2026-11-17T11:00:00Z'))
  })

  it('stores a WAF event at an offset time as the same instant on every database', () => {
    const host = authenticateHost(enrol('offset-waf-host').credential)!
    const events = parseWafEvents([{ eventId: 'tz-1', occurredAt: '2026-11-17T06:00:00-05:00', site: 'example.test', ruleId: null, anomalyScore: 0, action: 'passed', clientIp: '203.0.113.9', method: 'GET', path: '/' }])
    // The raw insert stores this text as it is, so SQLite alone would read an offset back correctly.
    expect(events[0]!.occurredAt).toBe('2026-11-17T11:00:00.000Z')
    ingestWafEvents(host, events)
    expect(utc(WafEvent.where('host_id', host.id).first()!.occurredAt)).toBe(Date.parse('2026-11-17T11:00:00Z'))
  })

  it('refuses a batch with a bad timestamp with a 422 before writing anything', () => {
    const host = authenticateHost(enrol('bad-time-host').credential)!
    // The good item comes first, so this also shows the transaction rolls it back.
    const scan = { target: '/', files: 0, bytes: 0, detections: [] }
    expect(() => ingestScans(host, [{ ...scan, scanKey: 's-ok', startedAt: '2026-11-17T10:00:00Z' }, { ...scan, scanKey: 's-bad', startedAt: 'not a date' }])).toThrow('startedAt must be an RFC 3339 date-time')
    const finding = { check: 'c', category: 'hardening', severity: 'low', title: 't' }
    expect(() => ingestFindings(host, [{ ...finding, findingKey: 'ok', seenAt: '2026-11-17T10:00:00Z' }, { ...finding, findingKey: 'bad', seenAt: '2026-02-30T00:00:00Z' }])).toThrow('seenAt must be an RFC 3339 date-time')
    expect(() => parseWafEvents([{ eventId: 'e', occurredAt: '2026-11-17T11:00:00', site: 's', anomalyScore: 0, action: 'passed', clientIp: '203.0.113.9', method: 'GET', path: '/' }])).toThrow('occurredAt must be an RFC 3339 date-time')
    expect(Scan.where('host_id', host.id).count()).toBe(0)
    expect(Finding.where('host_id', host.id).count()).toBe(0)
  })

  it('skips an OCSF line whose time is not an instant', () => {
    const base = { class_uid: 6004, http_request: { url: { path: '/' } } }
    const lines = [{ ...base, time: 'yesterday' }, { ...base, time: -1e15 }, { ...base, time: '2026-11-17T06:00:00-05:00', metadata: { uid: 'ok' } }].map(l => JSON.stringify(l)).join('\n')
    const { events, skipped } = parseOcsf(lines)
    expect(skipped).toBe(2)
    expect(events.map(e => e.occurredAt)).toEqual(['2026-11-17T11:00:00.000Z'])
  })
})
