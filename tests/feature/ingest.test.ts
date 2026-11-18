import { beforeAll, describe, expect, it } from 'bun:test'
import { refreshDatabase } from '@stacksjs/testing/database'
import {
  authenticateHost,
  createEnrolmentToken,
  enrolHost,
  ingestCveExposure,
  ingestFindings,
  ingestScans,
  ingestWafEvents,
  parseOcsf,
  parseWafEvents,
  revokeHost,
  rotateCredential,
} from '../../app/Guardian/ingest'

beforeAll(async () => {
  await refreshDatabase()
})

/** The instant a stored datetime names. Columns hold UTC without a zone suffix. */
function utc(value: unknown): number {
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
