import { describe, expect, it } from 'bun:test'
import { SEVERITIES, severityRank } from '../../app/Guardian/severity'
import CveExposureModel from '../../app/Models/CveExposure'
import DetectionModel from '../../app/Models/Detection'
import FindingModel from '../../app/Models/Finding'
import HostModel from '../../app/Models/Host'
import ScanModel from '../../app/Models/Scan'
import WafEventModel from '../../app/Models/WafEvent'

describe('Guardian domain models', () => {
  it('relate hosts to their scans, findings, CVE exposure and WAF events', () => {
    expect(HostModel.getDefinition().hasMany).toEqual(['Scan', 'Finding', 'CveExposure', 'WafEvent'])
    expect(ScanModel.getDefinition().hasMany).toEqual(['Detection'])
    expect(DetectionModel.getDefinition().hasOne).toEqual(['QuarantineItem'])
  })

  it('share one severity scale across detections, findings and CVE exposure', () => {
    for (const model of [DetectionModel, FindingModel, CveExposureModel]) {
      const attrs = model.getDefinition().attributes as Record<string, { default?: unknown }>
      expect(SEVERITIES).toContain(attrs.severity!.default as never)
    }
    expect(severityRank('critical')).toBeGreaterThan(severityRank('high'))
  })

  it('index the host and time columns dashboards query', () => {
    const names = (m: typeof ScanModel) => (m.getDefinition().indexes ?? []).map((i: { name: string }) => i.name)
    expect(names(ScanModel)).toContain('scans_host_started')
    expect(names(WafEventModel as never)).toContain('waf_events_host_occurred')
  })
})
