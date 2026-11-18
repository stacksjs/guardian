/**
 * One severity scale for detections, host findings and CVE exposure, so the per-host risk score
 * can combine them. Ordered from least to most severe.
 */
export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const
export type Severity = typeof SEVERITIES[number]

export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity)
}
