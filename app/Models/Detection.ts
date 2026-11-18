import { defineModel } from '@stacksjs/orm'
import { schema } from '@stacksjs/validation'
import { SEVERITIES } from '../Guardian/severity'

/** A file (or a member inside a container) a scan flagged. */
export default defineModel({
  name: 'Detection',
  table: 'detections',
  belongsTo: ['Scan'],
  hasOne: ['QuarantineItem'],
  traits: {
    useUuid: true,
    useTimestamps: true,
    useSeeder: { count: 12 },
  },
  indexes: [{ name: 'detections_scan', columns: ['scan_id'] }, { name: 'detections_sha256', columns: ['sha256'] }],
  attributes: {
    path: { required: true, fillable: true, validation: { rule: schema.string().max(4096) }, factory: faker => `/var/www/uploads/${faker.system.fileName()}` },
    containerPath: { required: false, fillable: true, validation: { rule: schema.string().max(4096) }, factory: () => null },
    signature: { required: true, fillable: true, validation: { rule: schema.string().max(255) }, factory: faker => faker.helpers.arrayElement(['Eicar-Test-Signature', 'Win.Trojan.Agent-1234567-0', 'Doc.Malware.Emotet-9-1', 'MalwareBazaar.AgentTesla']) },
    source: { required: true, fillable: true, validation: { rule: schema.enum(['clamav', 'guardian', 'malwarebazaar', 'heuristic']) }, factory: faker => faker.helpers.arrayElement(['clamav', 'guardian']) },
    severity: { required: true, fillable: true, default: 'high', validation: { rule: schema.enum([...SEVERITIES]) }, factory: faker => faker.helpers.arrayElement(['high', 'critical']) },
    sha256: { required: false, fillable: true, validation: { rule: schema.string().max(64) }, factory: faker => faker.string.hexadecimal({ length: 64, casing: 'lower', prefix: '' }) },
    action: { required: true, fillable: true, default: 'reported', validation: { rule: schema.enum(['reported', 'blocked', 'quarantined', 'deleted']) }, factory: faker => faker.helpers.arrayElement(['blocked', 'quarantined']) },
  },
  dashboard: { columns: ['path', 'signature', 'severity', 'action', 'createdAt'] },
} as const)
