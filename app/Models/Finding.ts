import { defineModel } from '@stacksjs/orm'
import { schema } from '@stacksjs/validation'
import { SEVERITIES } from '../Guardian/severity'

/** A host check result: a miner, a reverse shell, a risky setting, a persistence entry. */
export default defineModel({
  name: 'Finding',
  table: 'findings',
  belongsTo: ['Host'],
  traits: {
    useUuid: true,
    useTimestamps: true,
    useSeeder: { count: 30 },
  },
  indexes: [{ name: 'findings_host_last_seen', columns: ['host_id', 'last_seen_at'] }, { name: 'findings_host_finding_key_unique', columns: ['host_id', 'finding_key'], unique: true }],
  attributes: {
    /** Stable id from the agent (check plus subject), so a repeated finding updates last seen. */
    findingKey: { required: true, fillable: true, validation: { rule: schema.string().max(255) }, factory: faker => faker.string.uuid() },
    check: { required: true, fillable: true, validation: { rule: schema.string().max(120) }, factory: faker => faker.helpers.arrayElement(['process.tmp_executable', 'network.reverse_shell', 'kernel.unsigned_module', 'ssh.password_auth', 'persistence.cron_download']) },
    category: { required: true, fillable: true, validation: { rule: schema.enum(['malware', 'network', 'kernel', 'persistence', 'privilege', 'hardening', 'integrity']) }, factory: faker => faker.helpers.arrayElement(['malware', 'network', 'hardening', 'persistence']) },
    severity: { required: true, fillable: true, default: 'medium', validation: { rule: schema.enum([...SEVERITIES]) }, factory: faker => faker.helpers.arrayElement([...SEVERITIES]) },
    title: { required: true, fillable: true, validation: { rule: schema.string().max(255) }, factory: faker => faker.lorem.sentence({ min: 3, max: 7 }) },
    remediation: { type: 'text', required: false, fillable: true, validation: { rule: schema.string() }, factory: faker => faker.lorem.sentence() },
    details: { required: false, fillable: true, validation: { rule: schema.json() }, factory: () => JSON.stringify({}) },
    firstSeenAt: { required: true, fillable: true, validation: { rule: schema.timestamp() }, factory: faker => faker.date.recent({ days: 30 }).toISOString() },
    lastSeenAt: { required: true, fillable: true, validation: { rule: schema.timestamp() }, factory: faker => faker.date.recent({ days: 2 }).toISOString() },
    suppressed: { required: true, fillable: true, default: false, validation: { rule: schema.boolean() }, factory: () => false },
  },
  dashboard: { columns: ['host', 'check', 'severity', 'title', 'lastSeenAt'] },
} as const)
