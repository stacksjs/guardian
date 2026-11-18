import { defineModel } from '@stacksjs/orm'
import { schema } from '@stacksjs/validation'

/**
 * A web firewall event, in the shape ts-cloud already normalises zig-waf audit records into
 * (`WafEvent` in ts-cloud's protection/waf.ts), so ingest needs no translation.
 */
export default defineModel({
  name: 'WafEvent',
  table: 'waf_events',
  belongsTo: ['Host'],
  traits: {
    useUuid: true,
    useTimestamps: true,
    useSeeder: { count: 60 },
  },
  indexes: [{ name: 'waf_events_host_occurred', columns: ['host_id', 'occurred_at'] }, { name: 'waf_events_site_rule', columns: ['site', 'rule_id'] }],
  attributes: {
    occurredAt: { required: true, fillable: true, validation: { rule: schema.timestamp() }, factory: faker => faker.date.recent({ days: 3 }).toISOString() },
    site: { required: true, fillable: true, validation: { rule: schema.string().max(255) }, factory: faker => faker.internet.domainName() },
    ruleId: { required: false, fillable: true, validation: { rule: schema.number().min(0) }, factory: faker => faker.helpers.arrayElement([942100, 941100, 930120, 920350, 913100]) },
    anomalyScore: { required: true, fillable: true, default: 0, validation: { rule: schema.number().min(0) }, factory: faker => faker.number.int({ min: 0, max: 25 }) },
    action: { required: true, fillable: true, validation: { rule: schema.enum(['passed', 'logged', 'blocked']) }, factory: faker => faker.helpers.arrayElement(['logged', 'logged', 'blocked']) },
    clientIp: { required: true, fillable: true, validation: { rule: schema.string().max(45) }, factory: faker => faker.internet.ip() },
    method: { required: true, fillable: true, validation: { rule: schema.string().max(10) }, factory: faker => faker.helpers.arrayElement(['GET', 'POST']) },
    path: { required: true, fillable: true, validation: { rule: schema.string().max(2048) }, factory: faker => `/${faker.word.noun()}` },
    messages: { required: false, fillable: true, validation: { rule: schema.json() }, factory: faker => JSON.stringify([faker.lorem.sentence()]) },
  },
  dashboard: { columns: ['host', 'site', 'ruleId', 'anomalyScore', 'action', 'occurredAt'] },
} as const)
