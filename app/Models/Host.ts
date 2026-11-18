import { defineModel } from '@stacksjs/orm'
import { schema } from '@stacksjs/validation'

/** A machine Guardian protects: a Stacks box, a server, or a desktop running the Guardian app. */
export default defineModel({
  name: 'Host',
  table: 'hosts',
  hasMany: ['Scan', 'Finding', 'CveExposure', 'WafEvent'],
  traits: {
    useUuid: true,
    useTimestamps: true,
    useSeeder: { count: 6 },
  },
  indexes: [{ name: 'hosts_name_unique', columns: ['name'], unique: true }],
  attributes: {
    name: { required: true, fillable: true, validation: { rule: schema.string().max(255) }, factory: faker => `${faker.word.noun()}-${faker.number.int({ min: 1, max: 99 })}` },
    platform: { required: true, fillable: true, validation: { rule: schema.enum(['linux', 'macos', 'windows']) }, factory: faker => faker.helpers.arrayElement(['linux', 'linux', 'macos']) },
    role: { required: true, fillable: true, default: 'server', validation: { rule: schema.enum(['server', 'desktop']) }, factory: faker => faker.helpers.arrayElement(['server', 'desktop']) },
    enrolmentState: { required: true, fillable: true, default: 'pending', validation: { rule: schema.enum(['pending', 'active', 'revoked']) }, factory: () => 'active' },
    agentVersion: { required: false, fillable: true, validation: { rule: schema.string().max(40) }, factory: () => '0.1.0' },
    databaseVersion: { required: false, fillable: true, validation: { rule: schema.string().max(40) }, factory: faker => String(faker.number.int({ min: 1, max: 1_000_000 })) },
    lastSeenAt: { required: false, fillable: true, validation: { rule: schema.timestamp() }, factory: faker => faker.date.recent({ days: 1 }).toISOString() },
  },
  dashboard: { columns: ['name', 'platform', 'role', 'enrolmentState', 'lastSeenAt'] },
} as const)
