import { defineModel } from '@stacksjs/orm'
import { schema } from '@stacksjs/validation'

/** A machine Guardian protects: a Stacks box, a server, or a desktop running the Guardian app. */
export default defineModel({
  name: 'Host',
  table: 'hosts',
  hasMany: ['Scan', 'Finding', 'CveExposure', 'WafEvent', 'EnrolmentToken'],
  traits: {
    useUuid: true,
    useTimestamps: true,
    useSeeder: { count: 6 },
  },
  indexes: [
    { name: 'hosts_name_unique', columns: ['name'], unique: true },
    { name: 'hosts_node_id_unique', columns: ['node_id'], unique: true },
    { name: 'hosts_credential_hash', columns: ['credential_hash'] },
  ],
  attributes: {
    name: { required: true, fillable: true, validation: { rule: schema.string().max(255) }, factory: faker => `${faker.word.noun()}-${faker.number.int({ min: 1, max: 99 })}` },
    platform: { required: true, fillable: true, validation: { rule: schema.enum(['linux', 'macos', 'windows']) }, factory: faker => faker.helpers.arrayElement(['linux', 'linux', 'macos']) },
    role: { required: true, fillable: true, default: 'server', validation: { rule: schema.enum(['server', 'desktop']) }, factory: faker => faker.helpers.arrayElement(['server', 'desktop']) },
    enrolmentState: { required: true, fillable: true, default: 'pending', validation: { rule: schema.enum(['pending', 'active', 'revoked']) }, factory: () => 'active' },
    agentVersion: { required: false, fillable: true, validation: { rule: schema.string().max(40) }, factory: () => '0.1.0' },
    databaseVersion: { required: false, fillable: true, validation: { rule: schema.string().max(40) }, factory: faker => String(faker.number.int({ min: 1, max: 1_000_000 })) },
    /** Stable node id, the same one zig-waf's fleet uses, so a host enrolled in both lines up. */
    nodeId: { required: true, fillable: true, validation: { rule: schema.string().max(64) }, factory: faker => faker.string.uuid() },
    /** SHA-256 of the host credential; the credential itself is shown once at enrolment. */
    credentialHash: { required: false, fillable: true, hidden: true, validation: { rule: schema.string().max(64) }, factory: () => null },
    credentialRotatedAt: { required: false, fillable: true, validation: { rule: schema.timestamp() }, factory: () => null },
    revokedAt: { required: false, fillable: true, validation: { rule: schema.timestamp() }, factory: () => null },
    /** Last reported protection state (real-time on/off, database versions, engine). */
    protection: { required: false, fillable: true, validation: { rule: schema.json() }, factory: () => JSON.stringify({ realtime: true }) },
    lastSeenAt: { required: false, fillable: true, validation: { rule: schema.timestamp() }, factory: faker => faker.date.recent({ days: 1 }).toISOString() },
  },
  dashboard: { columns: ['name', 'platform', 'role', 'enrolmentState', 'lastSeenAt'] },
} as const)
