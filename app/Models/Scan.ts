import { defineModel } from '@stacksjs/orm'
import { schema } from '@stacksjs/validation'

/** One scan run on a host: a path, a schedule, an upload, a real-time event batch. */
export default defineModel({
  name: 'Scan',
  table: 'scans',
  belongsTo: ['Host'],
  hasMany: ['Detection'],
  traits: {
    useUuid: true,
    useTimestamps: true,
    useSeeder: { count: 40 },
  },
  indexes: [
    { name: 'scans_host_started', columns: ['host_id', 'started_at'] },
    { name: 'scans_host_scan_key_unique', columns: ['host_id', 'scan_key'], unique: true },
  ],
  attributes: {
    /** Client-chosen id for the scan, so a replayed batch is recognised and not stored twice. */
    scanKey: { required: true, fillable: true, validation: { rule: schema.string().max(64) }, factory: faker => faker.string.uuid() },
    target: { required: true, fillable: true, validation: { rule: schema.string().max(1024) }, factory: faker => faker.helpers.arrayElement(['/var/www', '/home', 'upload', 'realtime', '/opt/app']) },
    trigger: { required: true, fillable: true, default: 'manual', validation: { rule: schema.enum(['manual', 'scheduled', 'upload', 'realtime', 'mail']) }, factory: faker => faker.helpers.arrayElement(['manual', 'scheduled', 'upload']) },
    startedAt: { required: true, fillable: true, validation: { rule: schema.timestamp() }, factory: faker => faker.date.recent({ days: 7 }).toISOString() },
    finishedAt: { required: false, fillable: true, validation: { rule: schema.timestamp() }, factory: faker => faker.date.recent({ days: 7 }).toISOString() },
    files: { required: true, fillable: true, default: 0, validation: { rule: schema.number().min(0) }, factory: faker => faker.number.int({ min: 1, max: 200_000 }) },
    // 64-bit: Postgres makes `schema.number()` a 32-bit integer, which refuses anything past 2 GiB.
    bytes: { required: true, fillable: true, default: 0, type: 'bigint', validation: { rule: schema.number().min(0) }, factory: faker => faker.number.int({ min: 1_000, max: 20_000_000_000 }) },
    infected: { required: true, fillable: true, default: 0, validation: { rule: schema.number().min(0) }, factory: faker => faker.helpers.arrayElement([0, 0, 0, 0, 0, 0, 0, 0, 0, faker.number.int({ min: 1, max: 4 })]) },
    limited: { required: true, fillable: true, default: 0, validation: { rule: schema.number().min(0) }, factory: () => 0 },
    errors: { required: true, fillable: true, default: 0, validation: { rule: schema.number().min(0) }, factory: () => 0 },
    engineVersion: { required: false, fillable: true, validation: { rule: schema.string().max(40) }, factory: () => '0.1.0' },
    databaseVersion: { required: false, fillable: true, validation: { rule: schema.string().max(40) }, factory: faker => String(faker.number.int({ min: 1, max: 1_000_000 })) },
  },
  dashboard: { columns: ['host', 'target', 'trigger', 'files', 'infected', 'startedAt'] },
} as const)
