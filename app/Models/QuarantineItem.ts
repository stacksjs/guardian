import { defineModel } from '@stacksjs/orm'
import { schema } from '@stacksjs/validation'

/** A detected file moved out of reach, with what is needed to restore or delete it. */
export default defineModel({
  name: 'QuarantineItem',
  table: 'quarantine_items',
  belongsTo: ['Detection'],
  traits: {
    useUuid: true,
    useTimestamps: true,
    useSeeder: { count: 6 },
  },
  attributes: {
    storedAt: { required: true, fillable: true, validation: { rule: schema.string().max(4096) }, factory: faker => `quarantine/${faker.string.uuid()}` },
    originalPath: { required: true, fillable: true, validation: { rule: schema.string().max(4096) }, factory: faker => `/var/www/uploads/${faker.system.fileName()}` },
    // 64-bit: Postgres makes `schema.number()` a 32-bit integer, which refuses anything past 2 GiB.
    size: { required: true, fillable: true, default: 0, type: 'bigint', validation: { rule: schema.number().min(0) }, factory: faker => faker.number.int({ min: 68, max: 50_000_000 }) },
    state: { required: true, fillable: true, default: 'held', validation: { rule: schema.enum(['held', 'restored', 'deleted']) }, factory: () => 'held' },
    restoredAt: { required: false, fillable: true, validation: { rule: schema.timestamp() }, factory: () => null },
    deletedAt: { required: false, fillable: true, validation: { rule: schema.timestamp() }, factory: () => null },
  },
  dashboard: { columns: ['originalPath', 'size', 'state', 'createdAt'] },
} as const)
