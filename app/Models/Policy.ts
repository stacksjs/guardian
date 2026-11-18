import { defineModel } from '@stacksjs/orm'
import { schema } from '@stacksjs/validation'

/** What to scan and how strictly, applied to hosts that select it. */
export default defineModel({
  name: 'Policy',
  table: 'policies',
  traits: {
    useTimestamps: true,
    useSeeder: { count: 2 },
  },
  indexes: [{ name: 'policies_name_unique', columns: ['name'], unique: true }],
  attributes: {
    name: { required: true, fillable: true, validation: { rule: schema.string().max(120) }, factory: faker => `${faker.word.adjective()}-policy-${faker.string.alphanumeric(4)}` },
    surfaces: { required: true, fillable: true, validation: { rule: schema.json() }, factory: () => JSON.stringify(['uploads', 'mail', 'realtime']) },
    failClosed: { required: true, fillable: true, default: true, validation: { rule: schema.boolean() }, factory: () => true },
    limits: { required: false, fillable: true, validation: { rule: schema.json() }, factory: () => JSON.stringify({ maxFileSize: 100 * 1024 * 1024 }) },
    schedule: { required: false, fillable: true, validation: { rule: schema.string().max(120) }, factory: () => '0 3 * * *' },
    suppressions: { required: false, fillable: true, validation: { rule: schema.json() }, factory: () => JSON.stringify([]) },
  },
  dashboard: { columns: ['name', 'failClosed', 'schedule'] },
} as const)
