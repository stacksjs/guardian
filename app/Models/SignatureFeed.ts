import { defineModel } from '@stacksjs/orm'
import { schema } from '@stacksjs/validation'

/** A signature or advisory source a database is compiled from, and how current it is. */
export default defineModel({
  name: 'SignatureFeed',
  table: 'signature_feeds',
  traits: {
    useTimestamps: true,
    useSeeder: { count: 5 },
  },
  indexes: [{ name: 'signature_feeds_name_unique', columns: ['name'], unique: true }],
  attributes: {
    name: { required: true, fillable: true, validation: { rule: schema.string().max(120) }, factory: faker => faker.helpers.arrayElement(['clamav-main', 'clamav-daily', 'guardian-rules', 'cisa-kev', 'nvd']) + faker.string.alphanumeric(4) },
    source: { required: true, fillable: true, validation: { rule: schema.enum(['clamav', 'guardian', 'malwarebazaar', 'kev', 'nvd', 'osv']) }, factory: faker => faker.helpers.arrayElement(['clamav', 'guardian', 'kev']) },
    version: { required: false, fillable: true, validation: { rule: schema.string().max(40) }, factory: faker => String(faker.number.int({ min: 1, max: 30_000 })) },
    enabled: { required: true, fillable: true, default: true, validation: { rule: schema.boolean() }, factory: () => true },
    lastUpdatedAt: { required: false, fillable: true, validation: { rule: schema.timestamp() }, factory: faker => faker.date.recent({ days: 1 }).toISOString() },
    coverage: { type: 'text', required: false, fillable: true, validation: { rule: schema.string() }, factory: () => null },
  },
  dashboard: { columns: ['name', 'source', 'version', 'enabled', 'lastUpdatedAt'] },
} as const)
