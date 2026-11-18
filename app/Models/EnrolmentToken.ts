import { defineModel } from '@stacksjs/orm'
import { schema } from '@stacksjs/validation'

/** A single-use token an operator creates to enrol one host. Only its SHA-256 is stored. */
export default defineModel({
  name: 'EnrolmentToken',
  table: 'enrolment_tokens',
  belongsTo: ['Host'],
  traits: {
    useTimestamps: true,
  },
  indexes: [{ name: 'enrolment_tokens_hash_unique', columns: ['token_hash'], unique: true }],
  attributes: {
    tokenHash: { required: true, fillable: true, hidden: true, validation: { rule: schema.string().max(64) }, factory: faker => faker.string.hexadecimal({ length: 64, casing: 'lower', prefix: '' }) },
    label: { required: false, fillable: true, validation: { rule: schema.string().max(255) }, factory: faker => faker.word.noun() },
    expiresAt: { required: true, fillable: true, validation: { rule: schema.timestamp() }, factory: faker => faker.date.soon({ days: 1 }).toISOString() },
    usedAt: { required: false, fillable: true, validation: { rule: schema.timestamp() }, factory: () => null },
  },
} as const)
