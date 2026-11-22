import { defineModel } from '@stacksjs/orm'
import { schema } from '@stacksjs/validation'

/**
 * A signature or advisory source a database is compiled from, and how current it is.
 *
 * A row with a `kind` is an artifact Guardian itself publishes to enrolled hosts (see
 * app/Guardian/feed.ts): the signed rule pack (`rules`) or the compiled CVE index (`cve`). Only
 * the publish path writes those columns, and the serve path reads blobs only through them.
 * Rows without a `kind` (ClamAV, MalwareBazaar and the upstream advisory feeds) are never served.
 */
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
    /** The distributable artifact this row publishes; null for every feed that is not served. */
    kind: { required: false, fillable: true, validation: { rule: schema.enum(['rules', 'cve']) }, factory: () => null },
    /** Lowercase hex SHA-256 of the published blob, also its strong ETag. */
    sha256: { required: false, fillable: true, validation: { rule: schema.string().max(64) }, factory: () => null },
    // 64-bit: Postgres makes `schema.number()` a 32-bit integer, which refuses anything past 2 GiB.
    size: { required: false, fillable: true, type: 'bigint', validation: { rule: schema.number().min(0) }, factory: () => null },
    /** File name of the published blob inside the feed directory, recorded by the publish path only. */
    path: { required: false, fillable: true, validation: { rule: schema.string().max(255) }, factory: () => null },
    /** The canonical manifest bytes the signature covers (see app/Guardian/feed.ts). */
    manifest: { type: 'text', required: false, fillable: true, validation: { rule: schema.string() }, factory: () => null },
    /** Base64 Ed25519 signature over the manifest. */
    signature: { required: false, fillable: true, validation: { rule: schema.string().max(128) }, factory: () => null },
    /** Hex key id of the signing key: the first 8 bytes of BLAKE3(public key), as zav computes it. */
    keyId: { required: false, fillable: true, validation: { rule: schema.string().max(16) }, factory: () => null },
  },
  dashboard: { columns: ['name', 'source', 'version', 'enabled', 'lastUpdatedAt'] },
} as const)
