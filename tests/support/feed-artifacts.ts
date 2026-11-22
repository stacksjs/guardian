import { sign } from 'node:crypto'
import type { FeedSigningKey } from '../../app/Guardian/feed-format'
import { blake3, CVE_MAGIC, RULES_MAGIC } from '../../app/Guardian/feed-format'

/**
 * Feed artifacts built in TypeScript, so the distribution tests run with no zav binary (in CI).
 * They follow zig-anti-virus's formats: the rule bundle of docs/rules/guardian.md ("Bundle format
 * version 1") and the `.zavcve` container of src/db/format.zig. The zav-backed tests check the
 * same code paths against artifacts zav itself wrote.
 */

/** A `.zavrules` bundle of `files`, signed by `key` (or by `signer`, under `key`'s id). */
export function ruleBundle(options: { version: number, key: FeedSigningKey, signer?: FeedSigningKey, files?: Record<string, string> }): Buffer {
  const files = options.files ?? {
    'test-family/meta.toml': 'name = "test-family"\n',
    'test-family/marker.yar': 'rule marker { strings: $a = "guardian-test-marker" condition: $a }\n',
  }
  const records = Object.keys(files).sort().map((path) => {
    const name = Buffer.from(path, 'utf8')
    const content = Buffer.from(files[path]!, 'utf8')
    const head = Buffer.alloc(8)
    head.writeUInt16LE(name.length, 0)
    head.writeUInt32LE(content.length, 4)
    return Buffer.concat([head, name, content])
  })
  const body = Buffer.concat([Buffer.alloc(40), ...records])
  RULES_MAGIC.copy(body, 0)
  body.writeUInt32LE(1, 8)
  body.writeUInt32LE(records.length, 12)
  body.writeBigUInt64LE(BigInt(options.version), 16)
  body.writeBigUInt64LE(BigInt(body.length + 64), 24)
  Buffer.from(options.key.keyId, 'hex').copy(body, 32)
  return Buffer.concat([body, sign(null, body, (options.signer ?? options.key).privateKey)])
}

/**
 * A `.zavcve` index: a 4096-byte header and one `cve_records` section holding `records`, with the
 * section table hash, the BLAKE3 root of the body and, unless `key` is null, the key id and the
 * Ed25519 header signature filled in the way zav's writer fills them.
 */
export function cveIndex(options: { version: number, key: FeedSigningKey | null, records?: string }): Buffer {
  const section = Buffer.from(options.records ?? '{"id":"CVE-2021-44228","kev":true}\n', 'utf8')
  const head = Buffer.alloc(4096)
  CVE_MAGIC.copy(head, 0)
  head.writeUInt16LE(1, 8)
  head.writeUInt32LE(4096, 12)
  head.writeBigUInt64LE(BigInt(options.version), 24)
  head.writeBigUInt64LE(BigInt(options.version), 32)
  head.writeBigUInt64LE(BigInt(4096 + section.length), 40)
  head.writeUInt32LE(1, 48)
  head.writeUInt32LE(512, 52)
  // One section entry: kind cve_records (33), at 4096, page aligned.
  head.writeUInt32LE(33, 512)
  head.writeBigUInt64LE(4096n, 512 + 8)
  head.writeBigUInt64LE(BigInt(section.length), 512 + 16)
  head.writeBigUInt64LE(Bun.hash.xxHash3(section), 512 + 24)
  head.writeUInt8(12, 512 + 32)
  head.writeBigUInt64LE(Bun.hash.xxHash3(head.subarray(512, 512 + 64)), 120)
  Buffer.from(blake3(section)).copy(head, 256)
  if (options.key) {
    Buffer.from(options.key.keyId, 'hex').copy(head, 288)
    sign(null, head.subarray(0, 296), options.key.privateKey).copy(head, 296)
  }
  return Buffer.concat([head, section])
}

/** Re-sign a `.zavcve` header after a test changed it, as a holder of `key` could. */
export function resignCveHeader(index: Buffer, key: FeedSigningKey): Buffer {
  const out = Buffer.from(index)
  sign(null, out.subarray(0, 296), key.privateKey).copy(out, 296)
  return out
}
