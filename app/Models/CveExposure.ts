import { defineModel } from '@stacksjs/orm'
import { schema } from '@stacksjs/validation'
import { SEVERITIES } from '../Guardian/severity'

/** An installed package version on a host that a known CVE affects. */
export default defineModel({
  name: 'CveExposure',
  table: 'cve_exposures',
  belongsTo: ['Host'],
  traits: {
    useUuid: true,
    useTimestamps: true,
    useSeeder: { count: 25 },
  },
  indexes: [{ name: 'cve_exposures_host_cve_package', columns: ['host_id', 'cve_id', 'package'], unique: true }],
  attributes: {
    /** The inventory run that reported this exposure; each run replaces the host's whole set. */
    inventoryRun: { required: true, fillable: true, validation: { rule: schema.string().max(64) }, factory: faker => faker.string.uuid() },
    package: { required: true, fillable: true, validation: { rule: schema.string().max(255) }, factory: faker => faker.helpers.arrayElement(['openssl', 'nginx', 'sudo', 'glibc', 'lodash', 'xz-utils']) },
    ecosystem: { required: true, fillable: true, validation: { rule: schema.enum(['dpkg', 'rpm', 'apk', 'homebrew', 'pantry', 'npm', 'pypi', 'go', 'cargo', 'macos-app']) }, factory: faker => faker.helpers.arrayElement(['dpkg', 'npm']) },
    installedVersion: { required: true, fillable: true, validation: { rule: schema.string().max(120) }, factory: faker => faker.system.semver() },
    fixedVersion: { required: false, fillable: true, validation: { rule: schema.string().max(120) }, factory: faker => faker.system.semver() },
    cveId: { required: true, fillable: true, validation: { rule: schema.string().max(32) }, factory: faker => `CVE-${faker.number.int({ min: 2019, max: 2026 })}-${faker.number.int({ min: 1000, max: 49999 })}` },
    // A double, not the integer `schema.number()` implies: scores carry one decimal, and Postgres rounded 9.8 to 10.
    cvss: { required: false, fillable: true, type: 'double', validation: { rule: schema.number().min(0).max(10) }, factory: faker => faker.number.float({ min: 3, max: 10, fractionDigits: 1 }) },
    severity: { required: true, fillable: true, default: 'medium', validation: { rule: schema.enum([...SEVERITIES]) }, factory: faker => faker.helpers.arrayElement(['medium', 'high', 'critical']) },
    kev: { required: true, fillable: true, default: false, validation: { rule: schema.boolean() }, factory: faker => faker.datatype.boolean({ probability: 0.15 }) },
    kevDueDate: { required: false, fillable: true, validation: { rule: schema.string().max(10) }, factory: () => null },
  },
  dashboard: { columns: ['host', 'package', 'installedVersion', 'cveId', 'severity', 'kev'] },
} as const)
