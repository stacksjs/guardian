// Project data for the Guardian issue graph: which repositories it spans, the short aliases the
// outline uses for them, and the label vocabularies. lib.ts validates the outline against this.

export const HUB = 'stacksjs/guardian'
export const PLAN_URL = 'https://github.com/stacksjs/guardian/blob/main/docs/PLAN.md'
export const AGENTS_URL = 'https://github.com/stacksjs/guardian/blob/main/AGENTS.md'

export const REPOS: Record<string, string> = {
  guardian: 'stacksjs/guardian',
  zav: 'zig-utils/zig-anti-virus',
  mime: 'zig-utils/zig-mime',
  starter: 'zig-utils/zig-starter',
  regex: 'zig-utils/zig-regex',
  waf: 'zig-utils/zig-waf',
  zcli: 'zig-utils/zig-cli',
  zconfig: 'zig-utils/zig-config',
  xml: 'zig-utils/zig-xml',
  zbench: 'zig-utils/zig-benchmarks',
  zsftp: 'zig-utils/zig-sftp',
  home: 'home-lang/home',
  stacks: 'stacksjs/stacks',
  broadcasting: 'stacksjs/ts-broadcasting',
  cloud: 'stacksjs/ts-cloud',
  sftp: 'stacksjs/ts-sftp',
  lfs: 'stacksjs/ts-git-lfs',
  backups: 'stacksjs/ts-backups',
  images: 'stacksjs/ts-images',
  heic: 'stacksjs/ts-heic',
  avif: 'stacksjs/ts-avif',
  videos: 'stacksjs/ts-videos',
  rpx: 'stacksjs/rpx',
  stx: 'stacksjs/stx',
  craft: 'craft-native/craft',
  mail: 'mail-os/mail',
  pantry: 'pantry-pm/pantry',
  browser: 'stacksjs/browser',
  attic: 'stacksjs/attic',
  reviewos: 'ReviewOS/reviewos.org',
  bughq: 'bughq/bughq',
  postline: 'stacksjs/postline',
}

export const AREAS: Record<string, string> = {
  graph: 'Issue graph and project process',
  build: 'Build, toolchain, packaging',
  db: 'Compiled signature database and compiler',
  match: 'Signature matching kernels',
  hash: 'Hashing',
  formats: 'File formats, containers, normalisers',
  engine: 'Scan pipeline, limits, cache',
  runtime: 'Threads, I/O, scheduling',
  daemon: 'Daemon and wire protocols',
  capi: 'C ABI and language bindings',
  watch: 'Real-time file watching',
  host: 'Host checks',
  cve: 'CVE automation',
  update: 'Signature and feed updates',
  cli: 'Command-line interface',
  bench: 'Benchmarks and gates',
  lib: 'Reusable library work',
  framework: 'Stacks framework integration',
  storage: 'Uploads and storage',
  email: 'Mail paths',
  waf: 'Web application firewall',
  app: 'Guardian application',
  ui: 'User interface',
  desktop: 'Native desktop app',
  deploy: 'Deployment and rollout',
  security: 'Security fix',
  docs: 'Documentation',
}

export const TYPES: Record<string, string> = {
  new: 'New code',
  port: 'Port or adaptation of existing code',
  perf: 'Performance work with a measured budget',
  test: 'Tests, fixtures, fuzzing, differential checks',
  infra: 'Tooling, CI, repositories, releases',
  experiment: 'De-risking experiment with a pass line',
  gate: 'Phase gate',
  fix: 'Bug or security fix',
  rollout: 'Production cutover',
}

export const SIZES = ['S', 'M', 'L']
