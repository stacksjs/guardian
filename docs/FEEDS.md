# Feed distribution

Guardian serves two artifacts of its own to enrolled hosts, so each host updates from the Guardian
server instead of pulling every upstream feed itself:

| Kind | Artifact | Built by |
|---|---|---|
| `rules` | The signed Guardian rule pack (`.zavrules`, magic `ZAVRULE\n`) | `zav rule-pack` over the Guardian rule source |
| `cve` | The signed CVE index (`.zavcve`, magic `ZAVCVE\0\n`) | `zav cve fetch`, then `zav cve compile --signing-key`, from CISA KEV, OSV and NVD |

Nothing else is ever served. **ClamAV-derived databases are never distributed**: each host
fetches and compiles those itself. Three independent checks hold this:

1. Publishing accepts only the `guardian` source for `rules` and only `kev`, `osv` and `nvd` for
   `cve`. A `clamav` source is refused by name.
2. Publishing and serving both check the blob's first bytes and refuse anything that is not
   `ZAVRULE` or `ZAVCVE`: a compiled `.zavdb`, a ClamAV CVD, CLD or CUD, or any other file.
3. The download endpoint serves only the file name the publish step recorded for that kind. It
   never takes a path from a request.

The code is in `app/Guardian/feed*.ts`, and `tests/feature/feed.test.ts` exercises these checks.

## Server setup

### 1. The feed signing key

One Ed25519 key signs the manifests, the rule pack and the CVE index. It is a file of exactly 32
random bytes (the raw Ed25519 seed, the format `zav --signing-key` reads):

```bash
umask 077
head -c 32 /dev/urandom > /path/outside/the/repo/guardian-feed.key
```

Keep it outside the repository, readable only by the user Guardian runs as, and back it up. Point
`GUARDIAN_FEED_SIGNING_KEY_FILE` at it. Guardian refuses, before reading it, a key file that is not
exactly 32 bytes or that group or others can access (it must be mode 0600 or stricter). Without
that variable the server publishes nothing, `GET /api/feeds/key` answers 404, enrolment returns
`feedKey: null`, and the scheduled rebuild skips itself.

Only the processes that publish (the scheduler and `buddy feed:*`) need the seed. A process that
only enrols hosts and serves feeds needs the public half alone: set `GUARDIAN_FEED_PUBLIC_KEY` (64
hex digits) there and leave `GUARDIAN_FEED_SIGNING_KEY_FILE` unset. Where both are set, publishing
refuses to run unless they are the same key. Without `GUARDIAN_FEED_PUBLIC_KEY`, the public key is
derived from the seed once per process and seed file, not on every request.

### 2. The zav binary

Install `zav` (zig-anti-virus) on the server. Guardian uses `GUARDIAN_ZAV_BIN` when it is set and
otherwise looks for `zav` on `PATH`. zav runs with a small allowlisted environment (`PATH`,
`HOME`, `TMPDIR`, locale, proxy and CA settings, and `NVD_API_KEY` when set), never the server's
own secrets.

### 3. Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `GUARDIAN_FEED_SIGNING_KEY_FILE` | unset (feeds off) | Path of the 32-byte Ed25519 seed |
| `GUARDIAN_FEED_PUBLIC_KEY` | derived from the seed | The feed public key, for processes that serve feeds but never sign them |
| `GUARDIAN_FEED_DIR` | `storage/guardian/feeds` | Published blobs, plus the `work/` directory zav fetches and compiles in |
| `GUARDIAN_ZAV_BIN` | `zav` on `PATH` | The zav binary |
| `GUARDIAN_RULES_SOURCE_DIR` | unset | The Guardian rule source `buddy feed:publish-rules` packs |
| `GUARDIAN_CVE_OSV_ECOSYSTEMS` | zav's defaults (npm, PyPI, Go, crates.io) | Comma-separated OSV ecosystems to fetch |
| `GUARDIAN_CVE_NVD` | on | Set to `false` to leave NVD out of the index |
| `NVD_API_KEY` | unset | Your NVD API key. Passed to zav only when set; it raises NVD's rate limit |

### 4. Where published blobs live

The published blobs are files in `GUARDIAN_FEED_DIR`; the database rows only name them. That
directory must therefore:

- **outlive a deploy.** The default sits inside the release tree, so `config/cloud.ts` lists
  `storage/guardian` in both sites' `sharedPaths`, pointing at one project-level shared directory.
  A deploy that loses it leaves the rows naming missing blobs (hosts get 503 until the next
  publish puts the blob back) and throws away zav's saved NVD progress, forcing a full re-mirror.
- **be the same directory for every process that serves `/api`.** With more than one app server,
  put it on a shared filesystem. A server that cannot find or verify the recorded blob answers
  503 and logs why.

`storage/guardian/` is gitignored, so a local run never leaves blobs or the feed mirror to commit.

### 5. Publishing

- **CVE index:** the `RebuildCveIndex` job (`app/Jobs/RebuildCveIndex.ts`) runs every six hours
  at minute 17, on one server, never overlapping a previous run, and also under its own lock
  file. Run it by hand with `./buddy feed:rebuild-cve`.
- **Rule pack:** `./buddy feed:publish-rules [--source DIR] [--pack-version N]`. The version
  defaults to the published version plus one.

One publish of a kind runs at a time, under a lock file in the feed directory. Before anything is
published the copy that will be served is checked whole: a rule bundle's Ed25519 footer, and for an
index the header signature, the section table, the unsigned header bytes (which must be zero) and
BLAKE3 over the whole body against the signed root.

A run whose sources did not change publishes nothing: the rebuilt artifact is compared with the
published one by content (everything except its version, compile time and signature), so hosts
keep getting 304 instead of downloading an identical index. That holds only while the published
blob is intact on disk; if it is missing or damaged, the next publish puts it back. A failed fetch,
compile or publish is logged with its cause and leaves the published artifact, its manifest and its
ETags as they were. A server with a feed key but no usable zav binary (a wrong `GUARDIAN_ZAV_BIN`,
or a `PATH` without zav) is a logged failure, never a silent skip.

The index holds only the configured sources: with `GUARDIAN_CVE_NVD=false` the NVD mirror (and its
saved progress) is removed before compiling, and so is any OSV ecosystem no longer listed.

### Upstream terms

Only the Guardian server talks to the upstream feeds, once per run, never once per host. zav
syncs NVD incrementally by `lastModified` window from its saved progress (kept in
`GUARDIAN_FEED_DIR/work/cve/state`) and paces its requests to NVD's public rate limit, or to the
keyed limit when `NVD_API_KEY` is set. The six-hour cadence stays well inside NVD's guidance of no
more than one sync every two hours. A first NVD mirror without a key can take hours, which is why
the job's overlap guard lasts eight hours.

## Endpoints

All are under `/api`, behind the `host` middleware (the host's `gdh_` bearer credential), and
rate limited per host credential, so hosts behind one NAT do not share a budget. A much higher
per-address limit runs before authentication as a flood guard. `{kind}` is `rules` or `cve`; any
other kind is 404.

| Method and path | Answer |
|---|---|
| `GET /api/feeds/key` | `{ algorithm: "ed25519", publicKey, keyId }`, the current feed key (30 per minute per host) |
| `GET /api/feeds/{kind}/manifest` | `{ format, manifest, signature }`, the signed manifest (60 per minute per host) |
| `GET /api/feeds/{kind}/blob` | The artifact bytes (30 per minute per host) |

Both the manifest and the blob carry a strong `ETag` and `Cache-Control: private, no-cache`. The
blob's ETag is its SHA-256; the manifest's is the SHA-256 of its signed bytes. A request whose
`If-None-Match` matches gets `304 Not Modified` with no body. A blob request whose `If-Match`
names another blob (the host read a manifest that a newer publish has since replaced) gets
`412 Precondition Failed` before any byte, and the host picks up the new version on its next
check. A kind with nothing published is 404.

The blob is served only from the file the publish step recorded, opened without following
symlinks, and only when it has the recorded size, the kind's magic and the recorded SHA-256; the
bytes streamed come from the descriptor those checks read. Anything else is 503.

The manifest has six fields, `kind`, `version`, `sha256`, `size`, `createdAt` and `keyId`. The
signature is Ed25519 over `guardian-feed-manifest-v1`, one LF, then the manifest as JSON with keys
in lexicographic order and no whitespace. `app/Guardian/feed-format.ts` documents the exact bytes.

## Hosts

### Pinning the key

A host takes the feed public key **only from its enrolment response** (`feedKey.publicKey` and
`feedKey.keyId` from `POST /api/hosts/enrol`, an exchange authenticated by the single-use
enrolment token) and pins it. It never trusts a key from a feed response. `GET /api/feeds/key`
exists so an agent can notice that the server's key changed; adopting a new key is an operator
decision (re-enrol the host or re-pin the key), never automatic.

### Updating

The updater is `updateFeed` in `app/Guardian/feed-client.ts`. For each kind it:

1. requests the manifest with the last manifest ETag in `If-None-Match`, and stops on 304;
2. verifies the manifest signature with the pinned key;
3. refuses a version lower than or equal to the installed one, so an old, authentic manifest
   cannot be replayed to roll the host back. The floor is the larger of the version in its state
   file and the version in the installed file's header. A manifest of the installed version whose
   SHA-256 is the installed file's is current, and the state file is written again if it was lost;
4. downloads the blob with `If-Match` set to the manifest's digest, refusing more bytes than the
   manifest's size, and checks its size and SHA-256;
5. checks the artifact whole: the magic, the header version (it must equal the manifest's), a rule
   bundle's own Ed25519 footer, and for an index the header signature by the pinned key (an
   unsigned index is refused), the section table, the unsigned header bytes and BLAKE3 over the
   whole body against the signed root;
6. writes a temporary file, fsyncs it and renames it over the installed file. On any failure the
   installed file is left exactly as it was.

The whole blob is checked before the swap, because opening a `.zavcve` checks its header but not
every section body.

**Freshness.** A manifest's `createdAt` is signed but not compared with the clock. A server or
channel that keeps answering 304, or keeps replaying the current manifest, can hold a host on the
version it has; it can never move it backwards. Because an unchanged rebuild keeps the same
version and manifest, an old version alone does not prove a freeze, so this updater does not try
to detect one; an agent that must, needs a freshness signal it can trust independently.

### Using what was installed

Pass the pinned key to zav so it checks the signature again when it loads the artifact:

```bash
zav compile --guardian-bundle guardian.zavrules --guardian-key PUBLIC_KEY_HEX ...
zav audit --cve-index cve.zavcve --cve-key PUBLIC_KEY_HEX ...
zav host --cve-index cve.zavcve --cve-key PUBLIC_KEY_HEX ...
```

With `--cve-key`, zav requires a signature from that key and hashes the whole index body. Without
it, zav accepts only an unsigned, locally compiled index, so a served index always needs the flag.
