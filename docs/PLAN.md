# Guardian plan

## Context

**The problem.** The Stacks ecosystem takes in untrusted bytes in more than 40 places. Almost none of them are scanned:
- Framework uploads.
- The mail server: DATA, BDAT, IMAP APPEND, ActiveSync, CalDAV and webmail uploads.
- SES inbound mail.
- pantry-registry publishes and pantry client installs.
- SFTP, Git LFS and backup restores.
- rpx request bodies.
- Craft/browser downloads.
- App surfaces: Attic attachments, ReviewOS pushes, LFS, release assets and artifacts, bughq symbol uploads, postline media.

**Where ClamAV is today.** The only working scanner is ClamAV in pantry-registry. clamd parses about 4M hash signatures and about 170k pattern signatures into RAM, which takes 1.2-4 GiB (ClamAV's docs ask for 3-4 GiB). The registry box caps it at 55-65% of RAM. ts-cloud only references it in its memory commitment report. The mail server has an unused, TCP-only `clamav.zig` that lets mail through when the scanner is off.

**The goal.**
- **`zig-anti-virus` (`zav`):** our own Zig engine and daemon. Signatures are compiled offline into a signed, mmapped blob, so the daemon holds about 0 MB of private memory for signatures and 24-64 MB in total.
  - It speaks the clamd protocol, so existing clients keep working.
  - Throughput target: at least 3x clamd.
- **Host protection:** linux-guardian's host heuristics and CVE automation, implemented in Zig.
- **Framework:** native Stacks integration through a `@stacksjs/malware` package.
- **Guardian app:** `~/Code/Apps/guardian` with a web dashboard, a native macOS app (Craft AppKit plus tray popover) and a `guardian` CLI.

**Process.**
- The whole plan becomes **GitHub issues in each owning repo**, ordered by dependency, before any code.
- Fixes go into whichever repo owns the code, and releases go out with `release:patch`.
- Small conventional commits go straight to `origin/main` as the maintainer, with no co-author trailers.

## Decisions

Made by the maintainer (2026-11-17):
- **Signatures:**
  - ClamAV, compiled locally from CVDs each install downloads itself, never re-hosted
  - Guardian's own rules
  - linux-guardian-style heuristics and CVE automation
  - MalwareBazaar, optional and off by default (needs a key; non-commercial terms)
- **Desktop:** macOS AppKit with a native sidebar and tray popover first. Windows and Linux come later.
- **Repos:** `zig-utils/zig-anti-virus`, `zig-utils/zig-mime` and `stacksjs/guardian`, all public.
- **Production rollout:** mail and pantry-registry switch over to zav as soon as the tests pass.

My defaults, overridable:
- **Guardian rule language:** the same YARA subset the engine already reads, plus TOML metadata. There is no new language to learn or parse.
- **Pure Zig, no C dependencies.** If the decoder benchmark (E7) shows `std.compress` is too slow, optimise it in our code or upstream instead of linking zlib-ng.
- **Distribution:** Guardian rules and the CVE index may ship prebuilt. ClamAV-derived `.zavdb` blobs are only compiled on each host.
- **Toolchain:** Zig `0.17.0-dev.1857` or newer, the same as zig-routing. The global `.1441` is too old for zig-tls.
- **zig-waf:** it is Guardian's HTTP layer and stays standalone. Its open roadmap issues are implemented as part of this graph (Phase 8b). The console is one stx codebase, embedded in zig-wafd and imported by Guardian. The fleet is federated: zig-waf's controller is the authority for WAF, and Guardian is the single operator surface.

## Phase 0 - Issue graph first

The tooling is a generalised copy of `~/Code/Libraries/zig-routing/scripts/issues/`. It lives in the hub repo `stacksjs/guardian` under `scripts/issues/`.

**Outline format**
- `OUTLINE.txt` adds a repo column: `KEY | repo | title | area | type | size | blockers | flags`.
- Phase headers stay `## P<n> | milestone | goal`. Blockers must still appear above the issues they block, which keeps the order topological.
- Area and type lists become per-project data in `outline.config.ts`, checked against the outline before anything is created.

**Creating issues**
- `created.json` stores `owner/repo#N`.
- Bodies render cross-repo blocker links ("Blocked by owner/repo#N"), with goal, scope, out-of-scope, acceptance and upstream sections.
- In each target repo, `create.ts` creates the labels: `guardian`, `ready`, `blocked`, `needs-human`, `phase:<n>`, `area:*`, `type:{new,port,perf,test,infra,experiment,gate,fix}`, `size:{S,M,L}`. It reuses `blocked` where it already exists (zig-waf, zig-regex, stacks).
- Milestones are created per repo. The script is resumable with retries and backoff, never duplicates, and supports `--dry-run` and `--show KEY`.

**Hub issues**
- A pinned START issue and one epic per phase live in the hub.
- Each repo also gets a tracking epic listing its own leaves.

**Readiness sync**
- `sync-ready.ts` loads issues from every repo in `created.json` and flips each between `blocked` and `ready`.
- A hub workflow runs it on a schedule (every 15 min) and on manual dispatch. It needs a cross-org token secret, `ISSUE_GRAPH_TOKEN`. That is a `needs-human` issue for the maintainer.
- Agents also run sync locally after closing an issue.

**Rules**
- Always look issue numbers up in `created.json`. Never guess them; that lesson came from zig-routing.
- An outline line may point at an existing issue (`=> owner/repo#N`) instead of creating one. The 28 open zig-waf roadmap issues are wired in this way. `sync-ready` labels existing nodes too.
- Issues are public, so they must not contain box IPs, hostnames or private app details.

**Expected size:** about 300 issues across about 25 repos. The exact remotes are verified with `gh repo view` before creation. Target repos:
- zig-utils: zig-starter, zig-anti-virus (new), zig-mime (new), zig-regex, zig-waf, zig-cli, zig-xml, zig-benchmarks, zig-sftp
- home-lang/lang (compression format bugs)
- stacksjs: stacks, guardian (new), ts-broadcasting, ts-cloud, ts-sftp, ts-git-lfs, ts-backups, ts-images, rpx, stx
- craft-native/craft
- mail-os/mail
- pantry-pm/pantry (both the registry and the client)
- App repos: browser, attic, reviewos, bughq, postline

**Workflow**
- Create the hub repo first with `buddy new guardian` and `gh repo create stacksjs/guardian --public`. Then write the outline and bodies, dry-run, and create.
- Implementation takes the lowest open `ready` issue. Each commit says `Closes owner/repo#N`, and every closed issue gets a comment explaining its decisions.

## Phase 1 - zig-starter improvements (`zig-utils/zig-starter`)

- **Toolchain pin:** pin Zig through pantry `deps.yaml`, `build.zig.zon`, CI and the README together.
- **Git hygiene:** remove the committed 1.2 MB `test` Mach-O and fix `.gitignore`.
- **Build:**
  - `lib` steps that build a static and a dynamic library.
  - An `export fn starter_*_v1` sample with `include/zig_starter.h`.
  - The test step covers `main.zig`, and `lib_mod` gets an optimize mode.
- **Bun binding:** a bun:ffi wrapper under `ts/`, following `~/Code/Tools/dtsx/packages/zig-dtsx/src/index.ts` (look in `zig-out/lib` first, then `prebuilt/<slug>`).
- **Release:** prebuilt binaries for 6 targets (dtsx's `release.yml` matrix), then `pantry publish` and `pantry publish --npm`.
- **Extra build steps:** `fuzz` and `bench` (zig-benchmarks), plus a ReleaseSafe test job.
- **CI:** Windows, and a CPU-variant build matrix (see the engine's runtime dispatch).
- **Dependencies:** pantry-registry URL+hash entries in zon (zig-waf's pattern). Drop the relative paths and the wrong `package.jsonc` paths.

Release it, then use it to scaffold `zig-anti-virus` and `zig-mime`.

## Phase 2 - Engine design: performance and memory (`zig-utils/zig-anti-virus`)

The full study goes into the repo as `docs/DESIGN.md`. These are its main decisions; [E] marks a figure that an experiment must confirm.

**Compiled database `.zavdb`** (ClamAV already uses `.gdb`)
- **Header:** 4 KiB, little-endian, with offsets only (no pointers) and comptime layout asserts. It carries a section table with xxh3 per section, a BLAKE3 root and an ed25519 signature.
- **Loading:** raw `posix.mmap(PROT_READ)`. Never `std.Io.File.MemoryMap`, which silently falls back to heap plus read and would turn 200 MB into private memory.
- **Verification:** the full BLAKE3 runs once at install, recorded in a sidecar. Startup only checks the header and section table.
- **Section order:** the hot region comes first, 2 MiB aligned. Hot sections are the hash-need map, prefilters, atom tables, anchored index, FTM trie and hot hash keys. Then come the warm sections (subsignature programs, logical-signature table), then the cold ones (full digests, FP tables, names, regex, coverage report).

**Hashes**
- A per-file-size need map (4 bits per size for sizes below 2^24) decides which algorithms to run before any hashing happens. When the size has no hash signature, hashing is skipped entirely.
- Hot tier: an 8-byte prefix per entry, about 32 MB for 4M entries, mapped and clean. Cold tier: the full digest, always compared on a prefix hit.
- An optional binary-fuse filter, if experiment E1 shows it pays off.
- Hashing is one fused pass that computes only the needed algorithms.
- FP tables keep full digests.
- Signature names are tokenised to about 16 bytes per record.

**Byte patterns (instead of clamd's in-RAM Aho-Corasick)**
- For each subsignature, pick its rarest 4-byte atom using a benign-corpus 4-gram frequency model.
- Tiered sampled split-block Bloom prefilters, partitioned by ClamAV target type:
  - A: anchor of 11 bytes or more, stride 8
  - B: 7-10 bytes, stride 4
  - C: 4-6 bytes, stride 1
  - D: 3 bytes or fewer, deferred behind required partner subsignatures or anchored
- These have no loop-carried dependency, so they get memory-level parallelism. Target: about 1 GB/s per core [E], against roughly 70-200 MB/s for a large Aho-Corasick automaton.
- Hits go through an atom hash table, then a masked anchor compare, then a small verify VM with step budgets.
- Offset signatures (EP+n, EOF-n, Sx+n) are looked up directly and never scanned for.
- Logical signatures keep a sparse touched-state table per worker (128 KB, reset in O(touched)) and evaluate as RPN expressions.

**Runtime**
- **Threads:** work-stealing Chase-Lev deques with one worker per physical core, and a bounded injector for backpressure.
- **Allocation:** none in the hot loop. Each worker has a lazily faulted scratch arena, trimmed with madvise when idle.
- **Memory bound:** a global 64 MiB budget for large decoder windows.
- **I/O:**
  - pread into a reused 1 MiB buffer, then 256 KiB streaming.
  - io_uring batches openat/statx/read/close on Linux.
  - `getattrlistbulk` for walking directories on macOS.
  - mmap only for large random access, to avoid TLB shootdowns from munmap.
- **CPU variants:** builds for x86-64-v2, v3, v3+sha and aarch64+crypto, chosen at runtime. Hardware SHA-1/SHA-256 is otherwise compiled out of a baseline build.
- **Scan cache:** an mmapped `scan-cache.zavc`.
  - Keyed by (dev, ino, size, mtime_ns, ctime_ns, db_version).
  - Readers are protected with a seqlock plus CRC; only CLEAN verdicts are cached.
  - Racy-timestamp rule; caching is off on filesystems with coarse timestamps.
  - Delta rescan: a file cached clean under an older database is rescanned only against the signatures added since.
- **Reload:** the new blob is mmapped and swapped with epoch reclamation, adding about 0 MB of private memory (clamd doubles).
- **Containers:** streamed through a `Source` abstraction.
  - Children of 8 MiB or less go to an arena; larger ones spill to `O_TMPFILE`.
  - Limits match clamd's: recursion 17, file count and size caps, a ratio guard, overlapping-zip detection.
  - Decoder windows over 1 MiB are budgeted.

**Targets**
| Metric | Target |
|---|---|
| Private dirty, idle | 24 MB or less |
| Private dirty, nominal load | 64 MB or less |
| Reload delta | 2 MB or less |
| Startup, warm page cache | under 50 ms |
| Startup, cold page cache | under 300 ms |
| Mixed corpus | at least 3x clamd |
| Small files on Linux | at least 40k files/s per core |
| INSTREAM 1 MB, after the last byte | p99 of 5 ms or less |
| fanotify, cached file | 20 µs or less |
| Parity vs clamd `--bytecode=no` on supported types | at least 99.5%, with no new false positives |

**Coverage scope**
- **In:** hdb, hsb, mdb, msb, imp, ndb, ldb (including PCRE and byte-compare), cdb, ftm, fp, sfp, ign2, the YARA subset, Guardian rules, MalwareBazaar.
- **Phase 2:** pdb and wdb (phishing), idb, crb and cat.
- **Out:** `.cbc` bytecode, estimated at under 0.5% of unique detections [E]. The compiler writes a coverage report that counts every skipped signature by reason, so the loss is a measured number.

**Biggest risk:** parser and normaliser parity, not matching speed. Formats are built in the order they matter on a real corpus:
1. gzip, zip, tar, bzip2, xz, zstd, OOXML, MIME, PE, ELF, Mach-O, HTML and ASCII normalisers.
2. OLE2/VBA, PDF, JS, RTF, 7z.
3. CAB, CHM, NSIS, ISO, DMG, unpackers. RAR waits on a licence review.

**Experiments, each its own issue and run first:**
- **E0:** census of the real database (counts by type, the A-D tier histogram, size-less hashes, size coverage). Its numbers replace every [E].
- **E1:** hash index lookups and the share of bytes skipped.
- **E2:** prefilter bake-off: Bloom vs FDR vs a depth-4 double-array Aho-Corasick vs Teddy.
- **E3:** atom selection vs prefix, and tier-D deferral.
- **E4:** verify VM worst case.
- **E5:** memory: idle, load and reload.
- **E6:** I/O: pread vs mmap vs io_uring.
- **E7:** std decoder speed vs zlib-ng.
- **E8:** hardware hashers.
- **E9:** parity and false positives vs clamd.
- **E10:** scan-cache fault injection.
- **E11:** fanotify latency.
- **E12:** huge pages.
- **E13:** zig-regex byte mode vs PCRE2.
- **E14:** 1000 concurrent INSTREAM connections.

## Phase 3 - Engine implementation (modules in `zig-anti-virus/src/`)

**Modules**
- `db/`, `compile/`:
  - CVD (std.tar + flate, Talos signature checked)
  - per-extension parsers into a rule IR; YARA subset; Guardian rules; MalwareBazaar
  - atom selection, Bloom and hash builders using an external sort
  - layout, delta blobs, coverage report
- `match/`: hash index, need map, Bloom probe kernels per architecture, atom table, verify VM, anchored lookups, logical signatures, Teddy for small partitions, regex bridge.
- `hash/`: fused multihash plus hardware SHA-1. `simd/`: architecture dispatch and inline-asm byte shuffles.
- `fmt/`: the formats above. `engine/`: Source, pipeline, limits, scratch, budget, cache. `rt/`: deque, pool, epoch, ioloop, walk, io_small.
- `daemon/`:
  - clamd protocol: PING, VERSION, VERSIONCOMMANDS, RELOAD, SHUTDOWN, STATS, SCAN, CONTSCAN, MULTISCAN, ALLMATCHSCAN, INSTREAM, FILDES via SCM_RIGHTS, IDSESSION; `z`, `n` and bare prefixes.
  - INSTREAM scans incrementally as chunks arrive, spilling after 256 KiB.
  - A native multiplexed binary protocol `zavp/1`.
  - A `clamd.conf` parser.
- `capi/` (`zav.h`):
  - engine open, retain, release and reload; one scratch per JS thread
  - scan buffer, fd and path; streaming
  - an async `zav_submit` / `zav_poll` with a notify fd, so no JS callbacks run in the hot path
  - structs versioned by size
- `watch/`:
  - fanotify: `FAN_OPEN_EXEC_PERM` and `FAN_CLOSE_WRITE`, scanning the fd delivered in the event, with evictable ignore marks as an in-kernel clean cache and a deadline policy.
  - FSEvents.
  - Endpoint Security in a separately signed helper. It needs Apple's entitlement, which is a `needs-human` issue.
- `host/`: the linux-guardian layer. `cve/`: KEV, NVD and OSV compiled into `.zavcve`. Both are described in Phase 4.
- `cli/`: `zav scan | compile | daemon | update | audit | host | bench | coverage`, built with zig-cli.
- `update/`: ClamAV CVD and cdiff fetch with a generic User-Agent, MalwareBazaar (with key), the Guardian rule feed and CVE feeds. Compiling runs out of process at low priority, followed by an atomic rename and a reload.

**Tests**
- EICAR, plain and zipped.
- Differential tests against libclamav (`sigtool --test-sigs`), with a synthetic signature for each grammar feature.
- Fuzz targets for every parser.
- Bounded-time adversarial corpus: zip bombs, nesting, pathological PDF and HTML.

**Benchmark harness** (`bench/`)
- Corpus manifests of hashes (B1 benign filesystem, B2 large files, M1 malware run isolated, A1 adversarial, S1 mail streams).
- clamd as the baseline, with identical limits and threads, bytecode on and off.
- Memory sampled from smaps_rollup or task_info at 10 Hz.
- CI gates:
  - Every PR: micro-kernels, 10% threshold.
  - Nightly macro run fails on any of: a 5% MB/s regression, private dirty over 24/64 MB, a reload delta over 2 MB, any new false positive, parity under 99.5%, an adversarial case over its bound.

## Phase 4 - Host protection and CVE automation (from linux-guardian, without its flaws)

**Findings model:** `{severity, category, title, description, remediation, cve, details}` with typed enums, a 0-100 score, fast and deep tiers, JSON output and severity exit codes.

**Server context:** findings are downgraded on servers when the server's role explains them. A suppression config turns checks off.

**Linux checks**
- They read `/proc`, `/sys` and netlink directly, never `ps`, `ss`, `find`, `lsmod` or `modinfo`.
- Malware on the host:
  - cryptominers: tokenised name, pool and stratum matches, plus deleted-exe and CPU checks
  - executables running from temp directories, and hidden processes (comparing `/proc` views)
  - fileless code (memfd), LD_PRELOAD and `/etc/ld.so.preload`
  - reverse shells, from `/proc/net` plus process fds
- Kernel and boot:
  - kernel modules: `/proc/modules` vs `/sys/module`, taint flags, signatures, parameters
  - eBPF programs and the bootloader
- Privileges: SUID/SGID changes and capabilities.
- Persistence and access: cron, at and systemd units; SSH (authorized_keys changes, auth-log brute force, sshd_config); credential exposure.
- Hardening: firewall, kernel sysctls, AppArmor/SELinux, disk encryption, container security, pending updates.
- Integrity: dpkg/rpm verify, and package-manager ownership instead of hard-coded allowlists.
- An inode/ctime/mtime/size cache so unchanged files are not hashed again.

**macOS checks:** LaunchAgents and LaunchDaemons, login items, unsigned binaries in user Library paths, quarantine xattr, TCC-relevant persistence.

**CVE automation (`cve/` → `.zavcve`)**
- Feeds: CISA KEV, NVD API 2.0 (incremental by lastModStartDate, optional key), OSV.
- Comparison uses canonical version tokens for each scheme: semver, dpkg, rpm, apk, PEP 440, Maven, Go.
- Inventory collectors:
  - packages: dpkg, rpm (sqlite), apk, Homebrew, pantry
  - lockfiles: npm/pnpm/bun, pip, Go buildinfo, Cargo
  - macOS `Info.plist`
  - service banners
- A KEV hit is critical.

## Phase 5 - Upstream improvements to our Zig libraries

- **zig-regex:**
  - a `bytes` compile mode (raw `\xHH`, `.` matches any byte, byte classes)
  - a matcher with caller-supplied scratch and no allocator
  - a configurable DFA state cap
  - a required-literal extraction API
  - serialisable compiled programs, so regexes can live in the blob
- **zig-waf:**
  - `phrase.zig` becomes binary-safe, with pattern IDs and output lists, a dense root table and relocatable serialisation
  - a C ABI `zig_waf_register_operator` so hosts can plug in `@inspectFile`
  - a Guardian `@inspectFile` operator
- **zig-xml:** an incremental / `Io.Reader` input mode.
- **zig-benchmarks:** port to the 0.17 std, and add external-process RSS/PSS/smaps sampling.
- **zig-mime (new):** a streaming MIME walker.
  - SIMD boundary search, a nested-multipart stack, streaming base64 and quoted-printable decoding.
  - Accepts bare-LF line endings, a known evasion the mail parser misses.
  - Reuses mail's ContentType and boundary validation.
  - mail then switches to it.
- **zig-cli / zig-config:** fix whatever the zav CLI runs into.
- **home-lang/lang compression:** an issue (and fix) noting that its zstd, brotli and lz4 are not the spec formats.
- **zig-sftp:** implement the write handler, then add a scan in CLOSE with staged temp-then-rename.

## Phase 6 - Framework (`stacksjs/stacks`) and the TS packages

**Binding package:** `@zig-utils/anti-virus`, with prebuilt libraries, the bun:ffi wrapper and the async completion-queue integration.

**`@stacksjs/malware`** (new core package `storage/framework/core/malware`)
- Drivers:
  - `guardian`: in-process FFI, or the zavd socket.
  - `clamd`: the protocol is shared, so this covers any clamd or zavd endpoint.
  - `none`.
- A new `config/malware.ts` overlays the defaults: driver, `failClosed`, limits, quarantine disk, which surfaces to scan.
- Types go in `core/types`. `scan(bytes | stream | path | fd)` returns a Result.
- A `quarantined_files` model, a quarantine disk, and restore and delete actions.
- A dashboard page.

**Hooks**, each with a test that uploads EICAR and expects it blocked and quarantined:
- **Storage:**
  - `storage/src/put-file.ts:233-249`: scan between `readBytes` and `disk.write`, controlled by a new `scan` field on `PutFileOptions`.
  - `uploaded-file.ts:77,95` (`store*`), plus a new `UploadedFile.scan()`.
  - `Storage.putStream` (`facade.ts:346`): a scanning tee.
  - Presigned uploads (`facade.ts:510,546`): stage under a quarantine prefix, then a scan job promotes the object.
- **File manager:**
  - a `scan` task kind in `file-metadata.ts:52,77`, `TASK_JOBS` at `file-manager.ts:987` and the `StorageItemTask` enum
  - a `ScanStorageFileJob`
- **Direct writes:** forms (`defaults/routes/forms.ts:82`), feedback (`FeedbackStoreAction.ts:51`), `UploadTestAction`.
- **Validation:** a `file().clean()` rule, plus wiring the unused `verifyUploadedMime` (`storage/src/mime-verify.ts:137`).
- **Inbound email:**
  - The SES Lambda (`buddy/src/commands/deploy.ts:6960`) honours `receipt.virusVerdict`.
  - `parseInboundEmail` scans attachments.
  - Fix the `scan || true` bug (`deploy.ts:7046`) and the enable-on-any-scan bug (`:6725`).
- **AI:** `ai/src/local-speech.ts:109` (multipart audio) and `image.ts:283` (fetched files).
- **Docs:** a `stacks-malware` skill, a docs page and a `stacks-native` catalog entry (`buddy docs:native-skills:check`). Then release.

**TS libraries**, each with its own issue and release:
- **ts-broadcasting:** an optional scan hook for binary message payloads (`server.ts:689`).
- **ts-sftp:** a scanning filesystem wrapper using `createFileSystem`, with staged temp-then-rename and a scan in `close()`.
- **ts-git-lfs:** scan in `storage.ts write()` after `verifyObject` (`:132`), with the verdict cached by oid.
- **ts-backups:**
  - Scan on restore (`restore/index.ts:146,204`).
  - **Fix the path traversal in `restoreDirectory` (`:197`)**: a tampered archive can write outside the target folder. This is a high-priority security fix.
- **ts-images:**
  - `detectFormat` (`codecs/index.ts:94`) also detects trailing data and polyglots (JPEG+ZIP, PNG+HTML).
  - An optional pre-decode scan, applied the same way to ts-heic, ts-avif and ts-videos.
- **rpx:**
  - A per-route `scan` option in the TS proxy (`proxy-handler.ts:57,528`).
  - The Zig dataplane uses zig-waf `@inspectFile`, and spools large or chunked bodies instead of skipping them.

## Phase 7 - Guardian app (`~/Code/Apps/guardian`, `stacksjs/guardian`)

**Models:** Scan, Detection, QuarantineItem, Host, Finding, CveExposure, SignatureFeed, Policy. Migrations are generated from them.

**API:** hosts (Stacks boxes and desktops) enrol with a token and report scans, findings and CVE exposure.

**Web dashboard** (stx + ts-css; design-taste skill and its pre-flight check)
- Pages: overview with fleet score, detections, quarantine, hosts, CVE exposure (KEV first), signature feeds, policies.
- The Guardian rule feed and CVE index are served from here (operator guide: [FEEDS.md](FEEDS.md)).

**Shared packages**
- `packages/core`: engine client, policy, report model, used by the CLI, the agent and the server.
- `packages/cli`: the `guardian` CLI, built with clapp like `~/Code/Apps/system-cleaner/packages/cli`, also exposed through `app/Commands/*.ts`.
  - Commands: `scan <path>`, `watch`, `host`, `audit` (CVE), `update`, `quarantine ls|restore|rm`, `daemon`, `status`, `enrol`.
  - Flags: `--json`, `--deep`, `--min-severity`. Exit codes follow severity.

## Phase 8 - Native macOS app (Craft AppKit)

- **Base:** SystemCleaner (`app/Desktop/{launcher,bundle}.ts`, `resources/views/app/tray.stx`, `scripts/build-desktop-app.ts`, `verify-tray.ts`). Entitlements and Full Disk Access follow Uplink (`app/Desktop/Entitlements*.plist`).
- **Tray popover:** protection status, last scan, Quick Scan, signature age, threats count.
- **Main window:** native sidebar with Overview, Scan, Real-time protection, Quarantine, Host checks, Vulnerabilities, Updates, Settings.
- **Agent:** a compiled Bun agent loads zav through FFI and runs FSEvents watching. Blocking real-time protection needs the Endpoint Security helper, which waits on Apple's entitlement.
- **Craft fixes:**
  - Downloads go to a `.part` file, get scanned, then are revealed with `com.apple.quarantine` set (`CraftMacWebView.swift:419-433`).
  - Fix any AppKit sidebar or tray gaps found here in craft and stx, and release them.
- **Verify:** `app_screenshot` of the built, signed window and tray.
- **Releases:** no public release or 1.0 without the maintainer approving that specific release.

## Phase 8b - zig-waf as Guardian's HTTP layer (`zig-utils/zig-waf`)

**What exists already**
- zig-waf (pre-alpha; 46 issues closed, 28 open) has:
  - a compiled `Waf` engine with per-request transactions and SecLang/CRS
  - the `zig-wafd` proxy and a C ABI
  - a PostgreSQL fleet controller with an OpenAPI `src/api-v1.json`
  - audit writers (JSON, OCSF, HTTPS, callback)
  - an unbuilt STX console (WAF-60 to WAF-70)
- ts-cloud `protection/waf.ts` already generates zig-waf configs (detection-only by default, with paranoia, thresholds and `WafRuleExclusion[]`).
- The rpx dataplane links zig-waf with `-Dwaf`.

What is missing:
- nothing reads the detection log
- nothing graduates a site to blocking
- uploads are not scanned at the edge
- the remaining roadmap is unfinished

**The split:** Guardian becomes one product with three engines:
- zav for files
- zig-waf for HTTP L7 content
- host and CVE audit

Each engine stays standalone. Guardian is the operator surface that ties them together.

**Graph rule:** the 28 open zig-waf issues join the graph as **existing nodes**. They are referenced, never duplicated. The outline accepts `=> zig-utils/zig-waf#61` in place of creating an issue. New zig-waf work becomes new issues in zig-waf.

**Engine-level integration**
1. **`@inspectFile` runs zav in process.** Both are Zig, so zav is a zon dependency of zig-waf behind a build option, and the Guardian operator is registered through `src/plugin.zig`.
   - Add `zig_waf_register_operator` to the C ABI so the rpx dataplane and connectors can plug in hosts.
   - A CRS-style rule `SecRule FILES_TMPNAMES "@inspectFile guardian"` scans uploads at the edge.
   - rpx spools large and chunked bodies (today they pass uninspected beyond 128 KB) so they get scanned too.
2. **One literal-matching engine.** zig-waf's `@pm`, `@pmFromFile` and phrase.zig, and zav's atom prefilter, both move onto a new `literals/` module in zig-regex:
   - Teddy for small sets.
   - A binary-safe Aho-Corasick with case folding, pattern IDs and relocatable serialisation.
   - The SBBF sampled prefilter.
   - zig-regex byte mode serves `@rx` on binary bodies as well as ClamAV PCRE.
   - zig-waf adopts this only if CRS FTW, ModSecurity and Coraza differential evidence stays identical and the benchmarks do not regress.
3. **Shared multipart and MIME parsing.** Evaluate moving zig-waf `multipart.zig` and the mail MIME walker into zig-mime. zig-waf adopts it only under the same rule: identical differential evidence, no benchmark regression.
4. **Shared benchmark lab.** WAF-05 and zav's `bench/` use the same external-process RSS/PSS sampler and regression gates in zig-benchmarks.

**Product-level integration**
1. **Detection to enforcement loop.**
   - zig-waf ships audit events (OCSF, through its HTTPS writer) to Guardian's ingest API.
   - Guardian shows live events, per-site anomaly-score distributions and false-positive candidates.
   - The exclusion wizard (WAF-64) writes `WafRuleExclusion` entries back into the app's ts-cloud/Stacks config as a reviewed change.
   - The operator flips a site from `detection` to `blocking` once the CRS compatibility gates (WAF-34 to WAF-37) are green. Nothing flips automatically, matching ts-cloud's stated policy.
2. **One Stacks config.** `config/security.ts` `firewall` drives AWS WAF on AWS deploys today. Add a `waf` section (mode, paranoia, thresholds, exclusions) that buddy passes to ts-cloud's zig-waf generator on box deploys. One config then drives both targets. First, check how far deploy wires this today.
3. **CVE virtual patching.** When the CVE audit finds a KEV or critical CVE in a web-facing package on a host, Guardian proposes a zig-waf virtual-patch ruleset (CRS rule or custom SecRule). It rolls out through zig-waf ruleset rollout and rollback (WAF-63), scoped to that host's sites.
4. **Correlation.** WAF anomalies plus upload detections plus host findings for the same source IP feed a per-host risk score. Repeat offenders can be pushed into ts-cloud's ddos/ratelimit blocklists.
5. **One fleet, federated.** zig-waf's fleet controller stays the authority for WAF nodes and rulesets.
   - WAF-49 (enrollment, mTLS, heartbeats, inventory) is built so the Guardian host agent enrols once, with one node identity covering zavd, zig-waf and host audit.
   - Guardian's server talks to the controller through a typed client generated from `api-v1.json`.
6. **One console codebase.** WAF-60 to WAF-70 are built as an stx component library in `zig-waf/console`:
   - design system, shell
   - fleet, rulesets
   - exclusion wizard, live events
   - audit search, metrics
   - playground, users/OIDC
   - UI tests

   It is consumed twice: embedded as fingerprinted static assets in standalone zig-wafd (as zig-waf intends), and imported by Guardian's dashboard and desktop app as the WAF section. There is one implementation of each screen.
7. **In-process option.** Apps not behind rpx (`buddy dev`, serverless) get an optional `@stacksjs/waf` router middleware over zig-waf's prebuilt C ABI through bun:ffi. It defaults to detection.

**Order of the remaining zig-waf roadmap within the graph**
1. Compatibility and benchmarks, because they gate blocking mode: WAF-05, then WAF-34 to WAF-37. WAF-27 (XML) comes after these.
2. The engine-level integration items above.
3. Fleet and console: WAF-49 and WAF-60 to WAF-70, built together with Guardian Phases 7 and 8.
4. The proxy: zig-wafd HTTP/2 and routing (WAF-41, WAF-43).
5. Connectors (WAF-44 to WAF-47): Nginx, Caddy, Envoy, HAProxy. Stacks does not use them, but they are on zig-waf's v1 roadmap.
6. Packaging, docs and qualification (WAF-71 to WAF-73) last.
7. Blocking mode in ts-cloud defaults stays off until WAF-73's qualification passes.

## Phase 9 - Ecosystem rollout

- **ts-cloud:**
  - A `guardian` service: zavd as a systemd unit with a small `MemoryMax`, and a socket shared with the box's tenants.
  - The commitment report counts zavd. Remove the clamav assumptions.
- **mail-os/mail:**
  - `clamav.zig` gains Unix socket support and fail-closed mode.
  - Scans go into `Session.handleData` (between spam scoring at 1877-1908 and `saveMessage` at 1912), BDAT (1991, 2066, 2275), IMAP APPEND (`imap.zig:4138`), ActiveSync SendMail (`activesync.zig:470`), CalDAV PUT (`caldav.zig:1095`) and webmail upload (`webmail_http.zig:853`).
  - Switch to zig-mime.
  - Ship when `zig build test`, test-rfc, test-fuzz and test-e2e pass. A push deploys.
- **pantry-pm/pantry:**
  - The registry deploy moves to zavd and drops the clamav blocks (`deploy-registry.yml:143-394`); `ClamAvScanner` stays as it is.
  - The client scans after `verifyIntegrity` and before extraction (`installer.zig:1433`, `pipeline.zig:1236,1747`, `verified_staging.zig:32`), with the verdict cached alongside the sha256.
- **App repos:**
  - browser: scan finished downloads through the Craft hook plus the agent's `record()`.
  - attic: `archiver.ts:174`, `whatsapp-link.ts:982`.
  - reviewos:
    - add a malware pass to the pre-receive gate (`app/Actions/Git/scan.ts:105`), which today scans for secrets and skips binaries
    - LFS (`Git/lfs.ts:110`), attachments (`Attachment/upload.ts:100`), release assets (`Release/assets.ts:197`), CI artifacts (`Artifact/store.ts:110`), mirror and import
  - bughq: symbol uploads.
  - postline: media.
  - These apps get most of it from the framework hook once they upgrade. Each one's issue checks the paths that don't go through `Storage.put`.
- **After each cutover:** watch the deploy and confirm on the live services that an EICAR publish is refused and EICAR mail is rejected.

## Verification

- **Engine:**
  - `zig build test`, the fuzz runs and EICAR detection, plain and zipped.
  - The full ClamAV database compiles. The coverage report is committed.
  - E9 parity of at least 99.5% with no new false positives.
  - The nightly memory and throughput gates are green. The README shows numbers side by side with clamd.
- **Daemon:** pantry-registry's malware tests and mail's clamav tests pass against zavd unchanged. `clamdscan --stream` works against zavd.
- **Framework:** each hook's EICAR test; `./buddy lint`; `bun run typecheck`; the whole `core/buddy` suite before the release.
- **TS libraries:** each repo's suite, plus a new EICAR test for each hook.
- **App:**
  - `./buddy test`, `typecheck` and `lint`.
  - `guardian scan` against fixtures (exit codes, JSON); `guardian host` on a Linux box.
  - Dashboard checked in the browser pane.
  - The built macOS app screenshotted (tray and window), and an EICAR file dropped in a watched folder is caught live.
- **zig-waf:**
  - Its CI and evidence stay green: CRS FTW, ModSecurity and Coraza differential tests, and the benchmarks.
  - An EICAR multipart upload through the rpx dataplane with `-Dwaf` is blocked by `@inspectFile`.
  - zig-waf detection events appear in Guardian.
  - The exclusion wizard writes a valid `WafRuleExclusion` that ts-cloud accepts.
  - The console component library renders both embedded in zig-wafd and inside Guardian.
- **Issues:** `sync-ready` flips dependents after each close. Every closed issue has a decision comment.
