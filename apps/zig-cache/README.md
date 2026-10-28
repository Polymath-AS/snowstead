# Stock Zig snapshot spike

This is **whole-cache restore/build/save**, not transparent per-action caching.
The client invokes the normal, unmodified `zig build`; it does not replace Zig's
maker/configurer, patch the compiler, manufacture native action IDs, or skip
Zig's input validation. It owns fresh disposable local AND global cache roots
for every invocation. Nothing reads or writes your usual caches.

## Supported scope

Only stock Zig **0.17.0, x86_64 Linux**, reviewed nonincremental builds with
pre-resolved dependencies, and an explicitly inventoried external environment.
The real-project gate builds ZLS 0.17.0, commit
`542462c4ddf045493fa9ca028ee6bc3f38b2754a`.

The official [download index](https://ziglang.org/download/index.json), refreshed
October 28, 2026, lists stable 0.17.0 and master 0.18.0-dev.738+ae9a8acc7.
The harness pins the official Linux distribution to SHA-256
`1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026`.
The upstream source archive used for the layout audit is
`https://ziglang.org/download/0.17.0/zig-0.17.0.tar.xz`, SHA-256
`b6c7f1728f043700d6529bac980800792f824256a9d2f1839b3d62beed0b8abd`.
Current upstream development is on Codeberg, not GitHub master. No claim is made
about compatibility with master, older releases, another host, or another cache
format. Download checksums are a trust-on-official-HTTPS pin, not attestations.

The SHA-256 snapshot selection key includes:

- Format and project/trust namespace.
- The content and file modes of the entire compiler distribution (not just its
  version string), host OS/architecture, CPU model, ISA flags, and stock `zig env`
  native target (including detected kernel/libc versions).
- The content, paths, and modes of the **entire source/dependency tree**, excluding
  only root `.git/`, `.zig-cache/`, and `zig-out/`. Symlinks and special files are
  rejected. Do not put build inputs in these excluded output directories.
- The exact build arguments, including target and options.
- Canonical absolute checkout, toolchain, and scratch paths. These must match
  across CI jobs for snapshot reuse.
- The complete contents of a required caller-maintained context file identifying
  all external tools, SDKs, relevant environment, files outside the tree, and
  network-derived inputs. Include content hashes, not only paths or labels.
  If a build consumes Git metadata, inventory that state too: `.git/` is
  deliberately excluded from the source hash.

This intentionally gives up reuse across source **and layout** changes. It is a
safe small starting point for repeat CI checkouts, **not** a substitute for a hermetic build
system. Hashing source contents prevents same-size/same-mtime changes from
selecting an old snapshot even if native metadata checks would skip hashing.
No downloaded manifest metadata is rewritten to local inode/mtime values.
Zig still decides which restored entries it can use; a successful remote restore
does not imply a compiler hit. Stock serialized configurations and generated
inputs contain absolute paths. The client conservatively fences all three roots
in the compatibility key. Relocation therefore causes an explicit remote miss
and a normal clean build. There is no cross-path portability claim.

Arbitrary Zig build scripts can inspect undeclared tools, environment, filesystem,
time, or network inputs. There is no automatic safe general solution for those.
Only use this spike after reviewing the build graph and input inventory. Do not
use it if a build overrides `-fno-incremental`, writes shared caches, changes
source files during compilation, or consumes undeclared mutable inputs. The
client checks source contents again before save, but this is not filesystem
isolation or protection against racing source changes. The checkout, compiler,
and context must remain immutable for the entire operation.

## Layout and publication contract

The audited 0.17 implementation is `src/Compilation.zig` (cache modes and artifact
directories), `lib/std/Build/Cache.zig` (`Manifest.checkProgressless`, metadata
validation, and `isProblematicTimestamp`), `src/Module.zig`/`src/Builtin.zig`
(option-keyed builtin generation), and `lib/compiler/Maker.zig` (normal
build orchestration and atomic configuration publication). Incremental artifacts
also use `o/`; their names alone cannot distinguish them. The client forces
`-fno-incremental`, and the supported reviewed build must honor it.

Only completed `local/o/**`, `global/o/**`, 32-lowercase-hex manifest files
directly under each `h/`, serialized `local/c/<32 hex>` configurations, and
`global/b/<32 hex>/builtin.zig` are saved after `zig build` succeeds and exits.
The latter two are completed, keyed outputs, not mutable incremental compiler
state. They must accompany their manifests: omitting them caused real misses
in the initial experiment. It does not save `h/timestamp` (mutable filesystem
clock state), ZIR `z/`, temp files, active locks, package download `p/`, or other
maker state. Outputs and manifests have different native keys; the archive is
the publication unit, not either native ID.

Empty `tmp/` directories are created before invoking Zig; no temp contents are
restored. An initial incomplete restore failed with `configuration failed:
FileNotFound` when a recreated checkout required reconfiguration: stock Maker
can reuse the configurer executable and then create `tmp/<random>` without
creating its parent. The recreated-checkout regression gate covers this case.

The client streams a gzip/tar snapshot to a private spool file while computing
SHA-256. Downloads are bounded to 96 MiB compressed and verified completely
before parsing. Extraction permits only regular files under the allowed roots,
rejects traversal, links, duplicates, devices, unexpected trailing data, and
expansion beyond 1 GiB or 100,000 files. Modes are masked; ownership, timestamps,
and xattrs are not applied. Full verified outputs and manifests are published
together via one same-filesystem directory rename into the fresh session.
Concurrent invocations have separate sessions. It never snapshots an active
shared root. Temp sessions are removed on ordinary completion/error; SIGKILL or
machine failure can leave disposable temp directories for the runner to clean.

SHA-256 authenticates bytes to the authenticated HTTPS service's stored digest;
it is **not** a writer signature. Native Zig SipHash IDs are not cryptographic
integrity hashes. A malicious authorized writer can upload a correctly hashed
poisoned archive. Only reviewed CI gets write credentials. Separate deployments,
buckets, namespaces, and credentials define separate trust domains. Rotate both
credentials and the server/client namespaces after compromise; immutability is
first-writer-wins, not protection from a writer stealing a new key first.

Snapshots can contain generated sources, embedded data, source paths, and
executables, not merely objects. Private source builds require private reads.
**Do not run untrusted build scripts with production credentials**, even read
credentials. The client strips its transfer tokens from the child environment,
but same-user scripts can inspect their parent; this is hygiene, not a sandbox.
Use a separate low-privilege job/container for untrusted builds.

## Use

```sh
nix develop
pnpm install --frozen-lockfile
(cd apps/zig-cache && go build -o /tmp/snowstead-zig .)

# Resolve dependencies first, and inventory external inputs in a file outside
# the project. Use the pinned official distribution, not a system Zig shim.
export SNOWSTEAD_ZIG_READ_TOKEN='...'
/tmp/snowstead-zig -project /ci/project \
  -toolchain /opt/zig-x86_64-linux-0.17.0 \
  -context /ci/verified-external-inputs.json -trust project-reviewed-v1 \
  -scratch /ci/disposable-zig-session \
  -url https://dedicated-snapshot.example -- -Doptimize=ReleaseFast --summary all

# Trusted CI only: add -save BEFORE -- and provide a separate WRITE_TOKEN.
```

Use stable checkout/toolchain paths and the required `-scratch` path for CI reuse.
The scratch path **must not exist**: the client creates it exclusively, refuses
an existing directory without deleting its contents, and removes only the
session it created. A concurrent invocation with that same path fails rather
than operating on an active root. It must be outside the project/toolchain.
Different scratch paths select different remote keys. Neither checkout nor
scratch paths are rewritten in manifests.

The default is read-only. The client accepts HTTPS origins, or loopback HTTP for
disposable tests, and refuses redirects. Restore misses, auth errors, corruption,
and unavailable service all fall back to a normal clean build. Failed builds are
never saved. Network failure on save does not fail an otherwise successful build;
explicit rejected saves (including immutable 409 conflicts) are reported as
errors. A verified restored snapshot is not re-uploaded, even with `-save`.
Concurrent cold writers can produce different manifest metadata and therefore
conflict; identical snapshot bytes yield 204. There is no mutable "latest" pointer
or silent overwrite. Use a new trusted snapshot namespace to repopulate.

## Reproduce the gate

```sh
nix develop --command node scripts/zig-cache-benchmark.mjs
nix develop --command pnpm check
```

The harness verifies pinned downloads, prefetches dependencies outside timing,
starts its own loopback workerd/R2/Cache API emulator, builds the client, and runs
cold-save, three empty-root restores, a recreated checkout at the same path,
relocated-checkout, different-cache-layout, changed options/target,
source/import, external-context, and offline builds. A final ZLS build adds a
small compile-time embedFile guard, saves successfully, changes only the embedded
file, and requires the real compiler to fail without uploading any objects.
An existing scratch directory must remain untouched. Every run uses entirely
fresh local and global roots; installed outputs are removed too. Logs, SHA-256s,
transfer bytes, build summaries, wall seconds, and Linux peak RSS are retained
under `.amp/in/artifacts/zig-snapshot/`; processes and scratch data are removed.
The client RSS excludes compiler children. GNU time maximum RSS is the largest
process contribution, **not aggregate process-tree RAM**. Loopback measurements
are not WAN/deployed performance; do not infer a production speedup from them.

Contract tests cover authenticated warm-cache reads, public read-only access,
denied reader writes, conditional upload conflicts, SHA-256 corruption,
separate protocol paths, unsafe archives, mutable-state exclusion, atomic failed
restore, concurrent isolated restores, same-metadata source mutations, and key
separation for toolchains, hosts, targets/options, trust, external context, and
absolute layouts. Other compiler distributions are not built in the gate.

### Measured on October 28, 2026

ZLS 0.17.0 ReleaseFast, stock Zig 0.17.0, AMD Ryzen 9 9900X3D, Linux 7.2.6,
native GNU libc 2.42. This is a local fixed-path CI model on a shared development
host, with other validation running concurrently, **not hosted CI or WAN data**.
Dependency prefetch is excluded; each measured invocation includes input hashing,
transfer, extraction, normal Zig build, and save where requested.

| Case | Wall seconds | Zig build seconds | Transferred bytes | Client peak RSS KiB | Largest process RSS KiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Cold build + save | 113.01 | 110.174 | 31,789,175 up | 13,616 | 2,004,468 |
| Empty roots restore 1 | 0.78 | 0.120 | 31,789,175 down | 13,880 | 41,408 |
| Empty roots restore 2 | 0.79 | 0.122 | 31,789,175 down | 14,212 | 41,408 |
| Empty roots restore 3 | 0.77 | 0.123 | 31,789,175 down | 14,352 | 41,408 |
| Recreated checkout, same path | 0.81 | 0.144 | 31,789,175 down | 14,032 | 41,408 |
| Relocated checkout (miss) | 110.90 | 110.590 | 0 | 13,872 | 1,983,436 |

Each restore reports six cached compiler/options steps, and installs an executable
byte-identical to the cold build, SHA-256
`e45ebfe263ebba6e255f6df6ffb526205655f8edb72708ad9943bafb52c30528`.
Code generators still run: this is not a promise that every build step is cached.
Raw logs and per-case JSON for this run are in the ignored
`.amp/in/artifacts/zig-gate/` directory.

Different scratch layout, strip options, musl/baseline target, source/import, and
external-context changes all restored zero bytes and performed clean builds
(90.17–110.98 seconds). Offline fallback completed in 107.09 seconds with zero
cached steps or transfers. The embedFile control first saved 31,778,437 bytes,
then changing only its four-byte input caused the expected real compiler error,
installed no executable, and uploaded zero objects. Occupied scratch contents
were preserved. A restored `-save` invocation succeeded without re-uploading.

Separate clean builds were **not bit-reproducible** in the initial gate: the
online-404 and offline cases selected the same key
`3ec76024aaeb5f0591a1a2f87d5cc8cf730aeaef652ef60cd9e294a1ec2b984e`
but produced different executable hashes. Both ran stock builds with empty roots
and reported version 0.17.0. The upstream/compiler or generator cause is not
diagnosed. The offline gate therefore checks successful normal execution,
expected version, zero restores/uploads, and zero cached steps, and records both
clean-build hashes rather than asserting a reproducibility contract. The strict
cold-versus-restored binary equality checks remain. This spike does not promise
bit-reproducible clean builds.

## Separate service boundary

`workers/zig-cache` is an isolated Worker prototype, like the earlier standalone
Go spike, **not** the hosted Go protocol in `workers/go`. It has its own
`/v1/snapshots/:sha256-compatibility-key` route and dedicated private R2 binding.
No Go action endpoint, hosted token permission, Nix storage, database schema,
gateway route, management API, or website is changed. Hosted organization
integration needs separately designed Zig scopes, quotas, reset, and GC before
this could join the production gateway. No existing scope silently grants Zig.

All PUTs require the trusted deployment writer. Private GET/HEAD require either
deployment token **before every Cache API lookup**. `PUBLIC_READ=true` explicitly
permits anonymous reads, not writes; visibility participates in the internal
cache key. Client responses are always no-store, including errors, so an outer
CDN must not bypass the authorization gate. R2 verifies streaming upload length
and SHA-256 and uses conditional create-only writes. Cache misses populate the
Cache API sequentially, without cloning/teeing a full snapshot into a potentially
unbounded slow-reader buffer, then stream a fresh read. This trades cold-read
latency for low application memory. Cache API failures fall back to R2.

R2 objects logically expire seven days after initial publication; duplicates do
not refresh retention. The Cache API is per data center, not tiered. Physical
cleanup requires a dedicated `zig/` lifecycle rule. There is no org byte quota,
per-user revocation, rate limiter, multipart upload, signed attestation, or hosted
administration in this spike. Before any deployment, obtain separate authority
to provision an isolated private bucket/hostname/secrets/lifecycle, verify no
public R2 bypass, configure rate/cost controls, and test over real HTTPS. The
checked-in names do not provision resources; workers.dev and previews are off.
No deployment or shared infrastructure change is part of the benchmark.

Cloudflare API design references (checked October 28, 2026):
[R2 streaming/checksum/conditional API](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/)
and [Cache API](https://developers.cloudflare.com/workers/runtime-apis/cache/).
