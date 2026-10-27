# Snowstead Go build cache

An isolated Go prototype: a Cloudflare Worker, private R2 storage, Cloudflare's
edge Cache API, and the native Go `GOCACHEPROG` helper in `apps/go-cache`.
It does not change Nix, require Postgres, or run builds remotely. Organization,
dashboard, tier, and per-user credential integration are not implemented here.
One deployment is one trusted cache, not a multi-tenant endpoint.

## Correctness and trust

Go calculates action IDs from its build inputs. Snowstead never invents compiler
cache keys or bypasses Go's normal decisions about what is cacheable. Both R2
on upload and the helper on download validate SHA-256 against Go's output ID.
Local files are validated too. This detects corruption, **not malicious builds
from an authorized writer**: anyone with the write credential can seed new
action IDs with attacker-chosen, correctly hashed content.

- Give `WRITE_TOKEN` only to trusted CI jobs building reviewed code. Never
  expose it to fork PRs, untrusted build scripts, or developer workstations.
  Give those builds `READ_TOKEN` and set the helper's read-only policy.
- Go compilation and build scripts can read their process environment. Merely
  hiding a token from the shell output is not a security boundary. Separate the
  actual jobs and their credential permissions.
- Separate projects/trust domains by Worker deployment, credentials, namespace,
  and ideally bucket. Sharing one writer across projects shares their trust.
- R2 writes are conditional create-only operations. Different outputs for an
  existing action get 409, including concurrent uploads. A writer cannot replace
  a published result. This is first-writer-wins, **not protection from a stolen
  writer credential populating new keys first**.
- R2 is private, without an R2 custom domain or r2.dev endpoint. Do not bind this
  Worker to the Nix public bucket. Authentication precedes every edge cache
  lookup, so a warm object never authorizes an unauthenticated reader.
- The helper requires HTTPS except on loopback and refuses redirects. Local
  helper caches are isolated by endpoint, credential, and read-only policy.
- On writer compromise, rotate both credentials and `CACHE_NAMESPACE`, and
  clear client caches before reuse. Rotating only the write token does not
  remove previously poisoned entries. Use a new endpoint or clean helper cache
  when changing the remote trust domain.

This prototype has deployment-level secrets, not individual token revocation
or attestations. It assumes that the Worker configuration and Cloudflare account
are trusted. No production organization authorization is inherited from Nix.

## CDN and retention

After authentication, GET looks in the Cloudflare edge Cache API, then private
R2. A successful origin response is cached for at most one hour and never past
its retention deadline. Namespace and retention policy are in the internal
cache key. Query strings cannot select another object or bypass that key.
Responses to clients use `Cache-Control: no-store` and
`Cloudflare-CDN-Cache-Control: no-store`: a public outer CDN must not skip auth.
`X-Snowstead-Cache: HIT` identifies an authenticated edge-cache hit.

**The Cache API is per data center and does not use tiered caching.** This is
deliberate for the private prototype; neither public R2 URLs nor long-lived
signed download URLs bypass its gate. Live regional hit rates and WAN latency
must be measured, not inferred from local workerd tests. Tiered private delivery
would be a separate authenticated origin design, not a configuration toggle.

Retention is seven days from initial upload by default; duplicate writes do not
extend it. The Worker refuses expired objects even before physical deletion.
Configure an R2 lifecycle rule to remove `go/` objects after seven days. Lifecycle
deletion is asynchronous, so expired entries can temporarily reject a conflicting
replacement until R2 deletes them. Local caches are independent and have no
automatic eviction. The server caps an artifact at 64 MiB and applies a Worker
request rate limit; it does **not** enforce an overall byte quota. Treat bucket
usage alerts and lifecycle configuration as deployment prerequisites.

## Run locally

From the repository root:

```sh
nix develop
pnpm install --frozen-lockfile
pnpm --filter @snowstead/go-cache-worker dev -- \
  --var READ_TOKEN:local-reader --var WRITE_TOKEN:local-writer
```

Build and configure the helper as described in `apps/go-cache/README.md`. Use
`http://127.0.0.1:8787` as its URL and one of these local-only tokens.

## Local HTTP load and memory checks

From the repository root:

```sh
nix develop --command node scripts/go-cache-load.mjs > /tmp/go-cache-load.jsonl 2> /tmp/go-cache-load.log
nix develop --command pnpm --filter @snowstead/go-cache-worker check
```

The load script bundles this Worker and starts a disposable Miniflare/workerd
server, Cache API, and R2 emulator on loopback. It never deploys, uses cloud
credentials, or connects to a running cache. Only this test server omits the
rate-limit binding, so results measure successful cache work rather than 429s.
`GO_CACHE_WORKER_SOURCE` can select a saved source file for baseline comparisons.

It validates SHA-256 of every completed download, output headers, and private
response headers. It runs three warm passes for 1 KiB and 1 MiB artifacts at
concurrency 12, and 16 MiB and 64 MiB artifacts at concurrency 4. Separate phases
cover cold reads, four cold readers paused for two seconds, cancelled downloads
and subsequent complete reads, mixed uploads/downloads, warm authentication
denials, duplicate/conflicting upload races, and corrupted writes. Errors are
excluded from throughput and fail the run. Authentication controls and deliberate
cancellations are separate rows, not artifact-throughput results. Mixed rows
count upload/download pairs; race rows count complete four-writer races plus
corruption and readback checks. Latencies include the entire operation, and
`verifiedMiBPerSecond` counts downloaded, verified bytes, not upload bytes.

JSON lines contain per-phase throughput, p50/p95 latency, errors, and hits, then
raw memory samples. On Linux the script samples its own workerd child process's
RSS every 100 ms and reports Node RSS separately. Workerd RSS includes the local
R2/Cache API emulators and runtime overhead, **not just the application isolate's
heap**; Node RSS includes both Miniflare and the load generator. Neither is a
measurement of the deployed Worker's 128 MiB isolate budget. Sampling can miss
brief allocation peaks. Use the median warm pass, repeat complete runs, and do
not infer WAN performance, regional hit rates, or production RAM from loopback.

For a separate memory-profile run, set `GO_CACHE_INSPECT_HEAP=1`. This enables a
loopback inspector and samples `Runtime.getHeapUsage` for the application isolate
alongside RSS. `applicationHeapBytes` distinguishes V8 used/allocated heap,
embedder heap, and backing storage from the much larger emulator process. These
are sampled local figures, not a guarantee about all native allocations or the
deployed memory limit. Inspector sampling changes timing, so do not compare its
throughput against an unprofiled run.

## Terraform acceptance gate

```sh
nix develop
GOTOOLCHAIN=go1.24.5 scripts/go-cache-terraform.sh
```

The gate pins Terraform v1.13.5 to commit
`328813676aec7a4e2a491484f91b5e0b67847b6c`, starts a disposable local Worker/R2
store, and runs four builds: uncached, trusted-writer population, remote
read-only reuse, and a build with changed compiler flags. Both Go's cache and
the helper's cache are empty before each build. Module downloads happen before
timing. The gate requires successful
uploads, remote hits, zero Go compiler invocations on the remote build, and
byte-identical runnable binaries for unchanged inputs. Changed compiler flags
must invoke the compiler and produce a different runnable binary. It retains
logs and cleans up its processes and temporary storage. `GO_CACHE_PROOF_DIR`
selects the retained log directory;
`TERRAFORM_SOURCE` can name an existing clean checkout at the pinned commit.

Set `GO_CACHE_BENCHMARK=true` to record GNU time wall seconds and maximum RSS
and run three additional samples each of cold uncached builds, empty-client
remote reuse, and warm-local reuse. Each repeated binary must match the baseline.
`GO_CACHE_HELPER` can select an already-built helper for comparisons. Helper RSS
is measured separately: whole-build maximum RSS generally belongs to the Go
compiler or linker, not the cache helper, and is not aggregate process-tree RAM.
Run without other CPU-heavy work, compare medians, and keep the Worker and
toolchain fixed when attributing changes to the helper.

This is a **local full-stack gate**, not proof of deployed Cloudflare behavior
or WAN speed. A live gate must run the same clean-client scenario over
HTTPS, confirm authenticated edge hits, test denials after warming, and verify
that no R2 public endpoint exists. Do not claim a speedup from a single run.

## Cloud deployment prerequisites

Provisioning and deployment change shared infrastructure and incur usage;
obtain approval before executing them. Use an isolated staging Worker, private
bucket, secrets, and hostname, not the Nix production infrastructure.

1. Set a unique Worker name, bucket name, and namespace in this directory's
   `wrangler.jsonc`. Add the staging custom-domain route. Workers.dev and preview
   URLs are disabled intentionally.
2. Create the private bucket. Verify public access is disabled. Add a lifecycle
   rule with `pnpm exec wrangler r2 bucket lifecycle add <bucket> go-retention go/
   --expire-days 7` and verify it with `lifecycle list`.
3. Configure distinct, randomly generated, 32-byte-or-longer `READ_TOKEN` and
   `WRITE_TOKEN` Worker secrets using Wrangler. Never commit them or put them
   in command-line flags for a deployed service.
4. Deploy explicitly from `workers/go-cache` so the existing root Nix config
   cannot be selected accidentally. Run the live Terraform gate and security
   checks before sharing credentials. Inspect R2 usage and Worker rate limits.

No cloud resources are created by checks or the local Terraform gate.
