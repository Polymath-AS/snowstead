# Go remote build cache

Build with Go 1.24 or later:

```sh
go build -o snowstead-go-cache .
export GOCACHEPROG="$(pwd)/snowstead-go-cache"
export SNOWSTEAD_GO_CACHE_URL=https://your-go-cache-endpoint
export SNOWSTEAD_GO_CACHE_TOKEN=your-bearer-token
go build -trimpath ./...
```

Use consistent toolchains and build flags across machines. `-trimpath` avoids
embedding machine-specific source paths and improves cross-checkout reuse;
the helper does not change your compiler flags or Go's action IDs.

The executable takes no subcommand. It speaks the official Go GOCACHEPROG
JSON protocol on stdin/stdout, including the separate base64 body value after
nonempty puts. Stderr contains a machine-readable summary on close or EOF.

`SNOWSTEAD_GO_CACHE_DIR` selects the persistent local cache root (default:
`os.UserCacheDir()/snowstead-go-cache`). A SHA-256 subdirectory isolates each
endpoint, credential, and read-only policy, including when the root is explicit.
Set `SNOWSTEAD_GO_CACHE_READ_ONLY=true` to disable remote uploads; local puts
remain available. Protect this directory as you would Go's normal build cache.
There is no automatic eviction; do not delete its files while builds are running.

Remote requests require HTTPS, except HTTP on localhost or a loopback IP.
For public reads, explicitly set `SNOWSTEAD_GO_CACHE_READ_ONLY=true` and leave
`SNOWSTEAD_GO_CACHE_TOKEN` unset. Writes always require a nonempty token. The
standalone prototype still requires a token on reads; anonymous access is for
public named caches in the main service. Invalid/missing remote configuration
disables remote access. Redirects are never followed. Credentials, when present,
use bearer authentication. Requests stop after five seconds without body-stream
progress; response headers also have a five-second deadline. Healthy transfers
may take longer than five seconds. There is also a 69-second absolute request
limit: five seconds plus the 64 MiB maximum artifact at 1 MiB/s. This bounds
trickling peers without imposing the old five-second whole-body cutoff on large
artifacts. The observed 23,345,386-byte Kubernetes artifact crossed that cutoff
while still transferring data. Progress is tracked per request, including when
HTTP/2 multiplexes requests on one connection. Remote errors, misses, invalid
headers, oversized downloads, and digest mismatches are cache misses, not build
failures. Puts are published locally before uploading; failed uploads never
prevent local reuse.
The first network failure (including a download-body timeout), HTTP 401, 403,
429, or 5xx disables remote reads and writes for the rest of that helper process.
Already-started requests can finish or time out; later requests use local data
or miss immediately. A new helper process retries the remote. HTTP 404 and 409
do not disable it. Invalid artifacts are never served. Local filesystem errors
on put are reported to Go.

The stderr summary includes `read_errors`, `read_timeouts`, and `remote_disabled`.
Read errors count failed remote attempts, including invalid responses, digest or
size mismatches, and download persistence failures; timeouts are a subset.
Expected HTTP 404 misses, local-only misses, and requests skipped after the
circuit breaker opens do not increment these error counters. `remote_disabled`
reports whether that circuit breaker opened during this helper process. Upload
errors remain separate: `upload_errors=0` does not imply successful downloads.

GET and PUT use `/v1/actions/<lowercase hex action ID>` relative to the endpoint
base. Remote artifacts are limited to 64 MiB; larger Go puts remain local-only.
Downloads require Content-Length and a matching SHA-256 X-Snowstead-Output-ID.
Local blobs are also verified before serving. Files and action records are
atomically renamed into place; returned absolute paths remain on disk after
close. Up to 16 requests run concurrently and responses may arrive out of order,
matched by request ID. Put bodies are decoded serially, with backpressure before
decoding. Base64 bodies and remote downloads stream through bounded buffers to
temporary files while hashing; uploads stream from verified local files. Neither
large local-only puts nor concurrent downloads buffer entire artifacts in RAM.
The protocol reader uses a 64 KiB buffer. This is not an RSS cap: the Go runtime,
HTTP transport, and filesystem bookkeeping also consume memory. Local hits are
hashed with streaming reads.
Close and EOF drain all pending work before the summary; close responds last.
No background uploads are lost at close. There is no automatic eviction.

Run `go test ./...` and `go test -race ./...` in this directory.

From the repository root, build the helper and run
`node scripts/go-cache-helper-bench.mjs /absolute/path/to/snowstead-go-cache`
inside `nix develop`. This exercises the public protocol against a synthetic
loopback HTTP origin, verifies bytes and digests, and samples helper peak RSS
on Linux. Defaults are three repetitions of 32 GETs and PUTs per 1 and 16 MiB
artifact; `BENCH_REPEATS`, `BENCH_REQUESTS`, and comma-separated `BENCH_MIB`
override the workload. It is not a Worker or WAN benchmark. For real Terraform
builds against local workerd/R2, use `scripts/go-cache-terraform.sh` as documented
in `workers/go-cache/README.md`.
