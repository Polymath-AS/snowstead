import { mkdtemp, rm } from "node:fs/promises";
import { availableParallelism, tmpdir } from "node:os";
import { join } from "node:path";
import type { ApiClient } from "./api.js";
import {
  getMissingPaths,
  createUploadSessions,
  commitUploads,
  uploadBlob,
  shouldUseMultipart,
  uploadPresigned,
  uploadBlobMultipart,
  completeUpload,
} from "./api.js";
import { batcher, limiter } from "./batch.js";
import { getPathInfos, dumpAndCompress } from "./nix.js";
import type { PathInfo } from "./nix.js";
import { runPool } from "./pool.js";

// Paths in flight at once. Most are small, so a push waits on round trips
// far more than on bandwidth; compression has its own, CPU-sized limit.
const DEFAULT_CONCURRENCY = 32;
// The server takes up to 100 per batch; a batch goes once it is full or
// once its first path has waited BATCH_DELAY_MS.
const BATCH_SIZE = 100;
const BATCH_DELAY_MS = 50;

export interface PushResult {
  readonly pushed: number;
  readonly skipped: number;
  readonly failed: number;
  readonly errors: string[];
}

interface PushOptions {
  readonly concurrency?: number;
  readonly onProgress?: (current: number, total: number, name: string, status: string) => void;
}

/**
 * Pushes one path: its session and its publish join those of the other
 * paths in flight, so a push makes two API requests per batch of paths
 * rather than several per path.
 */
function pathPusher(client: ApiClient, cache: string) {
  const compress = limiter(availableParallelism());
  const createSession = batcher(BATCH_SIZE, BATCH_DELAY_MS, (paths: Parameters<typeof createUploadSessions>[2][number][]) =>
    createUploadSessions(client, cache, paths),
  );
  const commit = batcher(BATCH_SIZE, BATCH_DELAY_MS, (ids: string[]) => commitUploads(client, ids));

  return async (storePath: string, info: PathInfo): Promise<{ sizeKb: number }> => {
    const narDir = await mkdtemp(join(tmpdir(), "helios-nar-"));
    const narFile = join(narDir, "nar.zst");

    try {
      // Hash and size are computed while the compressed NAR is written,
      // avoiding a second full read of the file.
      const { fileHash, fileSize } = await compress(() => dumpAndCompress(storePath, narFile));

      const session = await createSession({
        storePath: info.storePath,
        storePathHash: info.storePathHash,
        narHash: info.narHash,
        narSize: info.narSize,
        fileHash,
        fileSize,
        compression: "zstd",
        references: info.references,
      });

      if (session.uploadMethod === "presigned" && session.uploadUrl) {
        // Straight to R2; the API never handles the NAR.
        await uploadPresigned(session.uploadUrl, session.uploadHeaders ?? {}, narFile);
      } else if (shouldUseMultipart(fileSize)) {
        await uploadBlobMultipart(client, session.sessionId, narFile);
        // A commit takes multipart sessions only once completed.
        await completeUpload(client, session.sessionId);
      } else {
        await uploadBlob(client, session.sessionId, narFile);
      }

      const result = await commit(session.sessionId);
      if (!result.published) {
        throw new Error(`publish failed (${String(result.status)}): ${result.error ?? "unknown error"}`);
      }

      return { sizeKb: Math.round(fileSize / 1024) };
    } finally {
      await rm(narDir, { recursive: true, force: true });
    }
  };
}

export async function pushPaths(
  client: ApiClient,
  cache: string,
  storePaths: string[],
  options?: PushOptions,
): Promise<PushResult> {
  const concurrency = options?.concurrency ?? DEFAULT_CONCURRENCY;
  const onProgress = options?.onProgress;

  const hashToPath = new Map<string, string>();
  const hashes: string[] = [];
  for (const p of storePaths) {
    const basename = p.split("/").pop();
    if (!basename) continue;
    const hash = basename.split("-")[0];
    hashToPath.set(hash, p);
    hashes.push(hash);
  }

  // Check missing in sequential batches of the server's maximum size
  const missingSet = new Set<string>();
  for (let i = 0; i < hashes.length; i += 500) {
    const chunk = hashes.slice(i, i + 500);
    const missing = await getMissingPaths(client, cache, chunk);
    for (const h of missing) {
      missingSet.add(h);
    }
  }

  const skipped = storePaths.length - missingSet.size;
  let pushed = 0;
  let failed = 0;
  const errors: string[] = [];
  let completed = 0;

  const missingHashes = hashes.filter((h) => missingSet.has(h));
  const total = missingHashes.length;

  if (total === 0) {
    return { pushed: 0, skipped, failed: 0, errors: [] };
  }

  // One batched nix path-info call for all missing paths, instead of one
  // process spawn per path inside the upload pool.
  const missingPaths: string[] = [];
  for (const hash of missingHashes) {
    const storePath = hashToPath.get(hash);
    if (storePath) missingPaths.push(storePath);
  }
  const pathInfos = await getPathInfos(missingPaths);
  const pushPath = pathPusher(client, cache);

  await runPool(missingHashes, concurrency, async (hash) => {
    const storePath = hashToPath.get(hash);
    if (!storePath) return;
    const name = storePath.split("/").pop() ?? hash;

    try {
      const info = pathInfos.get(storePath);
      if (!info) {
        throw new Error(`missing path info for ${storePath}`);
      }
      const result = await pushPath(storePath, info);
      completed++;
      onProgress?.(completed, total, name, `ok (${String(result.sizeKb)}KB)`);
      pushed++;
    } catch (err) {
      completed++;
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`${name}: ${msg}`);
      onProgress?.(completed, total, name, `FAIL: ${msg}`);
      failed++;
    }
  });

  return { pushed, skipped, failed, errors };
}
