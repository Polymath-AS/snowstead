import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdtemp, stat, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ApiClient } from "./api.js";
import {
  getMissingPaths,
  createUploadSession,
  uploadBlob,
  shouldUseMultipart,
  uploadBlobMultipart,
  completeUpload,
  publishPath,
} from "./api.js";
import { getPathInfo, dumpAndCompress } from "./nix.js";

const DEFAULT_CONCURRENCY = 8;

async function computeFileHash(filePath: string): Promise<string> {
  const hash = createHash("sha256");
  const stream = createReadStream(filePath);
  for await (const chunk of stream) {
    hash.update(chunk);
  }
  return hash.digest("hex");
}

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

async function pushSinglePath(
  client: ApiClient,
  cache: string,
  storePath: string,
  hash: string,
): Promise<{ sizeKb: number }> {
  const info = await getPathInfo(storePath);
  const narDir = await mkdtemp(join(tmpdir(), "helios-nar-"));
  const narFile = join(narDir, "nar.zst");

  try {
    await dumpAndCompress(storePath, narFile);

    const fileHash = await computeFileHash(narFile);
    const fileStat = await stat(narFile);
    const fileSize = Number(fileStat.size);

    const session = await createUploadSession(client, cache, {
      storePath: info.storePath,
      storePathHash: info.storePathHash,
      narHash: info.narHash,
      narSize: info.narSize,
      fileHash,
      fileSize,
      compression: "zstd",
      references: info.references,
    });

    if (shouldUseMultipart(fileSize)) {
      await uploadBlobMultipart(client, session.sessionId, narFile);
    } else {
      await uploadBlob(client, session.sessionId, narFile);
    }
    await completeUpload(client, session.sessionId);
    await publishPath(client, session.sessionId);

    return { sizeKb: Math.round(fileSize / 1024) };
  } finally {
    await rm(narDir, { recursive: true, force: true });
  }
}

async function runPool<T>(
  items: readonly T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<void>,
): Promise<void> {
  let next = 0;

  async function worker(): Promise<void> {
    while (next < items.length) {
      const idx = next;
      next++;
      await fn(items[idx], idx);
    }
  }

  const workers: Promise<void>[] = [];
  for (let i = 0; i < Math.min(concurrency, items.length); i++) {
    workers.push(worker());
  }
  await Promise.all(workers);
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

  // Check missing in sequential batches (server chunks internally for D1 limits)
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

  await runPool(missingHashes, concurrency, async (hash) => {
    const storePath = hashToPath.get(hash);
    if (!storePath) return;
    const name = storePath.split("/").pop() ?? hash;

    try {
      const result = await pushSinglePath(client, cache, storePath, hash);
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

