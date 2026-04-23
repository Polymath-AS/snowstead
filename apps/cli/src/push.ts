import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { stat, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ApiClient } from "./api.js";
import {
  getMissingPaths,
  createUploadSession,
  uploadBlob,
  completeUpload,
  publishPath,
} from "./api.js";
import { getPathInfo, getClosurePaths, dumpAndCompress } from "./nix.js";

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

export async function pushPaths(
  client: ApiClient,
  cache: string,
  storePaths: string[],
  onProgress?: (current: number, total: number, name: string, status: string) => void,
): Promise<PushResult> {
  const hashToPath = new Map<string, string>();
  const hashes: string[] = [];
  for (const p of storePaths) {
    const basename = p.split("/").pop();
    if (!basename) continue;
    const hash = basename.split("-")[0];
    hashToPath.set(hash, p);
    hashes.push(hash);
  }

  // Check missing in parallel batches
  const chunks: string[][] = [];
  for (let i = 0; i < hashes.length; i += 500) {
    chunks.push(hashes.slice(i, i + 500));
  }

  const batchResults = await Promise.all(
    chunks.map((chunk) => getMissingPaths(client, cache, chunk)),
  );

  const missingSet = new Set<string>();
  for (const batch of batchResults) {
    for (const h of batch) {
      missingSet.add(h);
    }
  }

  const skipped = storePaths.length - missingSet.size;
  let pushed = 0;
  let failed = 0;
  const errors: string[] = [];

  const missingHashes = hashes.filter((h) => missingSet.has(h));
  const total = missingHashes.length;

  if (total === 0) {
    return { pushed: 0, skipped, failed: 0, errors: [] };
  }

  for (let idx = 0; idx < missingHashes.length; idx++) {
    const hash = missingHashes[idx];
    const storePath = hashToPath.get(hash);
    if (!storePath) continue;
    const name = storePath.split("/").pop() ?? hash;

    onProgress?.(idx + 1, total, name, "starting");

    try {
      const info = await getPathInfo(storePath);

      const narFile = join(tmpdir(), `odin-nar-${hash}.zst`);
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

        await uploadBlob(client, session.sessionId, narFile);
        await completeUpload(client, session.sessionId);
        await publishPath(client, session.sessionId);

        const sizeKb = Math.round(fileSize / 1024);
        onProgress?.(idx + 1, total, name, `ok (${String(sizeKb)}KB)`);
        pushed++;
      } finally {
        await rm(narFile, { force: true });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`${name}: ${msg}`);
      onProgress?.(idx + 1, total, name, `FAIL: ${msg}`);
      failed++;
    }
  }

  return { pushed, skipped, failed, errors };
}

export async function pushClosure(
  client: ApiClient,
  cache: string,
  rootPath: string,
  onProgress?: (current: number, total: number, name: string, status: string) => void,
): Promise<PushResult> {
  const paths = await getClosurePaths(rootPath);
  return pushPaths(client, cache, paths, onProgress);
}
