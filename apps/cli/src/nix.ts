import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { promisify } from "node:util";

const exec = promisify(execFile);

export interface PathInfo {
  readonly storePath: string;
  readonly storePathHash: string;
  readonly narHash: string;
  readonly narSize: number;
  readonly references: string[];
  readonly deriver?: string;
}

interface NixPathInfoJson {
  readonly narHash: string;
  readonly narSize: number;
  readonly references: string[];
  readonly deriver?: string;
}

// nix path-info output for a large batch (references lists included) can far
// exceed execFile's default 1 MiB stdout buffer.
const EXEC_MAX_BUFFER_BYTES = 64 * 1024 * 1024;

// Bound argv size per nix invocation; store paths are ~90 bytes each.
const PATH_INFO_BATCH_SIZE = 500;

function toPathInfo(storePath: string, entry: NixPathInfoJson): PathInfo {
  const basename = storePath.split("/").pop();
  if (!basename) {
    throw new Error(`Invalid store path: ${storePath}`);
  }
  const storePathHash = basename.split("-")[0];

  const refs = entry.references.map((r: string) => {
    const refBase = r.split("/").pop();
    if (!refBase) {
      throw new Error(`Invalid reference path: ${r}`);
    }
    return refBase.split("-")[0];
  });

  return {
    storePath,
    storePathHash,
    narHash: entry.narHash,
    narSize: entry.narSize,
    references: refs,
    deriver: entry.deriver,
  };
}

/**
 * Query path info for many store paths with a bounded number of nix
 * invocations, instead of one process spawn per path.
 */
export async function getPathInfos(
  storePaths: readonly string[],
): Promise<Map<string, PathInfo>> {
  const infos = new Map<string, PathInfo>();

  for (let i = 0; i < storePaths.length; i += PATH_INFO_BATCH_SIZE) {
    const chunk = storePaths.slice(i, i + PATH_INFO_BATCH_SIZE);
    const { stdout } = await exec("nix", ["path-info", "--json", ...chunk], {
      maxBuffer: EXEC_MAX_BUFFER_BYTES,
    });
    const parsed: Record<string, NixPathInfoJson> = JSON.parse(stdout);

    for (const storePath of chunk) {
      const entry = parsed[storePath];
      if (!entry) {
        throw new Error(`nix path-info returned no data for ${storePath}`);
      }
      infos.set(storePath, toPathInfo(storePath, entry));
    }
  }

  return infos;
}

export async function getClosurePaths(storePath: string): Promise<string[]> {
  const { stdout } = await exec("nix", ["path-info", "-r", storePath], {
    maxBuffer: EXEC_MAX_BUFFER_BYTES,
  });
  return stdout.trim().split("\n").filter(Boolean);
}

export interface CompressedNar {
  readonly fileHash: string;
  readonly fileSize: number;
}

/**
 * Dump a store path as a NAR, compress it with zstd, and write it to
 * outputPath. The compressed stream is hashed and counted while it is
 * written, so callers do not need to re-read the file to compute the
 * upload hash and size.
 */
export async function dumpAndCompress(
  storePath: string,
  outputPath: string,
): Promise<CompressedNar> {
  const nix = spawn("nix", ["store", "dump-path", storePath], {
    stdio: ["ignore", "pipe", "ignore"],
  });
  const zstd = spawn("zstd", ["-q", "-c"], {
    stdio: ["pipe", "pipe", "ignore"],
  });

  nix.stdout.pipe(zstd.stdin);

  // Observe the piped chunks to hash and count them; pipe() still owns
  // backpressure to the file stream.
  const hash = createHash("sha256");
  let fileSize = 0;
  zstd.stdout.on("data", (chunk: Buffer) => {
    hash.update(chunk);
    fileSize += chunk.length;
  });

  const out = createWriteStream(outputPath);
  zstd.stdout.pipe(out);

  await new Promise<void>((resolve, reject) => {
    let nixExited = false;
    let zstdExited = false;
    let fileFlushed = false;
    let settled = false;

    const fail = (err: Error) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    };

    const tryResolve = () => {
      if (nixExited && zstdExited && fileFlushed && !settled) {
        settled = true;
        resolve();
      }
    };

    nix.on("error", fail);
    zstd.on("error", fail);
    out.on("error", fail);

    nix.on("close", (code) => {
      nixExited = true;
      if (code !== 0) {
        fail(new Error(`nix store dump-path exited with ${String(code)}`));
        return;
      }
      tryResolve();
    });

    zstd.on("close", (code) => {
      zstdExited = true;
      if (code !== 0) {
        fail(new Error(`zstd exited with ${String(code)}`));
        return;
      }
      tryResolve();
    });

    out.on("finish", () => {
      fileFlushed = true;
      tryResolve();
    });
  });

  return { fileHash: hash.digest("hex"), fileSize };
}
