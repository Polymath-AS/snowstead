import { execFile, spawn } from "node:child_process";
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

export async function getPathInfo(storePath: string): Promise<PathInfo> {
  const { stdout } = await exec("nix", ["path-info", "--json", storePath]);
  const parsed: Record<string, NixPathInfoJson> = JSON.parse(stdout);
  const entry = parsed[storePath];
  if (!entry) {
    throw new Error(`nix path-info returned no data for ${storePath}`);
  }

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

export async function getClosurePaths(storePath: string): Promise<string[]> {
  const { stdout } = await exec("nix", ["path-info", "-r", storePath]);
  return stdout.trim().split("\n").filter(Boolean);
}

export async function dumpAndCompress(
  storePath: string,
  outputPath: string,
): Promise<void> {
  const nix = spawn("nix", ["store", "dump-path", storePath], {
    stdio: ["ignore", "pipe", "ignore"],
  });
  const zstd = spawn("zstd", ["-q", "-o", outputPath], {
    stdio: ["pipe", "ignore", "ignore"],
  });

  nix.stdout.pipe(zstd.stdin);

  return new Promise((resolve, reject) => {
    let nixExited = false;
    let zstdExited = false;
    let settled = false;

    const fail = (err: Error) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    };

    const tryResolve = () => {
      if (nixExited && zstdExited && !settled) {
        settled = true;
        resolve();
      }
    };

    nix.on("error", fail);
    zstd.on("error", fail);

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
  });
}
