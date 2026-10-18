export type Brand<T, B extends string> = T & { readonly __brand: B };

export type CacheName = Brand<string, "CacheName">;
export type StorePathHash = Brand<string, "StorePathHash">;
export type NarHash = Brand<string, "NarHash">;
export type FileHash = Brand<string, "FileHash">;
export type Compression = "zstd" | "xz" | "bzip2" | "none";

/** Upload instructions returned by the session API. Dates are ISO strings on the wire. */
export type SessionResponse = {
  readonly sessionId: string;
  readonly r2Key: string;
  readonly expiresAt: string;
} & (
  | { readonly uploadMethod: "direct" }
  | {
      readonly uploadMethod: "presigned";
      readonly uploadUrl: string;
      readonly uploadHeaders: Record<string, string>;
    }
  | {
      readonly uploadMethod: "presigned-parts";
      readonly partSize: number;
      readonly parts: ReadonlyArray<{ readonly partNumber: number; readonly url: string }>;
    }
);

export interface NarInfoFields {
  readonly storePath: string;
  readonly storePathHash: StorePathHash;
  readonly narHash: NarHash;
  readonly narSize: number;
  readonly fileHash: FileHash;
  readonly fileSize: number;
  readonly compression: Compression;
  readonly references: readonly StorePathHash[];
  readonly deriver?: string;
  readonly system?: string;
  readonly signatures: readonly string[];
}

export interface ParseError {
  readonly kind: "ParseError";
  readonly message: string;
}
