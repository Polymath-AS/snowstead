export type {
  Brand,
  CacheName,
  StorePathHash,
  NarHash,
  FileHash,
  Compression,
  NarInfoFields,
  ParseError,
  SessionResponse,
} from './types.js';

export {
  parseCacheName,
  parseStorePathHash,
  parseNarHash,
  parseStorePathBasename,
  nix32Encode,
  parseFileHash,
  parseCompression,
} from './parsers.js';

/** Tenant used by self-hosted installs and tokens predating organizations. */
export const DEFAULT_ORG_ID = "default";
