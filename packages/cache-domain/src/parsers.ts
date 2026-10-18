import type {
  CacheName,
  Compression,
  FileHash,
  NarHash,
  ParseError,
  StorePathHash,
} from './types.js';

const NIX_BASE32_CHARS = "0123456789abcdfghijklmnpqrsvwxyz";
const NIX_BASE32_RE = new RegExp(`^[${NIX_BASE32_CHARS}]+$`);
const HEX_RE = /^[0-9a-f]{64}$/;
const SRI_SHA256_RE = /^[A-Za-z0-9+/]{43}=$/;
const STORE_BASENAME_RE = new RegExp(`^[${NIX_BASE32_CHARS}]{32}-[A-Za-z0-9+\\-._?=]{1,211}$`);
const CACHE_NAME_RE = /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/;
const VALID_COMPRESSIONS = new Set<Compression>(["zstd", "xz", "bzip2", "none"]);

function err(message: string): ParseError {
  return { kind: "ParseError", message };
}

export function parseCacheName(raw: string): CacheName | ParseError {
  if (!CACHE_NAME_RE.test(raw)) {
    return err(
      "CacheName must be 1-64 lowercase alphanumeric chars or hyphens, no leading/trailing hyphen",
    );
  }
  return raw as CacheName;
}

export function parseStorePathHash(raw: string): StorePathHash | ParseError {
  if (raw.length !== 32) {
    return err("StorePathHash must be exactly 32 characters");
  }
  if (!NIX_BASE32_RE.test(raw)) {
    return err("StorePathHash contains invalid nix base-32 characters");
  }
  return raw as StorePathHash;
}

export function parseNarHash(raw: string): NarHash | ParseError {
  const digest = narHashDigest(raw);
  if (!(digest instanceof Uint8Array)) {
    return digest;
  }
  return `sha256:${nix32Encode(digest)}` as NarHash;
}

// Nix prints NAR hashes as SRI (`sha256-<base64>`, what `nix path-info
// --json` emits), as `sha256:<nix32>` (narinfo) or as `sha256:<hex>`.
// Signatures cover the nix32 form, so every form is canonicalised to it.
function narHashDigest(raw: string): Uint8Array | ParseError {
  if (raw.startsWith("sha256-")) {
    const b64 = raw.slice(7);
    if (!SRI_SHA256_RE.test(b64)) {
      return err("NarHash SRI digest must be 44 base64 characters");
    }
    return base64Decode(b64);
  }
  if (!raw.startsWith("sha256:")) {
    return err("NarHash must start with 'sha256:' or 'sha256-'");
  }
  const hash = raw.slice(7);
  if (HEX_RE.test(hash)) {
    return Uint8Array.from(hash.match(/../g)!, (h) => parseInt(h, 16));
  }
  if (hash.length !== 52) {
    return err("NarHash hash part must be 52 nix base-32 or 64 hex characters");
  }
  if (!NIX_BASE32_RE.test(hash)) {
    return err("NarHash contains invalid nix base-32 characters");
  }
  // 52 digits carry 260 bits; the top 4 must be zero for a 32-byte digest.
  if (NIX_BASE32_CHARS.indexOf(hash[0]) > 1) {
    return err("NarHash does not fit 32 bytes");
  }
  return nix32Decode(hash);
}

const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Standard padded base64; the caller has checked the alphabet. */
function base64Decode(text: string): Uint8Array {
  const digits = text.replace(/=+$/, "");
  const out = new Uint8Array(Math.floor((digits.length * 6) / 8));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const c of digits) {
    acc = (acc << 6) | BASE64_CHARS.indexOf(c);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

/** Nix base-32: the least significant 5-bit group is the last character. */
export function nix32Encode(bytes: Uint8Array): string {
  const len = Math.floor((bytes.length * 8 - 1) / 5) + 1;
  let out = "";
  for (let n = len - 1; n >= 0; n--) {
    const b = n * 5;
    const i = b >> 3;
    const j = b & 7;
    const c = (bytes[i] >> j) | (i + 1 < bytes.length ? bytes[i + 1] << (8 - j) : 0);
    out += NIX_BASE32_CHARS[c & 0x1f];
  }
  return out;
}

function nix32Decode(text: string): Uint8Array {
  const out = new Uint8Array(32);
  for (let n = 0; n < text.length; n++) {
    const digit = NIX_BASE32_CHARS.indexOf(text[text.length - n - 1]);
    const b = n * 5;
    const i = b >> 3;
    const j = b & 7;
    out[i] |= (digit << j) & 0xff;
    if (i + 1 < out.length) out[i + 1] |= digit >> (8 - j);
  }
  return out;
}

/** A store path basename, `<32-char hash>-<name>`, as narinfo References lists. */
export function parseStorePathBasename(raw: string): string | ParseError {
  if (!STORE_BASENAME_RE.test(raw)) {
    return err(`invalid store path basename: ${raw}`);
  }
  return raw;
}

export function parseFileHash(raw: string): FileHash | ParseError {
  if (!HEX_RE.test(raw)) {
    return err("FileHash must be exactly 64 lowercase hex characters");
  }
  return raw as FileHash;
}

export function parseCompression(raw: string): Compression | ParseError {
  if (!VALID_COMPRESSIONS.has(raw as Compression)) {
    return err(`Compression must be one of: ${[...VALID_COMPRESSIONS].join(", ")}`);
  }
  return raw as Compression;
}
