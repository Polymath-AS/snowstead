import { describe, it, expect } from 'vitest';
import {
  parseCacheName,
  parseStorePathHash,
  parseNarHash,
  parseStorePathBasename,
  parseFileHash,
  parseCompression,
} from '../src/index.js';

function isParseError(result: unknown): result is { kind: 'ParseError'; message: string } {
  return (
    typeof result === 'object' &&
    result !== null &&
    (result as { kind?: string }).kind === 'ParseError'
  );
}

describe('parseCacheName', () => {
  it.each(['my-cache', 'a', 'a1b2', 'abc', 'a-b'])('accepts valid name %j', (input) => {
    const result = parseCacheName(input);
    expect(isParseError(result)).toBe(false);
    expect(result).toBe(input);
  });

  it.each([
    { input: '', label: 'empty string' },
    { input: 'My-Cache', label: 'uppercase' },
    { input: '-leading', label: 'leading hyphen' },
    { input: 'trailing-', label: 'trailing hyphen' },
    { input: 'has spaces', label: 'spaces' },
    { input: 'a'.repeat(65), label: '65-char string' },
    { input: 'has_underscore', label: 'underscore' },
  ])('rejects $label', ({ input }) => {
    const result = parseCacheName(input);
    expect(isParseError(result)).toBe(true);
  });
});

describe('parseStorePathHash', () => {
  it('accepts 32 valid nix-base32 chars', () => {
    const input = '0v9z1234abcdfghijklmnpqrsvwxyz01';
    const result = parseStorePathHash(input);
    expect(isParseError(result)).toBe(false);
    expect(result).toBe(input);
  });

  it.each([
    { input: '0'.repeat(31), label: '31 chars (too short)' },
    { input: '0'.repeat(33), label: '33 chars (too long)' },
    { input: '0'.repeat(31) + 'e', label: "contains 'e'" },
    { input: '0'.repeat(31) + 'o', label: "contains 'o'" },
    { input: '0'.repeat(31) + 't', label: "contains 't'" },
    { input: '0'.repeat(31) + 'u', label: "contains 'u'" },
    { input: '0'.repeat(31) + 'A', label: 'uppercase letters' },
  ])('rejects $label', ({ input }) => {
    const result = parseStorePathHash(input);
    expect(isParseError(result)).toBe(true);
  });
});

describe('parseNarHash', () => {
  // `nix path-info --json` and `nix hash convert` agree on these.
  const nix32 = 'sha256:02crsn39w9wxan1z3dz9g1zb76l09jb462qzb3q8r8zic4p2k6rg';

  it.each([
    { input: nix32, label: 'nix32' },
    { input: 'sha256-L5spLmHxo4zwWB8LQ5ZMgJqzfnjpt/GDVZ0nnobVmQk=', label: 'SRI' },
    { input: 'sha256:2f9b292e61f1a38cf0581f0b43964c809ab37e78e9b7f183559d279e86d59909', label: 'hex' },
  ])('canonicalises $label to nix32', ({ input }) => {
    expect(parseNarHash(input)).toBe(nix32);
  });

  it.each([
    { input: '0'.repeat(52), label: 'no sha256: prefix' },
    { input: 'md5:' + '0'.repeat(52), label: 'md5: prefix' },
    { input: 'sha256:' + '0'.repeat(51), label: '51 hash chars' },
    { input: 'sha256:' + '0'.repeat(53), label: '53 hash chars' },
    { input: 'sha256:' + '0'.repeat(51) + 'e', label: "hash contains 'e'" },
    { input: 'sha256:' + 'z'.repeat(52), label: 'more than 256 bits' },
    { input: 'sha256-' + 'A'.repeat(43), label: 'SRI without padding' },
  ])('rejects $label', ({ input }) => {
    expect(isParseError(parseNarHash(input))).toBe(true);
  });
});

describe('parseStorePathBasename', () => {
  it('accepts a basename', () => {
    expect(parseStorePathBasename('g60m3aky9f59wgy1gi0y06xwmbw19d6m-xgcc-16.2.0-libgcc')).toBe(
      'g60m3aky9f59wgy1gi0y06xwmbw19d6m-xgcc-16.2.0-libgcc',
    );
  });

  it.each([
    { input: 'g60m3aky9f59wgy1gi0y06xwmbw19d6m', label: 'a bare hash' },
    { input: '/nix/store/g60m3aky9f59wgy1gi0y06xwmbw19d6m-xgcc', label: 'a full path' },
    { input: 'g60m3aky9f59wgy1gi0y06xwmbw19d6m-a b', label: 'a space' },
    { input: 'g60m3aky9f59wgy1gi0y06xwmbw19d6m-a\nb', label: 'a newline' },
  ])('rejects $label', ({ input }) => {
    expect(isParseError(parseStorePathBasename(input))).toBe(true);
  });
});

describe('parseFileHash', () => {
  it('accepts 64 lowercase hex chars (repeated a)', () => {
    const input = 'a'.repeat(64);
    const result = parseFileHash(input);
    expect(isParseError(result)).toBe(false);
    expect(result).toBe(input);
  });

  it('accepts 64 lowercase hex chars (mixed)', () => {
    const input = '0123456789abcdef'.repeat(4);
    const result = parseFileHash(input);
    expect(isParseError(result)).toBe(false);
    expect(result).toBe(input);
  });

  it.each([
    { input: 'a'.repeat(63), label: '63 chars' },
    { input: 'a'.repeat(65), label: '65 chars' },
    { input: 'a'.repeat(63) + 'g', label: "contains 'g'" },
    { input: 'A'.repeat(64), label: 'uppercase hex' },
  ])('rejects $label', ({ input }) => {
    const result = parseFileHash(input);
    expect(isParseError(result)).toBe(true);
  });
});

describe('parseCompression', () => {
  it.each(['zstd', 'xz', 'bzip2', 'none'] as const)('accepts %j', (input) => {
    const result = parseCompression(input);
    expect(isParseError(result)).toBe(false);
    expect(result).toBe(input);
  });

  it.each([
    { input: 'gzip', label: 'gzip' },
    { input: '', label: 'empty string' },
    { input: 'ZSTD', label: 'uppercase ZSTD' },
  ])('rejects $label', ({ input }) => {
    const result = parseCompression(input);
    expect(isParseError(result)).toBe(true);
  });
});
