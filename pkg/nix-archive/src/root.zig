//! NAR (Nix ARchive) production and verification.
//!
//! - `dump`: serialise a filesystem tree straight from the kernel (Linux).
//! - `Sink`: hash, count and zstd-compress a NAR stream in one pass.
//! - `Verifier`: hash and decompress an uploaded stream, checking it is a NAR.

const walk = @import("walk.zig");
const sink = @import("sink.zig");
const verify = @import("verify.zig");

pub const Sink = sink.Sink;
pub const Digest = sink.Digest;
pub const WriteFn = sink.WriteFn;
pub const Options = sink.Options;
pub const SinkError = sink.Error;

pub const dump = walk.dump;
pub const supported = walk.supported;
pub const DumpError = walk.Error;
pub fn lastErrno() i32 {
    return walk.last_errno;
}

pub const Verifier = verify.Verifier;
pub const Compression = verify.Compression;
pub const Sha256 = @import("sha256.zig").Sha256;

test {
    _ = @import("tests.zig");
    _ = @import("sha256.zig");
}
