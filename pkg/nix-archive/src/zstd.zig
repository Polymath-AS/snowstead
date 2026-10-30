//! Minimal hand-written bindings for the libzstd streaming API.

pub const CCtx = opaque {};
pub const DCtx = opaque {};

pub const InBuffer = extern struct {
    src: ?*const anyopaque,
    size: usize,
    pos: usize,
};

pub const OutBuffer = extern struct {
    dst: ?*anyopaque,
    size: usize,
    pos: usize,
};

pub const c_compressionLevel: c_int = 100;
pub const c_checksumFlag: c_int = 201;
pub const c_nbWorkers: c_int = 400;
pub const c_windowLog: c_int = 101;
pub const c_enableLongDistanceMatching: c_int = 160;

pub const e_continue: c_int = 0;
pub const e_end: c_int = 2;

pub extern "c" fn ZSTD_createCCtx() ?*CCtx;
pub extern "c" fn ZSTD_freeCCtx(cctx: ?*CCtx) usize;
pub extern "c" fn ZSTD_CCtx_setParameter(cctx: *CCtx, param: c_int, value: c_int) usize;
pub extern "c" fn ZSTD_compressStream2(cctx: *CCtx, output: *OutBuffer, input: *InBuffer, end_op: c_int) usize;
pub extern "c" fn ZSTD_CCtx_setPledgedSrcSize(cctx: *CCtx, pledged_src_size: c_ulonglong) usize;
pub extern "c" fn ZSTD_CStreamOutSize() usize;

pub extern "c" fn ZSTD_createDCtx() ?*DCtx;
pub extern "c" fn ZSTD_freeDCtx(dctx: ?*DCtx) usize;
pub extern "c" fn ZSTD_decompressStream(dctx: *DCtx, output: *OutBuffer, input: *InBuffer) usize;
pub extern "c" fn ZSTD_DStreamOutSize() usize;

pub extern "c" fn ZSTD_isError(code: usize) c_uint;

pub fn isError(code: usize) bool {
    return ZSTD_isError(code) != 0;
}
