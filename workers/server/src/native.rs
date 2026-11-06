//! Bounded streaming SHA-256, NAR magic checking, and optional zstd decompression.
//!
//! This does not validate the NAR grammar. In particular, a raw stream with valid
//! magic and a truncated or malformed body can succeed. Callers must compare the
//! returned hashes and sizes with their expected values when those are known.

use std::{ffi::c_void, fmt, mem::MaybeUninit, ptr::NonNull};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Compression {
    #[cfg(test)]
    None = 0,
    Zstd = 1,
}

/// Layout matches nix-archive's extern Digest, including field order.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest {
    pub file_hash: [u8; 32],
    pub file_size: u64,
    pub nar_hash: [u8; 32],
    pub nar_size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidArgument,
    OutOfMemory,
    Zstd,
    Truncated,
    NotNar,
    SizeExceeded,
    /// An update already failed and released the native verifier.
    Failed,
    UnknownStatus(i32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument => f.write_str("invalid verifier argument"),
            Self::OutOfMemory => f.write_str("allocating NAR verifier"),
            Self::Zstd => f.write_str("invalid zstd stream"),
            Self::Truncated => f.write_str("truncated zstd stream"),
            Self::NotNar => f.write_str("missing NAR magic"),
            Self::SizeExceeded => {
                f.write_str("NAR exceeds the declared size or verifier counter limit")
            }
            Self::Failed => f.write_str("NAR verifier has already failed"),
            Self::UnknownStatus(code) => write!(f, "unknown verifier status {code}"),
        }
    }
}

impl std::error::Error for Error {}

fn status(code: i32) -> Result<(), Error> {
    match code {
        0 => Ok(()),
        1 => Err(Error::InvalidArgument),
        2 => Err(Error::OutOfMemory),
        3 => Err(Error::Zstd),
        4 => Err(Error::Truncated),
        5 => Err(Error::NotNar),
        6 => Err(Error::SizeExceeded),
        code => Err(Error::UnknownStatus(code)),
    }
}

pub(super) struct Api {
    create: unsafe extern "C" fn(i32, u64, *mut *mut c_void) -> i32,
    update: unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32,
    finish: unsafe extern "C" fn(*mut c_void, *mut Digest) -> i32,
    free: unsafe extern "C" fn(*mut c_void),
    #[cfg(feature = "profiling")]
    pub(super) profile_start: unsafe extern "C" fn(),
    #[cfg(feature = "profiling")]
    pub(super) profile_finish: unsafe extern "C" fn(),
}

macro_rules! ffi {
    ($module:ident, $prefix:literal) => {
        mod $module {
            use super::*;
            unsafe extern "C" {
                #[link_name = concat!($prefix, "verify_create_bounded")]
                fn create(compression: i32, max_nar_size: u64, out: *mut *mut c_void) -> i32;
                #[link_name = concat!($prefix, "verify_update")]
                fn update(ptr: *mut c_void, data: *const u8, len: usize) -> i32;
                #[link_name = concat!($prefix, "verify_finish")]
                fn finish(ptr: *mut c_void, out: *mut Digest) -> i32;
                #[link_name = concat!($prefix, "verify_free")]
                fn free(ptr: *mut c_void);
                #[cfg(feature = "profiling")]
                #[link_name = concat!($prefix, "profile_start")]
                fn profile_start();
                #[cfg(feature = "profiling")]
                #[link_name = concat!($prefix, "profile_finish")]
                fn profile_finish();
            }
            pub(super) const API: Api = Api {
                create,
                update,
                finish,
                free,
                #[cfg(feature = "profiling")]
                profile_start,
                #[cfg(feature = "profiling")]
                profile_finish,
            };
        }
    };
}
ffi!(portable, "sn_");
ffi!(accelerated, "sn_fast_");

pub(super) fn api() -> &'static Api {
    #[cfg(target_arch = "x86_64")]
    let fast = std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("sha");
    #[cfg(target_arch = "aarch64")]
    let fast = std::arch::is_aarch64_feature_detected!("sha2");
    if fast {
        &accelerated::API
    } else {
        &portable::API
    }
}

/// Owns one native verifier. Failed updates immediately release its allocation.
pub struct Verifier {
    ptr: Option<NonNull<c_void>>,
    api: &'static Api,
}

// SAFETY: the verifier and its zstd context have no thread affinity, retain no
// Rust borrows, and are accessed exclusively through &mut self or consuming self.
unsafe impl Send for Verifier {}

#[cfg_attr(feature = "profiling", hotpath::measure_all)]
impl Verifier {
    /// Reject output beyond this ceiling during update, not after decompression.
    /// Finish still permits shorter streams; callers must compare expected sizes.
    pub fn new_bounded(compression: Compression, max_nar_size: u64) -> Result<Self, Error> {
        Self::new_with_api(compression, max_nar_size, api())
    }

    fn new_with_api(
        compression: Compression,
        max_nar_size: u64,
        api: &'static Api,
    ) -> Result<Self, Error> {
        let mut ptr = std::ptr::null_mut();
        // SAFETY: out is writable; compression is one of the two ABI values,
        // and the selected API supports this CPU. Retain it for this allocation.
        status(unsafe { (api.create)(compression as i32, max_nar_size, &mut ptr) })?;
        let ptr = NonNull::new(ptr).ok_or(Error::OutOfMemory)?;
        Ok(Self {
            ptr: Some(ptr),
            api,
        })
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let ptr = self.ptr.ok_or(Error::Failed)?;
        // SAFETY: ptr is uniquely owned and live, and bytes is readable for len.
        // The synchronous native call does not retain bytes.
        let result =
            status(unsafe { (self.api.update)(ptr.as_ptr(), bytes.as_ptr(), bytes.len()) });
        if result.is_err() {
            self.release();
        }
        result
    }

    /// Finalizes both hashes and consumes this verifier, including on failure.
    pub fn finish(self) -> Result<Digest, Error> {
        let ptr = self.ptr.ok_or(Error::Failed)?;
        let mut digest = MaybeUninit::uninit();
        // SAFETY: ptr is live and exclusively owned; digest has the ABI layout.
        // Native code initializes all digest fields on success only.
        status(unsafe { (self.api.finish)(ptr.as_ptr(), digest.as_mut_ptr()) })?;
        // SAFETY: a successful finish initialized every field.
        Ok(unsafe { digest.assume_init() })
        // Drop frees the native state on both the success and error paths.
    }

    fn release(&mut self) {
        if let Some(ptr) = self.ptr.take() {
            // SAFETY: take ensures this allocation is freed exactly once.
            unsafe { (self.api.free)(ptr.as_ptr()) };
        }
    }
}

impl Drop for Verifier {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    const MAGIC: &[u8] = b"\x0d\0\0\0\0\0\0\0nix-archive-1\0\0\0";

    // An independently serialized regular-file NAR, not generated by the Zig core.
    fn nar(contents: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in [
            b"nix-archive-1".as_slice(),
            b"(",
            b"type",
            b"regular",
            b"contents",
            contents,
            b")",
        ] {
            bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
            bytes.extend_from_slice(value);
            bytes.resize(bytes.len().next_multiple_of(8), 0);
        }
        bytes
    }

    fn verify(mode: Compression, bytes: &[u8], chunk: usize) -> Result<Digest, Error> {
        let mut v = Verifier::new_bounded(mode, u64::MAX)?;
        v.update(&[])?;
        for part in bytes.chunks(chunk) {
            v.update(part)?;
        }
        v.finish()
    }

    fn expected(file: &[u8], raw: &[u8]) -> Digest {
        Digest {
            file_hash: Sha256::digest(file).into(),
            file_size: file.len() as u64,
            nar_hash: Sha256::digest(raw).into(),
            nar_size: raw.len() as u64,
        }
    }

    #[test]
    fn bounded_raw_and_zstd_exact_and_one_byte_excess() {
        let raw = nar(&vec![b'x'; 1024 * 1024]);
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        // Exercise the portable fallback even on SHA-capable hosts, alongside
        // the runtime-selected implementation. Both must honor the same ABI,
        // fragmented hashes, output ceiling, and post-error lifetime contract.
        for api in [&portable::API, api()] {
            for (mode, bytes) in [
                (Compression::None, raw.as_slice()),
                (Compression::Zstd, compressed.as_slice()),
            ] {
                for chunk in [1, 29, bytes.len()] {
                    let mut exact = Verifier::new_with_api(mode, raw.len() as u64, api).unwrap();
                    for part in bytes.chunks(chunk) {
                        exact.update(part).unwrap();
                    }
                    assert_eq!(exact.finish().unwrap(), expected(bytes, &raw));

                    let mut excess =
                        Verifier::new_with_api(mode, raw.len() as u64 - 1, api).unwrap();
                    let error = bytes
                        .chunks(chunk)
                        .find_map(|part| excess.update(part).err());
                    assert_eq!(error, Some(Error::SizeExceeded));
                    assert_eq!(excess.update(&[]), Err(Error::Failed));
                    assert_eq!(excess.finish(), Err(Error::Failed));
                }
            }
        }
    }

    #[test]
    fn rejects_high_expansion_in_one_update_and_releases_native_state() {
        let raw = nar(&vec![0; 16 * 1024 * 1024]);
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        assert!(compressed.len() < 4096);
        for ceiling in [0, MAGIC.len() as u64, 1024 * 1024] {
            let mut v = Verifier::new_bounded(Compression::Zstd, ceiling).unwrap();
            assert_eq!(v.update(&compressed), Err(Error::SizeExceeded));
            assert_eq!(v.finish(), Err(Error::Failed));
        }
        // A rejected upload must not poison later allocations/verifications.
        assert_eq!(
            verify(Compression::None, MAGIC, 1).unwrap(),
            expected(MAGIC, MAGIC)
        );
    }

    #[test]
    fn accepts_client_window_limit_and_rejects_larger_history() {
        // Standard frame headers with unknown content size and 2^27 / 2^28
        // windows. No body is needed to check the allocation policy.
        let mut allowed = Verifier::new_bounded(Compression::Zstd, 1024).unwrap();
        allowed.update(&[0x28, 0xb5, 0x2f, 0xfd, 0, 0x88]).unwrap();
        assert_eq!(allowed.finish(), Err(Error::Truncated));
        let mut rejected = Verifier::new_bounded(Compression::Zstd, 1024).unwrap();
        assert_eq!(
            rejected.update(&[0x28, 0xb5, 0x2f, 0xfd, 0, 0x90]),
            Err(Error::Zstd)
        );
    }

    #[hegel::test]
    fn fragmented_frames_preserve_hashes_sizes_and_bounds(tc: hegel::TestCase) {
        use hegel::generators as gs;

        let contents = tc.draw(gs::vecs(gs::integers::<u8>()).max_size(8192));
        let raw = nar(&contents);
        let split = tc.draw(gs::integers::<usize>().max_value(raw.len()));
        let mut compressed = zstd::stream::encode_all(&raw[..split], 3).unwrap();
        compressed.extend(zstd::stream::encode_all(&raw[split..], 3).unwrap());
        for api in [&portable::API, api()] {
            for (mode, bytes) in [
                (Compression::None, raw.as_slice()),
                (Compression::Zstd, compressed.as_slice()),
            ] {
                let boundary = tc.draw(gs::integers::<usize>().max_value(bytes.len()));
                let chunk = tc.draw(gs::integers::<usize>().min_value(1).max_value(bytes.len()));
                let mut exact = Verifier::new_with_api(mode, raw.len() as u64, api).unwrap();
                exact.update(&bytes[..boundary]).unwrap();
                exact.update(&[]).unwrap();
                for part in bytes[boundary..].chunks(chunk) {
                    exact.update(part).unwrap();
                }
                assert_eq!(exact.finish().unwrap(), expected(bytes, &raw));

                let mut excess = Verifier::new_with_api(mode, raw.len() as u64 - 1, api).unwrap();
                assert_eq!(excess.update(bytes), Err(Error::SizeExceeded));
                assert_eq!(excess.update(&[]), Err(Error::Failed));
                assert_eq!(excess.finish(), Err(Error::Failed));
            }
        }
    }

    #[test]
    fn drains_multiple_output_buffers_and_concatenated_frames() {
        let raw = nar(&vec![b'x'; 2 * 1024 * 1024]);
        let split = 31;
        let mut compressed = zstd::stream::encode_all(&raw[..split], 3).unwrap();
        compressed.extend(zstd::stream::encode_all(&raw[split..], 3).unwrap());
        for chunk in [1, 29, compressed.len()] {
            assert_eq!(
                verify(Compression::Zstd, &compressed, chunk).unwrap(),
                expected(&compressed, &raw)
            );
        }
    }

    #[test]
    fn rejects_short_magic_and_incomplete_compressed_frames() {
        for len in 0..MAGIC.len() {
            assert_eq!(
                verify(Compression::None, &MAGIC[..len], 1),
                Err(Error::NotNar)
            );
        }
        let raw = nar(b"hello\n");
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        for len in 0..compressed.len() {
            assert!(verify(Compression::Zstd, &compressed[..len], 1).is_err());
        }
    }

    #[test]
    fn rejects_corruption_and_does_not_resume_after_error() {
        let mut raw = nar(b"hello\n");
        raw[8] ^= 1;
        assert_eq!(verify(Compression::None, &raw, 1), Err(Error::NotNar));
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        assert_eq!(
            verify(Compression::Zstd, &compressed, 1),
            Err(Error::NotNar)
        );

        let mut v = Verifier::new_bounded(Compression::Zstd, u64::MAX).unwrap();
        assert_eq!(v.update(b"not a zstd frame"), Err(Error::Zstd));
        assert_eq!(v.update(&[]), Err(Error::Failed));
        assert_eq!(v.finish(), Err(Error::Failed));

        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
        encoder.include_checksum(true).unwrap();
        std::io::Write::write_all(&mut encoder, &nar(b"hello\n")).unwrap();
        let mut compressed = encoder.finish().unwrap();
        *compressed.last_mut().unwrap() ^= 1;
        assert_eq!(verify(Compression::Zstd, &compressed, 1), Err(Error::Zstd));
    }

    #[test]
    fn only_magic_not_full_nar_structure_is_checked() {
        assert_eq!(
            verify(Compression::None, MAGIC, 1).unwrap(),
            expected(MAGIC, MAGIC)
        );
        let mut body = MAGIC.to_vec();
        body.extend_from_slice(b"not a valid NAR body");
        assert_eq!(
            verify(Compression::None, &body, 1).unwrap(),
            expected(&body, &body)
        );
    }
}
