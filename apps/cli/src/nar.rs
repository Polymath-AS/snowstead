//! The Zig NAR core hashes and compresses in-process. Spooling keeps HTTP
//! retries replayable and supplies the v1 API's required final hash and size.
use anyhow::{Context, bail};
use base64::Engine;
use std::{
    ffi::{CString, c_char, c_void},
    io::{self, Read, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

#[repr(C)]
#[derive(Default)]
pub struct Digest {
    pub file_hash: [u8; 32],
    pub file_size: u64,
    pub nar_hash: [u8; 32],
    pub nar_size: u64,
}
type Callback = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32;
type Dump =
    unsafe extern "C" fn(*const c_char, i32, i32, u64, Callback, *mut c_void, *mut Digest) -> i32;
type Create = unsafe extern "C" fn(i32, i32, u64, Callback, *mut c_void) -> *mut c_void;
type Update = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32;
type Finish = unsafe extern "C" fn(*mut c_void, *mut Digest) -> i32;
type Free = unsafe extern "C" fn(*mut c_void);
struct Api {
    dump: Dump,
    create: Create,
    update: Update,
    finish: Finish,
    free: Free,
}
macro_rules! ffi {
    ($module:ident,$prefix:literal) => {
        mod $module {
            use super::*;
            unsafe extern "C" {
                #[link_name=concat!($prefix,"dump")]
                pub fn dump(
                    path: *const c_char,
                    level: i32,
                    threads: i32,
                    size: u64,
                    write: Callback,
                    ctx: *mut c_void,
                    out: *mut Digest,
                ) -> i32;
                #[link_name=concat!($prefix,"create")]
                pub fn create(
                    level: i32,
                    threads: i32,
                    size: u64,
                    write: Callback,
                    ctx: *mut c_void,
                ) -> *mut c_void;
                #[link_name=concat!($prefix,"update")]
                pub fn update(ctx: *mut c_void, b: *const u8, len: usize) -> i32;
                #[link_name=concat!($prefix,"finish")]
                pub fn finish(ctx: *mut c_void, out: *mut Digest) -> i32;
                #[link_name=concat!($prefix,"free")]
                pub fn free(ctx: *mut c_void);
            }
            pub const API: Api = Api {
                dump,
                create,
                update,
                finish,
                free,
            };
        }
    };
}
ffi!(portable, "sn_");
ffi!(accelerated, "sn_fast_");
fn api() -> &'static Api {
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
struct Output<'a, W> {
    writer: &'a mut W,
    error: Option<io::Error>,
}
#[cfg_attr(snowstead_hotpath, hotpath::measure)]
unsafe extern "C" fn write<W: Write>(ctx: *mut c_void, b: *const u8, len: usize) -> i32 {
    // The synchronous native call borrows this output for its whole lifetime.
    let output = unsafe { &mut *ctx.cast::<Output<'_, W>>() };
    let bytes = unsafe { std::slice::from_raw_parts(b, len) };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        output.writer.write_all(bytes)
    }))
    .unwrap_or_else(|_| Err(io::Error::other("NAR output callback panicked")));
    if let Err(e) = result {
        output.error = Some(e);
        -1
    } else {
        0
    }
}
struct Compressor {
    ctx: *mut c_void,
    api: &'static Api,
}
impl Drop for Compressor {
    fn drop(&mut self) {
        unsafe { (self.api.free)(self.ctx) }
    }
}
#[cfg_attr(snowstead_hotpath, hotpath::measure)]
pub fn dump<W: Write>(
    path: &Path,
    size: u64,
    level: i32,
    threads: i32,
    writer: &mut W,
) -> anyhow::Result<Digest> {
    let path_c = CString::new(path.as_os_str().as_bytes())?;
    let mut output = Output {
        writer,
        error: None,
    };
    let ctx = (&mut output as *mut Output<'_, W>).cast();
    let mut digest = Digest::default();
    let api = api();
    let rc = unsafe {
        (api.dump)(
            path_c.as_ptr(),
            level,
            threads,
            size,
            write::<W>,
            ctx,
            &mut digest,
        )
    };
    if let Some(e) = output.error.take() {
        return Err(e.into());
    }
    if rc == 0 {
        return Ok(digest);
    }
    if rc != -2 {
        bail!(
            "NAR encoding failed for {} (the store path may have changed or be unreadable)",
            path.display()
        );
    }

    // The native filesystem walker is Linux-only. Other supported systems
    // still use in-process compression and hashing over Nix's NAR stream.
    let mut child = std::process::Command::new("nix-store")
        .arg("--dump")
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("running nix-store --dump")?;
    let result = (|| {
        let ptr = unsafe { (api.create)(level, threads, size, write::<W>, ctx) };
        if ptr.is_null() {
            bail!("creating NAR compressor")
        }
        let compressor = Compressor { ctx: ptr, api };
        let mut buf = vec![0; 1 << 20];
        let mut stdout = child.stdout.take().context("Nix stdout")?;
        loop {
            let n = stdout.read(&mut buf)?;
            if n == 0 {
                break;
            }
            if unsafe { (api.update)(compressor.ctx, buf.as_ptr(), n) } != 0 {
                bail!("compressing NAR")
            }
        }
        if !child.wait()?.success() {
            bail!("nix-store --dump failed")
        }
        if unsafe { (api.finish)(compressor.ctx, &mut digest) } != 0 {
            bail!("finishing NAR compression")
        }
        Ok(digest)
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    if let Some(e) = output.error {
        return Err(e.into());
    }
    result
}

pub struct Compressed {
    pub path: PathBuf,
    pub digest: Digest,
    _directory: tempfile::TempDir,
}
#[cfg_attr(snowstead_hotpath, hotpath::measure)]
pub fn prepare(
    path: &Path,
    size: u64,
    expected: &str,
    level: i32,
    threads: i32,
) -> anyhow::Result<Compressed> {
    let directory = tempfile::Builder::new()
        .prefix("snowstead-nar-")
        .tempdir()?;
    let destination = directory.path().join("nar.zst");
    let mut file = std::fs::File::create(&destination)?;
    let digest = dump(path, size, level, threads, &mut file)?;
    if digest.nar_size != size || Some(digest.nar_hash) != parse_hash(expected) {
        bail!(
            "NAR hash or size differs from the Nix database for {}",
            path.display()
        );
    }
    Ok(Compressed {
        path: destination,
        digest,
        _directory: directory,
    })
}
fn parse_hash(hash: &str) -> Option<[u8; 32]> {
    if let Some(b64) = hash.strip_prefix("sha256-") {
        return base64::engine::general_purpose::STANDARD
            .decode(b64)
            .ok()?
            .try_into()
            .ok();
    }
    let encoded = hash.strip_prefix("sha256:")?;
    if encoded.len() == 64 {
        return hex::decode(encoded).ok()?.try_into().ok();
    }
    if encoded.len() != 52 {
        return None;
    }
    let alphabet = b"0123456789abcdfghijklmnpqrsvwxyz";
    let mut bytes = [0; 32];
    for (i, c) in encoded.bytes().rev().enumerate() {
        let value = alphabet.iter().position(|v| *v == c)? as u16;
        let bit = i * 5;
        if bit == 255 && value > 1 {
            return None;
        }
        bytes[bit / 8] |= (value << (bit % 8)) as u8;
        if bit % 8 > 3 && bit / 8 + 1 < 32 {
            bytes[bit / 8 + 1] |= (value >> (8 - bit % 8)) as u8;
        }
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};
    #[test]
    fn native_frames_match_nix_and_reject_changed_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("small"), b"hello").unwrap();
        std::fs::write(root.join("large"), vec![17; 5 * 1024 * 1024 + 3]).unwrap();
        std::os::unix::fs::symlink("small", root.join("link")).unwrap();
        let reference = std::process::Command::new("nix-store")
            .arg("--dump")
            .arg(&root)
            .output()
            .unwrap();
        assert!(reference.status.success());
        let raw = &reference.stdout;
        let hash = Sha256::digest(raw);
        let expected = format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(hash)
        );
        let spool = prepare(&root, raw.len() as u64, &expected, 3, 0).unwrap();
        let bytes = std::fs::read(&spool.path).unwrap();
        assert_eq!(zstd::stream::decode_all(&bytes[..]).unwrap(), *raw);
        assert_eq!(
            spool.digest.file_hash,
            <[u8; 32]>::from(Sha256::digest(&bytes))
        );
        #[cfg(target_os = "linux")]
        {
            let mut portable_bytes = Vec::new();
            let mut output = Output {
                writer: &mut portable_bytes,
                error: None,
            };
            let mut digest = Digest::default();
            let c = CString::new(root.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe {
                    (portable::API.dump)(
                        c.as_ptr(),
                        3,
                        0,
                        raw.len() as u64,
                        write::<Vec<u8>>,
                        (&mut output as *mut Output<'_, Vec<u8>>).cast(),
                        &mut digest,
                    )
                },
                0
            );
            assert_eq!(bytes, portable_bytes);
        }
        let threaded = prepare(&root, raw.len() as u64, &expected, 3, 2).unwrap();
        let threaded_bytes = std::fs::read(&threaded.path).unwrap();
        assert_eq!(zstd::stream::decode_all(&threaded_bytes[..]).unwrap(), *raw);
        assert_eq!(
            threaded.digest.file_hash,
            <[u8; 32]>::from(Sha256::digest(&threaded_bytes))
        );
        assert!(
            prepare(
                &root,
                raw.len() as u64,
                "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                3,
                2
            )
            .is_err()
        );
        let path = spool.path.clone();
        drop(spool);
        assert!(!path.exists());
    }
}
