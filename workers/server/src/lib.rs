#![cfg_attr(feature = "profiling", recursion_limit = "256")]

// Pair hotpath's lifecycle counters with its inclusive wall-time measurements:
// future poll time alone excludes SQL/pool/lock waits, and a handler returning
// a streaming body does not measure that body's subsequent lifetime.
#[cfg(feature = "profiling")]
pub(crate) use hotpath::measure_block as profile_block;
macro_rules! profile_future {
    ($value:expr, label = $label:literal) => {{
        let value = $value;
        #[cfg(feature = "observability")]
        let value = crate::observability::future(value, $label);
        #[cfg(feature = "profiling")]
        let value = Box::pin(hotpath::functions::measure_async(
            $label,
            hotpath::future!(value, label = $label),
        ));
        value
    }};
}
macro_rules! profile_stream {
    ($value:expr, label = $label:literal) => {{
        let value = $value;
        #[cfg(feature = "observability")]
        let value = crate::observability::stream(value, $label);
        #[cfg(feature = "profiling")]
        let guard = hotpath::functions::build_measurement_guard_block($label, false);
        #[cfg(feature = "profiling")]
        let value = hotpath::stream!(
            futures_util::StreamExt::map(value, move |item| {
                let _ = &guard;
                item
            }),
            label = $label
        );
        value
    }};
}
pub(crate) use {profile_future, profile_stream};
// Disabled builds expand to the original expression, not even evaluating a label.
#[cfg(not(feature = "profiling"))]
macro_rules! profile_block {
    ($label:literal, $value:expr) => {
        $value
    };
}
#[cfg(not(feature = "profiling"))]
pub(crate) use profile_block;

mod app;
mod artifacts;
pub mod auth;
mod bandwidth;
mod cache_host;
mod capacity;
mod cdn;
pub mod config;
mod db;
pub mod error;
mod go;
mod maintenance;
mod management;
mod management_auth;
mod management_policy;
pub mod migrations;
mod native;
mod nix;
#[cfg(feature = "observability")]
pub mod observability;
mod protocol_policy;
mod push_job_worker;
mod push_jobs;
mod reads;
mod sccache;
pub mod signing;
mod signing_management;
pub mod storage;
mod uploads;

pub use app::{AppState, router, serve};

/// Owns the process-wide native profiler. Create once, before native work,
/// and drop only after requests and background jobs have drained.
#[cfg(feature = "profiling")]
pub struct NativeProfile {
    _private: (),
}

#[cfg(feature = "profiling")]
impl NativeProfile {
    /// The caller must ensure there is only one active profiling session.
    ///
    /// # Safety
    /// No other session may be starting, finishing, or running native work
    /// during construction. All native work must end before this is dropped.
    pub unsafe fn start() -> Self {
        // SAFETY: guaranteed by the caller. Select the same CPU-safe archive
        // used by verification so its allocator and timing zones are tracked.
        unsafe { (native::api().profile_start)() };
        Self { _private: () }
    }
}

#[cfg(feature = "profiling")]
impl Drop for NativeProfile {
    fn drop(&mut self) {
        // SAFETY: the owner drains native work before dropping this session.
        unsafe { (native::api().profile_finish)() };
    }
}
