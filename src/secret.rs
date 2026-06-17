//! Memory-safe wrappers for shellcode and Pass replacement bytes.
//!
//! [`SecretBuf`] zeroizes itself on drop and prints `<redacted N bytes>`
//! in `Debug` output instead of raw bytes.
//!
//! # Scope (intentional)
//!
//! The on-wire serialized form of [`crate::plugin_system::Pass`] still
//! uses `Vec<u8>` because external modules exchange JSON wire frames.
//! `SecretBuf` is an *in-process* safety belt that wipes host-side
//! allocations once they're no longer needed. The bytes still travel
//! through serde during external module calls.
//!
//! # Memory protection
//!
//! On Unix platforms, `SecretBuf` calls `mlock(2)` on construction to
//! advise the kernel not to swap the buffer to disk. The call is
//! best-effort: it may fail silently due to `RLIMIT_MEMLOCK` or
//! insufficient privileges, in which case the buffer remains usable
//! but is not swap-protected. On Windows (and other non-Unix targets),
//! `mlock` is not attempted; buffer contents may be paged to disk
//! under memory pressure. For high-sensitivity operations on any
//! platform, consider running with swap disabled or on an encrypted
//! swap partition.
//!
//! # Limits
//!
//! Wiping `Vec<u8>` on drop prevents the most common leak vector: the
//! kernel handing the same physical page to another process or to the
//! same process after `free`. It does NOT defeat a debugger attached to
//! the live process, swap-file forensics, or memory dumps captured before
//! the wipe runs. Treat this as a *hygiene* feature, not a containment
//! one.

use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Heap buffer that overwrites itself with zeros on drop.
///
/// Constructible from `Vec<u8>` via `From` or `SecretBuf::new`. Deref'd
/// to `[u8]` so existing call sites that expect a `&[u8]` slice need no
/// change. `Debug` redacts the contents to avoid accidental log leakage
/// even when an `#[instrument]` annotation forgets to `skip()` it.
///
/// On Unix, the backing allocation is `mlock`'d on a best-effort basis
/// to prevent the kernel from swapping it to disk. `munlock` is called
/// in `Drop` before the buffer is zeroized.
#[derive(Default, Zeroize, Clone)]
pub struct SecretBuf(Vec<u8>);

/// Best-effort `mlock`: returns silently on failure or non-Unix platforms.
#[cfg(unix)]
fn try_mlock(buf: &[u8]) {
    if !buf.is_empty() {
        // SAFETY: pointer + len describe a valid, heap-allocated region.
        unsafe { libc::mlock(buf.as_ptr().cast(), buf.len()) };
    }
}

/// Best-effort `munlock`: returns silently on failure or non-Unix platforms.
#[cfg(unix)]
fn try_munlock(buf: &[u8]) {
    if !buf.is_empty() {
        // SAFETY: pointer + len describe a valid, heap-allocated region.
        unsafe { libc::munlock(buf.as_ptr().cast(), buf.len()) };
    }
}

impl SecretBuf {
    pub fn new(bytes: Vec<u8>) -> Self {
        #[cfg(unix)]
        try_mlock(&bytes);
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume self and return the inner `Vec`, **without** zeroizing.
    /// Useful when the bytes must cross a serde boundary; callers should
    /// re-wrap or zeroize the result manually.
    #[deprecated(
        note = "extracts inner Vec without zeroizing; prefer as_ref() or consuming the SecretBuf directly"
    )]
    pub fn into_vec_unzeroized(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl From<Vec<u8>> for SecretBuf {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

impl From<&[u8]> for SecretBuf {
    fn from(s: &[u8]) -> Self {
        Self::new(s.to_vec())
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        #[cfg(unix)]
        try_munlock(&self.0);
        self.0.zeroize();
    }
}

impl Deref for SecretBuf {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted {} bytes>", self.0.len())
    }
}
