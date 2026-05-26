//! Memory-safe wrappers for shellcode and Pass replacement bytes.
//!
//! v1.1.8 adds [`SecretBuf`] — a `Vec<u8>` wrapper that zeroizes itself on
//! drop and prints `<redacted N bytes>` in `Debug` output instead of the
//! raw bytes. Library code that briefly holds shellcode in memory wraps it
//! in `SecretBuf` so the heap allocation is wiped before the allocator
//! reuses the page.
//!
//! # Scope (intentional)
//!
//! The on-wire serialized form of [`crate::plugin_system::Pass`] still
//! uses `Vec<u8>` because the JSON shape is part of the WASM SDK contract
//! and changing it would break every shipped plugin. `SecretBuf` is an
//! *in-process* safety belt that wipes the host-side allocations once
//! they're no longer needed. The bytes still travel through serde during
//! WASM hook invocation; perfect in-process secrecy would require also
//! patching `serde_json`'s scratch buffers, which is out of scope for the
//! 1.x line.
//!
//! # What zeroize does (and doesn't) buy you
//!
//! Wiping `Vec<u8>` on drop prevents the most common leak vector — the
//! kernel handing the same physical page to another process or to the
//! same process after `free`. It does NOT defeat a debugger attached to
//! the live process, swap-file forensics, or memory dumps captured before
//! the wipe runs. Treat this as a *hygiene* feature, not a containment
//! one.

use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Heap buffer that overwrites itself with zeros on drop.
///
/// Constructible from `Vec<u8>` via `From` or `SecretBuf::new`. Deref'd
/// to `[u8]` so existing call sites that expect a `&[u8]` slice need no
/// change. `Debug` redacts the contents to avoid accidental log leakage
/// even when an `#[instrument]` annotation forgets to `skip()` it.
#[derive(Default, Zeroize, ZeroizeOnDrop, Clone)]
pub struct SecretBuf(Vec<u8>);

impl SecretBuf {
    pub fn new(bytes: Vec<u8>) -> Self {
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
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl From<Vec<u8>> for SecretBuf {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<&[u8]> for SecretBuf {
    fn from(s: &[u8]) -> Self {
        Self(s.to_vec())
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
