//! Data types shared across pumpbin (CLI, lib, modules, tests).

use serde::{Deserialize, Serialize};

/// A placeholder-replacement pair returned by `encrypt_shellcode`.
///
/// `holder` must be present as a fixed-length byte sequence in the binary
/// template. PumpBin finds it with memmem and overwrites it with `replace_by`,
/// padded to the holder's length.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Pass {
    pub holder: Vec<u8>,
    pub replace_by: Vec<u8>,
}

impl Pass {
    pub fn holder(&self) -> &[u8] {
        &self.holder
    }
    pub fn replace_by(&self) -> &[u8] {
        &self.replace_by
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EncryptShellcodeOutput {
    pub encrypted: Vec<u8>,
    pub pass: Vec<Pass>,
}

impl EncryptShellcodeOutput {
    pub fn encrypted(&self) -> &[u8] {
        &self.encrypted
    }
    pub fn pass(&self) -> &[Pass] {
        &self.pass
    }
}
