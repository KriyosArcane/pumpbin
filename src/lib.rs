pub mod convert;
pub mod error;
pub mod inspect;
pub mod logging;
pub mod modules;
pub mod pack;
pub mod pe;
pub mod plugin;
pub mod plugin_system;
pub mod profile;
pub mod sbom;
pub mod scaffold;
pub mod secret;
pub mod utils;
pub mod plugin_capnp {
    include!("../capnp/plugin_capnp.rs");
}

pub use convert::OutputFormat;
pub use error::{PumpBinError, PumpBinResult};
pub use plugin_system::Pass;
pub use profile::{BuildArtifact, Profile, PROFILE_SCHEMA};
pub use sbom::{Sbom, SBOM_SCHEMA};
pub use secret::SecretBuf;

use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryType {
    Executable,
    DynamicLibrary,
}

impl Display for BinaryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Executable => write!(f, "Exe"),
            Self::DynamicLibrary => write!(f, "Lib"),
        }
    }
}

impl std::str::FromStr for BinaryType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "exe" => Ok(Self::Executable),
            "lib" | "dll" | "so" | "dylib" | "shared" => Ok(Self::DynamicLibrary),
            _ => Err(format!("unknown binary type '{s}'; expected: exe, lib")),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellcodeSaveType {
    #[default]
    Local,
    Remote,
}

impl Display for ShellcodeSaveType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShellcodeSaveType::Local => write!(f, "Local"),
            ShellcodeSaveType::Remote => write!(f, "Remote"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Windows,
    Linux,
    Darwin,
}

impl Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Windows => write!(f, "Windows"),
            Platform::Linux => write!(f, "Linux"),
            Platform::Darwin => write!(f, "Darwin"),
        }
    }
}

impl std::str::FromStr for Platform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "windows" | "win" => Ok(Self::Windows),
            "linux" => Ok(Self::Linux),
            "darwin" | "macos" | "osx" | "mac" => Ok(Self::Darwin),
            _ => Err(format!(
                "unknown platform '{s}'; expected: windows, linux, darwin"
            )),
        }
    }
}
