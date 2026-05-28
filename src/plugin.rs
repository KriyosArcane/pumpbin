use std::{
    collections::HashMap,
    fs, iter,
    ops::Not,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow;
use bincode::{decode_from_slice, encode_to_vec, Decode, Encode};
use capnp::{
    io::Write,
    message::{self, ReaderOptions},
    serialize_packed,
};
use flate2::Compression;

use crate::{plugin_capnp, utils, BinaryType, Platform, ShellcodeSaveType};

const BINCODE_PLUGINS_CONFIG: bincode::config::Configuration = bincode::config::standard();
pub static CONFIG_FILE_PATH: OnceLock<PathBuf> = OnceLock::new();

#[derive(Debug, Default, Clone)]
pub struct PluginInfo {
    pub plugin_name: String,
    pub author: String,
    pub version: String,
    pub desc: String,
}

impl PluginInfo {
    pub fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    pub fn author(&self) -> &str {
        &self.author
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn desc(&self) -> &str {
        &self.desc
    }
}

#[derive(Debug, Default, Clone)]
pub struct PluginReplace {
    pub src_prefix: Vec<u8>,
    pub size_holder: Option<Vec<u8>>,
    pub max_len: u64,
}

impl PluginReplace {
    pub fn src_prefix(&self) -> &[u8] {
        &self.src_prefix
    }

    pub fn size_holder(&self) -> Option<&Vec<u8>> {
        self.size_holder.as_ref()
    }

    pub fn max_len(&self) -> usize {
        self.max_len as usize
    }

    /// Confirm that a candidate template binary contains every placeholder
    /// this replace-config will look for at generate-time. Used by both the
    /// Maker GUI (preflight before saving a .b1n) and the CLI `create-b1n`
    /// subcommand (preflight before encoding). Pre-1.1.3 the Maker enforced
    /// this and the CLI did not, producing silently-broken .b1n files that
    /// failed only later at `generate` time.
    ///
    /// Local mode requires both `src_prefix` and `size_holder` to be present
    /// in the template. Remote mode only requires `src_prefix` (the URL is
    /// substituted into the same slot at runtime).
    pub fn preflight_template(&self, template: &[u8]) -> anyhow::Result<()> {
        if memchr::memmem::find(template, &self.src_prefix).is_none() {
            return Err(crate::error::PumpBinError::PlaceholderNotFound {
                holder: String::from_utf8_lossy(&self.src_prefix).into_owned(),
            }
            .into());
        }

        // Local mode also needs the size_holder. Remote mode skips it (the
        // URL byte count is unbounded in the placeholder slot).
        if let Some(holder) = &self.size_holder {
            if memchr::memmem::find(template, holder).is_none() {
                return Err(crate::error::PumpBinError::PlaceholderNotFound {
                    holder: String::from_utf8_lossy(holder).into_owned(),
                }
                .into());
            }
        }
        Ok(())
    }

    /// Measure the contiguous run of constant padding bytes that follows
    /// `src_prefix` in `template`. Returns `None` if the prefix isn't
    /// present. Used by `create-b1n` to auto-detect a sensible `max_len`
    /// — the default of 4096 was wrong for ~every real loader, which
    /// allocates 1 MiB+ of placeholder room.
    ///
    /// Algorithm: locate `src_prefix`, read the byte immediately after,
    /// then count how many consecutive copies of that byte follow. Works
    /// regardless of which fill byte the template author chose (`'\0'`,
    /// `'0'`, `0xCC`, etc.) as long as it's a single repeating value.
    pub fn measure_placeholder_capacity(&self, template: &[u8]) -> Option<usize> {
        let prefix_at = memchr::memmem::find(template, &self.src_prefix)?;
        let region_start = prefix_at + self.src_prefix.len();
        let pad = *template.get(region_start)?;
        let mut end = region_start;
        while end < template.len() && template[end] == pad {
            end += 1;
        }
        Some(end - region_start)
    }
}

#[derive(Debug, Default, Clone)]
pub struct Bins {
    pub executable: Option<Vec<u8>>,
    pub dynamic_library: Option<Vec<u8>>,
}

impl Bins {
    pub fn is_platform_supported(&self) -> bool {
        matches!((self.executable(), self.dynamic_library()), (None, None)).not()
    }

    pub fn supported_binary_types(&self) -> Vec<BinaryType> {
        let mut bin_types = Vec::default();
        if self.executable().is_some() {
            bin_types.push(BinaryType::Executable);
        }
        if self.dynamic_library().is_some() {
            bin_types.push(BinaryType::DynamicLibrary);
        }

        bin_types
    }
}

impl Bins {
    pub fn executable(&self) -> Option<&Vec<u8>> {
        self.executable.as_ref()
    }

    pub fn dynamic_library(&self) -> Option<&Vec<u8>> {
        self.dynamic_library.as_ref()
    }

    pub fn executable_mut(&mut self) -> &mut Option<Vec<u8>> {
        &mut self.executable
    }

    pub fn dynamic_library_mut(&mut self) -> &mut Option<Vec<u8>> {
        &mut self.dynamic_library
    }
}

#[derive(Debug, Default, Clone)]
pub struct PluginBins {
    pub windows: Bins,
    pub linux: Bins,
    pub darwin: Bins,
}

impl PluginBins {
    pub fn supported_platforms(&self) -> Vec<Platform> {
        let mut platforms = Vec::default();
        if self.windows().is_platform_supported() {
            platforms.push(Platform::Windows);
        }
        if self.linux().is_platform_supported() {
            platforms.push(Platform::Linux);
        }
        if self.darwin().is_platform_supported() {
            platforms.push(Platform::Darwin);
        }

        platforms
    }

    pub fn get_that_binary(&self, platform: Platform, bin_type: BinaryType) -> Option<Vec<u8>> {
        let platform_bins = match platform {
            Platform::Windows => self.windows(),
            Platform::Linux => self.linux(),
            Platform::Darwin => self.darwin(),
        };

        match bin_type {
            BinaryType::Executable => platform_bins.executable().cloned(),
            BinaryType::DynamicLibrary => platform_bins.dynamic_library().cloned(),
        }
    }
}

impl PluginBins {
    pub fn windows(&self) -> &Bins {
        &self.windows
    }

    pub fn linux(&self) -> &Bins {
        &self.linux
    }

    pub fn darwin(&self) -> &Bins {
        &self.darwin
    }
}

/// Native module references. Each `Option<String>` is the id of a
/// module registered in `crate::modules::*_modules()`. Field types
/// were `Option<Vec<u8>>` (raw .wasm bytes) before v2.0.0; the on-wire
/// capnp `Data` field is reinterpreted as UTF-8 module-id bytes for
/// backward-schema-compat. Old wasm-bearing .b1n files are rejected on
/// decode (non-UTF-8 → clear error).
#[derive(Debug, Default, Clone)]
pub struct PluginPlugins {
    pub encrypt_shellcode: Option<String>,
    pub format_encrypted_shellcode: Option<String>,
    pub format_url_remote: Option<String>,
    pub upload_final_shellcode_remote: Option<String>,
    pub plugin_config: Vec<(String, String)>,
    pub modules: Vec<String>,
}

impl PluginPlugins {
    #[tracing::instrument(skip(self, _runtime_config), fields(path = %path.display(), module = ?self.encrypt_shellcode()))]
    pub fn run_encrypt_shellcode(
        &self,
        path: &Path,
        _runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<crate::plugin_system::EncryptShellcodeOutput> {
        let shellcode = fs::read(path)?;
        if let Some(id) = self.encrypt_shellcode() {
            return crate::modules::dispatch::encrypt(id, &shellcode);
        }
        Ok(crate::plugin_system::EncryptShellcodeOutput {
            encrypted: shellcode,
            ..Default::default()
        })
    }

    #[tracing::instrument(skip(self, shellcode, _runtime_config), fields(shellcode_len = shellcode.len(), module = ?self.format_encrypted_shellcode()))]
    pub fn run_format_encrypted_shellcode(
        &self,
        shellcode: &[u8],
        _runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<crate::plugin_system::FormatEncryptedShellcodeOutput> {
        if let Some(id) = self.format_encrypted_shellcode() {
            let out = crate::modules::dispatch::format_encrypted(id, shellcode)?;
            return Ok(crate::plugin_system::FormatEncryptedShellcodeOutput {
                formatted_shellcode: out.formatted,
            });
        }
        Ok(crate::plugin_system::FormatEncryptedShellcodeOutput {
            formatted_shellcode: shellcode.to_vec(),
        })
    }

    pub fn run_format_url_remote(
        &self,
        url: &str,
        _runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<crate::plugin_system::FormatUrlRemoteOutput> {
        if let Some(id) = self.format_url_remote() {
            let formatted = crate::modules::dispatch::format_url(id, url)?;
            return Ok(crate::plugin_system::FormatUrlRemoteOutput {
                formatted_url: formatted,
            });
        }
        Ok(crate::plugin_system::FormatUrlRemoteOutput {
            formatted_url: url.to_string(),
        })
    }

    pub fn run_upload_final_shellcode_remote(
        &self,
        final_shellcode: &[u8],
        _runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<crate::plugin_system::UploadFinalShellcodeRemoteOutput> {
        if let Some(id) = self.upload_final_shellcode_remote() {
            let url = crate::modules::dispatch::upload_remote(id, final_shellcode)?;
            return Ok(crate::plugin_system::UploadFinalShellcodeRemoteOutput {
                final_shellcode_url: url,
            });
        }
        Ok(crate::plugin_system::UploadFinalShellcodeRemoteOutput::default())
    }

    /// Run all `post_binary` hooks: WASM modules are chained in order, then
    /// Chain every post_binary module in order, returning the final bytes.
    ///
    /// Pre-1.1.2 this method also ran a host-side `host_self_sign` path that
    /// generated an ephemeral self-signed RSA cert on every build and shelled
    /// out to `openssl` + `osslsigncode`. That path was deleted because (1) a
    /// fresh per-build cert pollutes operator OPSEC with a unique signer
    /// identity, (2) the cert never chained to a real CA so it added no trust
    /// value, and (3) embedding a signing tool inside the core forced
    /// `openssl`/`osslsigncode` as hard host dependencies. Signing now lives in
    /// dedicated post_binary plugins (osslsigncode, signtool, blob-steal)
    /// shipped under `plugin-examples/signers/` from v1.2.0.
    /// Run every module id listed in `self.modules()` as a `PostBuildModule`
    /// in order. Each step mutates `binary` in place; the per-module
    /// argument vector is taken from `runtime_config["post:<id>"]`
    /// when present (semicolon-separated `key=value` list); otherwise
    /// the module gets zero args.
    #[tracing::instrument(skip(self, binary, runtime_config), fields(binary_len = binary.len(), modules_count = self.modules().len()))]
    pub fn run_post_binary(
        &self,
        binary: Vec<u8>,
        runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<Vec<u8>> {
        let mut out = binary;
        for id in self.modules() {
            let args: Vec<String> = runtime_config
                .and_then(|cfg| cfg.get(&format!("post:{id}")))
                .map(|s| s.split(';').filter(|p| !p.is_empty()).map(String::from).collect())
                .unwrap_or_default();
            crate::modules::dispatch::post_build(id, &args, &mut out)?;
        }
        Ok(out)
    }
}

impl PluginPlugins {
    pub fn encrypt_shellcode(&self) -> Option<&str> {
        self.encrypt_shellcode.as_deref()
    }

    pub fn format_encrypted_shellcode(&self) -> Option<&str> {
        self.format_encrypted_shellcode.as_deref()
    }

    pub fn format_url_remote(&self) -> Option<&str> {
        self.format_url_remote.as_deref()
    }

    pub fn upload_final_shellcode_remote(&self) -> Option<&str> {
        self.upload_final_shellcode_remote.as_deref()
    }

    pub fn plugin_config(&self) -> &[(String, String)] {
        &self.plugin_config
    }

    pub fn plugin_config_mut(&mut self) -> &mut Vec<(String, String)> {
        &mut self.plugin_config
    }

    pub fn encrypt_shellcode_mut(&mut self) -> &mut Option<String> {
        &mut self.encrypt_shellcode
    }

    pub fn format_encrypted_shellcode_mut(&mut self) -> &mut Option<String> {
        &mut self.format_encrypted_shellcode
    }

    pub fn format_url_remote_mut(&mut self) -> &mut Option<String> {
        &mut self.format_url_remote
    }

    pub fn upload_final_shellcode_remote_mut(&mut self) -> &mut Option<String> {
        &mut self.upload_final_shellcode_remote
    }

    pub fn modules(&self) -> &[String] {
        &self.modules
    }

    pub fn modules_mut(&mut self) -> &mut Vec<String> {
        &mut self.modules
    }
}

#[derive(Debug, Default, Clone)]
pub struct Plugin {
    pub version: String,
    pub info: PluginInfo,
    pub replace: PluginReplace,
    pub bins: PluginBins,
    pub plugins: PluginPlugins,
}

impl Plugin {
    pub fn decode_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        let mut decoder = flate2::write::ZlibDecoder::new(Vec::new());
        decoder.write_all(data)?;
        let decompressed = decoder.finish()?;

        let message =
            serialize_packed::read_message(decompressed.as_slice(), ReaderOptions::new())?;
        let plugin = message.get_root::<plugin_capnp::plugin::Reader>()?;

        let info = plugin.get_info()?;
        let replace = plugin.get_replace()?;
        let bins = plugin.get_bins()?;
        let plugins = plugin.get_plugins()?;

        let check_empty = |bin: &[u8]| {
            if bin.is_empty() {
                None
            } else {
                Some(bin.to_vec())
            }
        };

        fn bytes_to_module_id(bin: &[u8], slot: &str) -> anyhow::Result<Option<String>> {
            if bin.is_empty() {
                return Ok(None);
            }
            let id = std::str::from_utf8(bin).map_err(|_| {
                anyhow::anyhow!(
                    "plugin slot '{slot}' is not a valid UTF-8 module id. \
                     Pre-2.0 .b1n files with embedded WASM are not supported."
                )
            })?;
            Ok(Some(id.to_string()))
        }

        Ok(Self {
            version: plugin.get_version()?.to_string()?,
            info: PluginInfo {
                plugin_name: info.get_plugin_name()?.to_string()?,
                author: info.get_author()?.to_string()?,
                version: info.get_version()?.to_string()?,
                desc: info.get_desc()?.to_string()?,
            },
            replace: PluginReplace {
                src_prefix: replace.get_src_prefix()?.to_vec(),
                size_holder: check_empty(replace.get_size_holder()?),
                max_len: replace.get_max_len(),
            },
            bins: PluginBins {
                windows: {
                    let platform_bins = bins.get_windows()?;
                    Bins {
                        executable: check_empty(platform_bins.get_executable()?),
                        dynamic_library: check_empty(platform_bins.get_dynamic_library()?),
                    }
                },
                linux: {
                    let platform_bins = bins.get_linux()?;
                    Bins {
                        executable: check_empty(platform_bins.get_executable()?),
                        dynamic_library: check_empty(platform_bins.get_dynamic_library()?),
                    }
                },
                darwin: {
                    let platform_bins = bins.get_darwin()?;
                    Bins {
                        executable: check_empty(platform_bins.get_executable()?),
                        dynamic_library: check_empty(platform_bins.get_dynamic_library()?),
                    }
                },
            },
            plugins: PluginPlugins {
                encrypt_shellcode: bytes_to_module_id(
                    plugins.get_encrypt_shellcode()?,
                    "encrypt_shellcode",
                )?,
                format_encrypted_shellcode: bytes_to_module_id(
                    plugins.get_format_encrypted_shellcode()?,
                    "format_encrypted_shellcode",
                )?,
                format_url_remote: bytes_to_module_id(
                    plugins.get_format_url_remote()?,
                    "format_url_remote",
                )?,
                upload_final_shellcode_remote: bytes_to_module_id(
                    plugins.get_upload_final_shellcode_remote()?,
                    "upload_final_shellcode_remote",
                )?,
                plugin_config: {
                    let entries = plugins.get_config_entries()?;
                    let mut config = Vec::new();
                    for entry in entries {
                        config.push((
                            entry.get_key()?.to_string()?,
                            entry.get_value()?.to_string()?,
                        ));
                    }
                    config
                },
                modules: {
                    let mods = plugins.get_modules()?;
                    let mut decoded = Vec::new();
                    for (idx, m) in mods.into_iter().enumerate() {
                        let raw = m?;
                        let id = std::str::from_utf8(raw).map_err(|_| {
                            anyhow::anyhow!(
                                "modules[{idx}] is not a valid UTF-8 module id. Pre-2.0 .b1n files with embedded WASM are not supported."
                            )
                        })?;
                        decoded.push(id.to_string());
                    }
                    decoded
                },
            },
        })
    }

    pub fn encode_to_vec(&self) -> anyhow::Result<Vec<u8>> {
        let mut message = message::Builder::new_default();
        let mut plugin = message.init_root::<plugin_capnp::plugin::Builder>();
        plugin.set_version(self.version());

        let mut info = plugin.reborrow().init_info();
        let plugin_info = self.info();
        info.set_plugin_name(plugin_info.plugin_name());
        info.set_author(plugin_info.author());
        info.set_version(plugin_info.version());
        info.set_desc(plugin_info.desc());

        let mut replace = plugin.reborrow().init_replace();
        let plugin_replace = self.replace();
        replace.set_src_prefix(plugin_replace.src_prefix());
        if let Some(size_holder) = plugin_replace.size_holder() {
            replace.set_size_holder(size_holder);
        }
        replace.set_max_len(plugin_replace.max_len() as u64);

        let mut bins = plugin.reborrow().init_bins();
        if self.bins().windows().is_platform_supported() {
            let mut builder = bins.reborrow().init_windows();
            let platform_bins = self.bins().windows();

            if let Some(bin) = platform_bins.executable() {
                builder.set_executable(bin);
            }
            if let Some(bin) = platform_bins.dynamic_library() {
                builder.set_dynamic_library(bin);
            }
        }
        if self.bins().linux().is_platform_supported() {
            let mut builder = bins.reborrow().init_linux();
            let platform_bins = self.bins().linux();

            if let Some(bin) = platform_bins.executable() {
                builder.set_executable(bin);
            }
            if let Some(bin) = platform_bins.dynamic_library() {
                builder.set_dynamic_library(bin);
            }
        }
        if self.bins().darwin().is_platform_supported() {
            let mut builder = bins.reborrow().init_darwin();
            let platform_bins = self.bins().darwin();

            if let Some(bin) = platform_bins.executable() {
                builder.set_executable(bin);
            }
            if let Some(bin) = platform_bins.dynamic_library() {
                builder.set_dynamic_library(bin);
            }
        }

        let mut plugins = plugin.reborrow().init_plugins();
        let plugin_plugins = self.plugins();
        if let Some(id) = plugin_plugins.encrypt_shellcode() {
            plugins.set_encrypt_shellcode(id.as_bytes());
        }
        if let Some(id) = plugin_plugins.format_encrypted_shellcode() {
            plugins.set_format_encrypted_shellcode(id.as_bytes());
        }
        if let Some(id) = plugin_plugins.format_url_remote() {
            plugins.set_format_url_remote(id.as_bytes());
        }
        if let Some(id) = plugin_plugins.upload_final_shellcode_remote() {
            plugins.set_upload_final_shellcode_remote(id.as_bytes());
        }

        let config = plugin_plugins.plugin_config();
        if !config.is_empty() {
            let mut entries = plugins.reborrow().init_config_entries(config.len() as u32);
            for (i, (k, v)) in config.iter().enumerate() {
                let mut entry = entries.reborrow().get(i as u32);
                entry.set_key(k);
                entry.set_value(v);
            }
        }

        let mods = plugin_plugins.modules();
        if !mods.is_empty() {
            let mut modules_list = plugins.reborrow().init_modules(mods.len() as u32);
            for (i, m) in mods.iter().enumerate() {
                modules_list.set(i as u32, m.as_bytes());
            }
        }

        let mut buf = Vec::new();
        serialize_packed::write_message(&mut buf, &message)?;

        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(buf.as_slice())?;
        let compressed = encoder.finish()?;

        anyhow::Ok(compressed)
    }

    pub fn save_type(&self) -> ShellcodeSaveType {
        if self.replace().size_holder().is_some() {
            ShellcodeSaveType::Local
        } else {
            ShellcodeSaveType::Remote
        }
    }

    /// `shellcode_src` is skipped because for Local mode it's a path that
    /// may identify the operator's working directory; for Remote mode it
    /// may be an attacker-controlled URL. The save_type and any failure
    /// reason still surface via the returned error.
    #[tracing::instrument(skip(self, shellcode_src), fields(plugin = %self.info().plugin_name(), save_type = ?self.save_type()))]
    pub fn validate_shellcode_source(&self, shellcode_src: &str) -> anyhow::Result<()> {
        use crate::error::PumpBinError;

        if shellcode_src.trim().is_empty() {
            return Err(PumpBinError::ShellcodeSourceEmpty.into());
        }

        match self.save_type() {
            ShellcodeSaveType::Local => {
                let path = Path::new(shellcode_src);
                if path.exists().not() {
                    return Err(PumpBinError::ShellcodeFileNotFound {
                        path: shellcode_src.to_string(),
                    }
                    .into());
                }

                // Wrap the read in SecretBuf so the heap bytes are zeroized
                // when this scope exits — even on the success path where we
                // only used the bytes to check for the placeholder marker.
                let data: crate::secret::SecretBuf = fs::read(path)
                    .map_err(|source| PumpBinError::ShellcodeReadFailed {
                        path: shellcode_src.to_string(),
                        source,
                    })?
                    .into();

                if data.is_empty() {
                    return Err(PumpBinError::ShellcodeFileEmpty {
                        path: shellcode_src.to_string(),
                    }
                    .into());
                }

                if data
                    .windows(b"$$SHELLCODE$$".len())
                    .any(|w| w == b"$$SHELLCODE$$")
                {
                    return Err(PumpBinError::ShellcodeContainsPlaceholder {
                        path: shellcode_src.to_string(),
                    }
                    .into());
                }
            }
            ShellcodeSaveType::Remote => {
                if shellcode_src.starts_with("http://").not()
                    && shellcode_src.starts_with("https://").not()
                {
                    return Err(PumpBinError::RemoteUrlInvalidScheme {
                        url: shellcode_src.to_string(),
                    }
                    .into());
                }
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self), fields(plugin = %self.info().plugin_name()))]
    pub fn validate_for_generation(
        &self,
        platform: Platform,
        bin_type: BinaryType,
    ) -> anyhow::Result<()> {
        use crate::error::PumpBinError;

        let save_type = self.save_type();

        let platform_bins = match platform {
            Platform::Windows => self.bins().windows(),
            Platform::Linux => self.bins().linux(),
            Platform::Darwin => self.bins().darwin(),
        };

        let binary_exists = match bin_type {
            BinaryType::Executable => platform_bins.executable().is_some(),
            BinaryType::DynamicLibrary => platform_bins.dynamic_library().is_some(),
        };

        if !binary_exists {
            return Err(PumpBinError::BinaryNotInPlugin {
                platform: platform.to_string(),
                bin_type: bin_type.to_string(),
            }
            .into());
        }

        if save_type == ShellcodeSaveType::Local && self.replace().size_holder().is_none() {
            return Err(PumpBinError::LocalRequiresSizeHolder.into());
        }

        if self.replace().max_len() == 0 {
            return Err(PumpBinError::MaxLenZero.into());
        }

        Ok(())
    }

    /// Inject shellcode into a binary template and run all post-processing modules.
    ///
    /// Takes ownership of `bin` so that `post_binary` modules can resize it,
    /// and returns the fully-processed binary bytes.
    ///
    /// `#[instrument]`: every shellcode/secret argument is in `skip(...)` to
    /// keep the JSON log file free of shellcode bytes, Pass holder/replace
    /// values, and runtime config (which often contains keys/passwords).
    /// Only metadata that's safe to leak — plugin name, save_type, binary
    /// length — is logged.
    #[tracing::instrument(
        skip(self, bin, shellcode_src, pass, runtime_config),
        fields(
            plugin = %self.info().plugin_name(),
            bin_len = bin.len(),
            pass_count = pass.len(),
        ),
    )]
    pub fn replace_binary(
        &self,
        mut bin: Vec<u8>,
        shellcode_src: String,
        mut pass: Vec<crate::plugin_system::Pass>,
        runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<Vec<u8>> {
        let save_type = self.save_type();

        // Resolve and process shellcode source
        let shellcode_bytes = match save_type {
            ShellcodeSaveType::Local => {
                let path = Path::new(&shellcode_src);
                let output = self.plugins().run_encrypt_shellcode(path, runtime_config)?;

                // Merge plugin-supplied Pass entries with caller-supplied ones.
                // Policy: caller wins on holder collision. Rationale: an operator
                // who pre-encrypted in the GUI and passed the resulting Pass list
                // has already committed to specific replacement bytes; re-running
                // encrypt_shellcode would generate a fresh key and silently
                // invalidate their plaintext shellcode. (Pre-1.1.2 this method
                // unconditionally clobbered `pass` with plugin output, dropping
                // any caller-supplied entries.)
                let caller_holders: std::collections::HashSet<Vec<u8>> =
                    pass.iter().map(|p| p.holder.clone()).collect();
                for p in output.pass() {
                    if !caller_holders.contains(&p.holder) {
                        pass.push(p.clone());
                    }
                }

                let final_shellcode = self
                    .plugins()
                    .run_format_encrypted_shellcode(output.encrypted(), runtime_config)?;

                final_shellcode.formatted_shellcode().to_vec()
            }
            ShellcodeSaveType::Remote => {
                let mut src = self
                    .plugins()
                    .run_format_url_remote(&shellcode_src, runtime_config)?
                    .formatted_url()
                    .as_bytes()
                    .to_vec();
                src.push(b'\0');
                src
            }
        };

        if shellcode_bytes.len() > self.replace().max_len() {
            return Err(crate::error::PumpBinError::ShellcodeTooLong {
                kind: match save_type {
                    ShellcodeSaveType::Local => "Shellcode",
                    ShellcodeSaveType::Remote => "Shellcode URL",
                },
                got: shellcode_bytes.len(),
                max: self.replace().max_len(),
            }
            .into());
        }

        utils::replace(
            &mut bin,
            self.replace().src_prefix(),
            shellcode_bytes.as_slice(),
            self.replace().max_len(),
        )?;

        // Apply Pass replacements (encryption keys, nonces, etc.)
        for p in pass {
            utils::replace(&mut bin, p.holder(), p.replace_by(), p.holder().len())?;
        }

        // Embed shellcode byte-count for local loaders.
        //
        // Two encoding modes, distinguished implicitly by the holder
        // length:
        //   - 4-byte holder: binary u32 little-endian length. Used by
        //     scaffolded PIC loaders to skip the decimal-parse code
        //     path (no core::fmt drag-in). Caps at u32::MAX shellcode
        //     bytes — way past PumpBin's max_len limits anyway.
        //   - any other length: ASCII decimal, left-padded with '0' to
        //     fill the holder slot (e.g. "000000158" in a 9-byte
        //     holder). The historical mode; matches the
        //     `$$99999$$` default and what every existing loader
        //     template parses.
        if save_type == ShellcodeSaveType::Local {
            let size_holder = self.replace().size_holder().unwrap();
            let size_bytes: Vec<u8> = if size_holder.len() == 4 {
                let len = u32::try_from(shellcode_bytes.len()).map_err(|_| {
                    crate::error::PumpBinError::SizeStringTooLong {
                        got: 5,
                        holder_len: 4,
                    }
                })?;
                len.to_le_bytes().to_vec()
            } else {
                let len_str = shellcode_bytes.len().to_string();
                let len_bytes = len_str.as_bytes();
                if len_bytes.len() > size_holder.len() {
                    return Err(crate::error::PumpBinError::SizeStringTooLong {
                        got: len_bytes.len(),
                        holder_len: size_holder.len(),
                    }
                    .into());
                }
                let mut v: Vec<u8> =
                    iter::repeat_n(b'0', size_holder.len() - len_bytes.len()).collect();
                v.extend_from_slice(len_bytes);
                v
            };

            utils::replace(
                &mut bin,
                size_holder,
                size_bytes.as_slice(),
                size_holder.len(),
            )?;
        }

        // Run post_binary modules (signing, obfuscation, etc.)
        bin = self.plugins().run_post_binary(bin, runtime_config)?;

        // Recompute PE CheckSum if this output is a PE. Without this,
        // every stamped EXE keeps the template's stale CheckSum, which
        // (a) makes `pumpbin-cli verify` fail on PumpBin's own output,
        // (b) is a strong tamper signal for stock Windows tooling and
        // AV. No-op for non-PE outputs (ELF, Mach-O).
        utils::recompute_pe_checksum(&mut bin);

        Ok(bin)
    }
}

impl Plugin {
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn info(&self) -> &PluginInfo {
        &self.info
    }

    pub fn replace(&self) -> &PluginReplace {
        &self.replace
    }

    pub fn bins(&self) -> &PluginBins {
        &self.bins
    }

    pub fn plugins(&self) -> &PluginPlugins {
        &self.plugins
    }
}

#[derive(Debug, Clone, Default, Encode, Decode, PartialEq, Eq)]
pub struct Plugins(HashMap<String, Vec<u8>>);

impl Plugins {
    pub fn read_plugins() -> anyhow::Result<Plugins> {
        let plugins_path =
            CONFIG_FILE_PATH
                .get()
                .ok_or(crate::error::PumpBinError::ConfigPathUnavailable {
                    what: "CONFIG_FILE_PATH was never initialized",
                })?;

        let buf = fs::read(plugins_path)?;
        let (plugins, _) = decode_from_slice(buf.as_slice(), BINCODE_PLUGINS_CONFIG)?;
        Ok(plugins)
    }

    pub fn update_plugins(&self) -> anyhow::Result<()> {
        let buf = encode_to_vec(self, BINCODE_PLUGINS_CONFIG)?;
        let plugins_path =
            CONFIG_FILE_PATH
                .get()
                .ok_or(crate::error::PumpBinError::ConfigPathUnavailable {
                    what: "CONFIG_FILE_PATH was never initialized",
                })?;

        if plugins_path.is_dir() {
            fs::remove_dir(plugins_path)?;
        }

        utils::atomic_write(plugins_path, &buf)?;

        Ok(())
    }

    pub fn get(&self, name: &str) -> anyhow::Result<Plugin> {
        let buf = self
            .0
            .get(name)
            .ok_or_else(|| crate::error::PumpBinError::PluginNotFound {
                name: name.to_string(),
            })?;

        Plugin::decode_from_slice(buf)
    }

    pub fn get_sorted_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.0.keys().map(|x| x.to_owned()).collect();
        names.sort();
        names
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn insert(&mut self, name: String, plugin: Vec<u8>) {
        self.0.insert(name, plugin);
    }

    pub fn remove(&mut self, name: &str) {
        self.0.remove(name);
    }
}
