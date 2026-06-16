use std::{collections::BTreeMap, fs, iter, ops::Not, path::Path};

use anyhow;
use capnp::{
    io::Write,
    message::{self, ReaderOptions},
    serialize_packed,
};
use flate2::Compression;

use crate::{plugin_capnp, utils, BinaryType, Platform, ShellcodeSaveType};

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
    /// this replace-config will look for at generate-time. Used by the CLI
    /// `create-b1n` subcommand before encoding so broken .b1n files fail
    /// before `generate` time.
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

    pub fn get_that_binary(&self, platform: Platform, bin_type: BinaryType) -> Option<&[u8]> {
        let platform_bins = match platform {
            Platform::Windows => self.windows(),
            Platform::Linux => self.linux(),
            Platform::Darwin => self.darwin(),
        };

        match bin_type {
            BinaryType::Executable => platform_bins.executable().map(|v| v.as_slice()),
            BinaryType::DynamicLibrary => platform_bins.dynamic_library().map(|v| v.as_slice()),
        }
    }

    pub fn has_binary(&self, platform: Platform, bin_type: BinaryType) -> bool {
        let platform_bins = match platform {
            Platform::Windows => self.windows(),
            Platform::Linux => self.linux(),
            Platform::Darwin => self.darwin(),
        };
        match bin_type {
            BinaryType::Executable => platform_bins.executable().is_some(),
            BinaryType::DynamicLibrary => platform_bins.dynamic_library().is_some(),
        }
    }

    /// Pick a (platform, binary_type) pair to generate against.
    ///
    /// - If a caller passes both `platform` and `binary_type`, those win
    ///   (subject to that slot actually being populated).
    /// - If only one side is given, the other auto-resolves against the
    ///   populated slots that match it.
    /// - If neither is given and exactly one slot is populated, pick it.
    /// - On ambiguity (multiple candidates with no narrowing), fall back
    ///   to the priority order: windows/exe, windows/lib, linux/exe,
    ///   linux/lib, darwin/exe, darwin/lib.
    pub fn auto_select_target(
        &self,
        platform: Option<Platform>,
        binary_type: Option<BinaryType>,
    ) -> anyhow::Result<(Platform, BinaryType)> {
        // (platform, binary_type) in fallback-priority order.
        const PRIORITY: &[(Platform, BinaryType)] = &[
            (Platform::Windows, BinaryType::Executable),
            (Platform::Windows, BinaryType::DynamicLibrary),
            (Platform::Linux, BinaryType::Executable),
            (Platform::Linux, BinaryType::DynamicLibrary),
            (Platform::Darwin, BinaryType::Executable),
            (Platform::Darwin, BinaryType::DynamicLibrary),
        ];

        // Populated slots that survive the caller-supplied filters.
        let candidates: Vec<(Platform, BinaryType)> = PRIORITY
            .iter()
            .copied()
            .filter(|(p, _)| platform.is_none_or(|want| *p == want))
            .filter(|(_, b)| binary_type.is_none_or(|want| *b == want))
            .filter(|(p, b)| self.has_binary(*p, *b))
            .collect();

        match candidates.as_slice() {
            [] => {
                // Help the operator: list what the .b1n actually has.
                let available: Vec<String> = PRIORITY
                    .iter()
                    .filter(|(p, b)| self.has_binary(*p, *b))
                    .map(|(p, b)| {
                        let bt = match b {
                            BinaryType::Executable => "exe",
                            BinaryType::DynamicLibrary => "lib",
                        };
                        format!("{}/{}", p.to_string().to_lowercase(), bt)
                    })
                    .collect();
                if available.is_empty() {
                    anyhow::bail!("this .b1n has no populated binary slots");
                } else {
                    anyhow::bail!(
                        "no slot matches the requested platform/type filter; available slots: {}",
                        available.join(", ")
                    );
                }
            }
            // Exactly one: unambiguous; this is the truly auto-detected case.
            [only] => Ok(*only),
            // Multiple candidates: pick the first by priority order.
            many => Ok(many[0]),
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
    pub fn validate_module_config(
        &self,
        runtime_config: Option<&BTreeMap<String, String>>,
    ) -> anyhow::Result<()> {
        let config = self.merged_runtime_config(runtime_config);

        if let Some(id) = self.encrypt_shellcode() {
            let args = module_config_args(&config, id);
            crate::modules::dispatch::validate_args_only(
                crate::modules::ModuleKind::Encrypt,
                id,
                &args,
            )?;
        }
        if let Some(id) = self.format_encrypted_shellcode() {
            let args = module_config_args(&config, id);
            crate::modules::dispatch::validate_args_only(
                crate::modules::ModuleKind::FormatEncrypted,
                id,
                &args,
            )?;
        }
        if let Some(id) = self.format_url_remote() {
            let args = module_config_args(&config, id);
            crate::modules::dispatch::validate_args_only(
                crate::modules::ModuleKind::FormatUrl,
                id,
                &args,
            )?;
        }
        if let Some(id) = self.upload_final_shellcode_remote() {
            let args = module_config_args(&config, id);
            crate::modules::dispatch::validate_args_only(
                crate::modules::ModuleKind::UploadRemote,
                id,
                &args,
            )?;
        }
        for (idx, id) in self.modules().iter().enumerate() {
            let mut args = post_chain_config_args(&config, idx);
            if args.is_empty() {
                args = config
                    .get(&format!("post:{id}"))
                    .map(|s| split_stored_post_args(s))
                    .unwrap_or_default();
            }
            crate::modules::dispatch::validate_args_only(
                crate::modules::ModuleKind::PostBuild,
                id,
                &args,
            )?;
        }

        Ok(())
    }

    #[tracing::instrument(skip(self, runtime_config), fields(path = %path.display(), module = ?self.encrypt_shellcode()))]
    pub fn run_encrypt_shellcode(
        &self,
        path: &Path,
        runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<crate::plugin_system::EncryptShellcodeOutput> {
        let shellcode = fs::read(path)?;
        if let Some(id) = self.encrypt_shellcode() {
            let config = self.merged_runtime_config(runtime_config);
            let args = module_config_args(&config, id);
            return crate::modules::dispatch::encrypt(id, &args, &shellcode);
        }
        Ok(crate::plugin_system::EncryptShellcodeOutput {
            encrypted: shellcode,
            ..Default::default()
        })
    }

    #[tracing::instrument(skip(self, shellcode, runtime_config), fields(shellcode_len = shellcode.len(), module = ?self.format_encrypted_shellcode()))]
    pub fn run_format_encrypted_shellcode(
        &self,
        shellcode: &[u8],
        runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<(
        crate::plugin_system::FormatEncryptedShellcodeOutput,
        Vec<crate::plugin_system::Pass>,
    )> {
        if let Some(id) = self.format_encrypted_shellcode() {
            let config = self.merged_runtime_config(runtime_config);
            let args = module_config_args(&config, id);
            let out = crate::modules::dispatch::format_encrypted(id, &args, shellcode)?;
            return Ok((
                crate::plugin_system::FormatEncryptedShellcodeOutput {
                    formatted_shellcode: out.formatted,
                },
                out.pass,
            ));
        }
        Ok((
            crate::plugin_system::FormatEncryptedShellcodeOutput {
                formatted_shellcode: shellcode.to_vec(),
            },
            vec![],
        ))
    }

    pub fn run_format_url_remote(
        &self,
        url: &str,
        runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<crate::plugin_system::FormatUrlRemoteOutput> {
        if let Some(id) = self.format_url_remote() {
            let config = self.merged_runtime_config(runtime_config);
            let args = module_config_args(&config, id);
            let formatted = crate::modules::dispatch::format_url(id, &args, url)?;
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
        runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<crate::plugin_system::UploadFinalShellcodeRemoteOutput> {
        if let Some(id) = self.upload_final_shellcode_remote() {
            let config = self.merged_runtime_config(runtime_config);
            let args = module_config_args(&config, id);
            let url = crate::modules::dispatch::upload_remote(id, &args, final_shellcode)?;
            return Ok(crate::plugin_system::UploadFinalShellcodeRemoteOutput {
                final_shellcode_url: url,
            });
        }
        Ok(crate::plugin_system::UploadFinalShellcodeRemoteOutput::default())
    }

    /// Chain every post_binary module in order, returning the final bytes.
    ///
    /// Pre-1.1.2 this method also ran a host-side `host_self_sign` path that
    /// generated an ephemeral self-signed RSA cert on every build and shelled
    /// out to `openssl` + `osslsigncode`. That path was deleted because (1) a
    /// fresh per-build cert creates a unique signer identity, (2) the cert
    /// never chained to a real CA so it added no trust
    /// value, and (3) embedding a signing tool inside the core forced
    /// `openssl`/`osslsigncode` as hard host dependencies. Signing now lives in
    /// dedicated post_binary plugins (osslsigncode, signtool, blob-steal)
    /// shipped under `plugin-examples/signers/` from v1.2.0.
    /// Run every module id listed in `self.modules()` as a `PostBuildModule`
    /// in order. Each step mutates `binary` in place. Per-module args come
    /// from baked `post_chain.<idx>.config.<key>` entries first, with
    /// runtime `post:<id>` entries used for operator-appended modules.
    #[tracing::instrument(skip(self, binary, runtime_config), fields(binary_len = binary.len(), modules_count = self.modules().len()))]
    pub fn run_post_binary(
        &self,
        binary: Vec<u8>,
        runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<Vec<u8>> {
        let mut out = binary;
        let config = self.merged_runtime_config(runtime_config);
        for (idx, id) in self.modules().iter().enumerate() {
            let mut args = post_chain_config_args(&config, idx);
            if args.is_empty() {
                args = config
                    .get(&format!("post:{id}"))
                    .map(|s| split_stored_post_args(s))
                    .unwrap_or_default();
            }
            crate::modules::dispatch::post_build(id, &args, &mut out)?;
        }
        Ok(out)
    }

    fn merged_runtime_config(
        &self,
        runtime_config: Option<&BTreeMap<String, String>>,
    ) -> BTreeMap<String, String> {
        let mut config: BTreeMap<String, String> = self.plugin_config().iter().cloned().collect();
        if let Some(runtime_config) = runtime_config {
            for (key, value) in runtime_config {
                config.insert(key.clone(), value.clone());
            }
        }
        config
    }
}

fn post_chain_config_args(config: &BTreeMap<String, String>, idx: usize) -> Vec<String> {
    let prefix = format!("post_chain.{idx}.config.");
    config
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix(&prefix)
                .map(|arg_key| format!("{arg_key}={value}"))
        })
        .collect()
}

fn module_config_args(config: &BTreeMap<String, String>, module_id: &str) -> Vec<String> {
    let prefix = format!("module:{module_id}.");
    let mut args = config
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix(&prefix)
                .map(|arg_key| format!("{arg_key}={value}"))
        })
        .collect::<Vec<_>>();

    if args.is_empty() {
        args = config
            .get(&format!("module:{module_id}"))
            .map(|s| split_stored_post_args(s))
            .unwrap_or_default();
    }

    args
}

fn split_stored_post_args(args: &str) -> Vec<String> {
    args.split(';')
        .filter(|part| !part.trim().is_empty())
        .map(|part| part.trim().to_string())
        .collect()
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

        let message = serialize_packed::read_message(
            decompressed.as_slice(),
            *ReaderOptions::new()
                .traversal_limit_in_words(Some(64 * 1024 * 1024))
                .nesting_limit(64),
        )?;
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

        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), Compression::new(6));
        encoder.write_all(buf.as_slice())?;
        let compressed = encoder.finish()?;

        anyhow::Ok(compressed)
    }

    /// Check all referenced module ids against the dispatch registries.
    /// Returns a `Vec` of human-readable warning strings for ids that
    /// don't resolve. Non-fatal: modules may be installed later.
    pub fn validate_module_ids(&self) -> Vec<String> {
        use crate::modules::{encrypt_modules, external, post_build_modules};

        let mut warnings = Vec::new();

        let can_resolve =
            |id: &str, slot: &str, check_static: &dyn Fn(&str) -> bool| -> Option<String> {
                if check_static(id) {
                    return None;
                }
                if external::registry().get(id).is_some() {
                    return None;
                }
                Some(format!(
                "module id '{id}' referenced by '{slot}' is not registered in any dispatch registry"
            ))
            };

        if let Some(id) = self.plugins().encrypt_shellcode() {
            if let Some(w) = can_resolve(id, "encrypt_shellcode", &|id| {
                encrypt_modules().iter().any(|m| m.id() == id)
            }) {
                warnings.push(w);
            }
        }
        if let Some(id) = self.plugins().format_encrypted_shellcode() {
            if let Some(w) = can_resolve(id, "format_encrypted_shellcode", &|_| false) {
                warnings.push(w);
            }
        }
        if let Some(id) = self.plugins().format_url_remote() {
            if let Some(w) = can_resolve(id, "format_url_remote", &|_| false) {
                warnings.push(w);
            }
        }
        if let Some(id) = self.plugins().upload_final_shellcode_remote() {
            if let Some(w) = can_resolve(id, "upload_final_shellcode_remote", &|_| false) {
                warnings.push(w);
            }
        }
        for (idx, id) in self.plugins().modules().iter().enumerate() {
            if let Some(w) = can_resolve(id, &format!("modules[{idx}]"), &|id| {
                post_build_modules().iter().any(|m| m.id() == id)
            }) {
                warnings.push(w);
            }
        }

        warnings
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

                let marker = self.replace().src_prefix();
                if !marker.is_empty() && data.windows(marker.len()).any(|w| w == marker) {
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

        self.validate_post_module_constraints(platform, bin_type)?;

        Ok(())
    }

    fn validate_post_module_constraints(
        &self,
        platform: Platform,
        bin_type: BinaryType,
    ) -> anyhow::Result<()> {
        let chain = self.plugins().modules();
        for id in chain {
            let Some(descriptor) =
                crate::modules::descriptor_for(crate::modules::ModuleKind::PostBuild, id)
            else {
                // Missing modules are reported by dispatch if/when the chain runs.
                continue;
            };

            if let Some(required) = descriptor.constraints.requires_platform {
                if required != platform {
                    anyhow::bail!(
                        "module '{id}' requires target platform {required}, but selected target is {platform}"
                    );
                }
            }
            if let Some(required) = descriptor.constraints.requires_binary_type {
                if required != bin_type {
                    anyhow::bail!(
                        "module '{id}' requires target type {required}, but selected target type is {bin_type}"
                    );
                }
            }
            for incompatible in &descriptor.constraints.incompatible_with {
                if chain.iter().any(|other| other == incompatible) {
                    anyhow::bail!(
                        "module '{id}' is incompatible with module '{incompatible}' in the same post-build chain"
                    );
                }
            }
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
                // who pre-encrypted and passed the resulting Pass list
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

                let (final_shellcode, format_pass) = self
                    .plugins()
                    .run_format_encrypted_shellcode(output.encrypted(), runtime_config)?;

                for p in format_pass {
                    if !caller_holders.contains(&p.holder) {
                        pass.push(p);
                    }
                }

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

        tracing::info!(encrypted_len = shellcode_bytes.len(), "shellcode processed");

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
        let pass_count = pass.len();
        for p in pass {
            utils::replace(&mut bin, p.holder(), p.replace_by(), p.holder().len())?;
        }

        tracing::info!(pass_count, "pass entries applied");

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
            let size_holder = self
                .replace()
                .size_holder()
                .ok_or(crate::error::PumpBinError::LocalRequiresSizeHolder)?;
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

        tracing::info!("post-build complete");

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a PluginBins with the requested slots populated. Uses a
    /// 1-byte sentinel for each slot since auto_select_target only
    /// cares about Some/None.
    fn bins_with(slots: &[(Platform, BinaryType)]) -> PluginBins {
        let mut bins = PluginBins::default();
        for (p, b) in slots {
            let target = match p {
                Platform::Windows => &mut bins.windows,
                Platform::Linux => &mut bins.linux,
                Platform::Darwin => &mut bins.darwin,
            };
            match b {
                BinaryType::Executable => *target.executable_mut() = Some(vec![0x00]),
                BinaryType::DynamicLibrary => *target.dynamic_library_mut() = Some(vec![0x00]),
            }
        }
        bins
    }

    #[test]
    fn single_slot_is_returned_with_no_explicit_args() {
        let bins = bins_with(&[(Platform::Linux, BinaryType::Executable)]);
        assert_eq!(
            bins.auto_select_target(None, None).unwrap(),
            (Platform::Linux, BinaryType::Executable)
        );
    }

    #[test]
    fn windows_exe_wins_when_multiple_slots_and_no_args() {
        let bins = bins_with(&[
            (Platform::Linux, BinaryType::Executable),
            (Platform::Windows, BinaryType::Executable),
            (Platform::Darwin, BinaryType::Executable),
        ]);
        assert_eq!(
            bins.auto_select_target(None, None).unwrap(),
            (Platform::Windows, BinaryType::Executable)
        );
    }

    #[test]
    fn fallback_priority_when_no_windows_exe() {
        // windows/lib beats linux/exe per the priority order.
        let bins = bins_with(&[
            (Platform::Linux, BinaryType::Executable),
            (Platform::Windows, BinaryType::DynamicLibrary),
            (Platform::Darwin, BinaryType::Executable),
        ]);
        assert_eq!(
            bins.auto_select_target(None, None).unwrap(),
            (Platform::Windows, BinaryType::DynamicLibrary)
        );
    }

    #[test]
    fn explicit_platform_narrows_to_its_only_populated_type() {
        let bins = bins_with(&[
            (Platform::Linux, BinaryType::DynamicLibrary),
            (Platform::Windows, BinaryType::Executable),
        ]);
        assert_eq!(
            bins.auto_select_target(Some(Platform::Linux), None)
                .unwrap(),
            (Platform::Linux, BinaryType::DynamicLibrary)
        );
    }

    #[test]
    fn explicit_platform_with_multiple_types_prefers_exe() {
        let bins = bins_with(&[
            (Platform::Linux, BinaryType::DynamicLibrary),
            (Platform::Linux, BinaryType::Executable),
        ]);
        assert_eq!(
            bins.auto_select_target(Some(Platform::Linux), None)
                .unwrap(),
            (Platform::Linux, BinaryType::Executable)
        );
    }

    #[test]
    fn explicit_args_that_match_nothing_error_with_available_slots() {
        let bins = bins_with(&[(Platform::Linux, BinaryType::Executable)]);
        let err = bins
            .auto_select_target(Some(Platform::Windows), None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("linux/exe") && err.contains("available slots"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn empty_plugin_errors_with_clear_message() {
        let bins = PluginBins::default();
        let err = bins.auto_select_target(None, None).unwrap_err().to_string();
        assert!(
            err.contains("no populated binary slots"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn explicit_args_that_match_a_populated_slot_pass_through() {
        let bins = bins_with(&[
            (Platform::Windows, BinaryType::Executable),
            (Platform::Linux, BinaryType::Executable),
        ]);
        assert_eq!(
            bins.auto_select_target(Some(Platform::Linux), Some(BinaryType::Executable))
                .unwrap(),
            (Platform::Linux, BinaryType::Executable)
        );
    }

    #[test]
    fn post_chain_config_args_are_extracted_by_index() {
        let mut config = BTreeMap::new();
        config.insert(
            "post_chain.0.config.donor".to_string(),
            "/tmp/a.exe".to_string(),
        );
        config.insert("post_chain.1.config.mode".to_string(), "first".to_string());
        config.insert(
            "post_chain.1.config.patches".to_string(),
            "aa:bb".to_string(),
        );

        assert_eq!(
            post_chain_config_args(&config, 0),
            vec!["donor=/tmp/a.exe".to_string()]
        );
        assert_eq!(
            post_chain_config_args(&config, 1),
            vec!["mode=first".to_string(), "patches=aa:bb".to_string()]
        );
    }

    #[test]
    fn stored_post_args_split_on_semicolon() {
        assert_eq!(
            split_stored_post_args("patches=aa:bb;mode=first"),
            vec!["patches=aa:bb".to_string(), "mode=first".to_string()]
        );
    }

    #[test]
    fn module_config_args_use_scoped_keys() {
        let mut config = BTreeMap::new();
        config.insert("module:demo.alpha".to_string(), "one".to_string());
        config.insert("module:demo.beta".to_string(), "two".to_string());

        assert_eq!(
            module_config_args(&config, "demo"),
            vec!["alpha=one".to_string(), "beta=two".to_string()]
        );
    }

    fn plugin_with_post_module(id: &str) -> Plugin {
        let mut bins = PluginBins::default();
        *bins.windows.executable_mut() = Some(vec![0x00]);
        *bins.linux.executable_mut() = Some(vec![0x00]);
        let mut plugin = Plugin {
            replace: PluginReplace {
                src_prefix: b"$$SHELLCODE$$".to_vec(),
                size_holder: Some(b"$$99999$$".to_vec()),
                max_len: 16,
            },
            bins,
            ..Default::default()
        };
        plugin.plugins.modules_mut().push(id.to_string());
        plugin
    }

    #[test]
    fn windows_only_post_module_rejects_linux_target() {
        let plugin = plugin_with_post_module("cert-graft");
        let err = plugin
            .validate_for_generation(Platform::Linux, BinaryType::Executable)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("requires target platform Windows"),
            "got: {err}"
        );
    }

    #[test]
    fn windows_only_post_module_accepts_windows_target() {
        let plugin = plugin_with_post_module("cert-graft");
        plugin
            .validate_for_generation(Platform::Windows, BinaryType::Executable)
            .unwrap();
    }
}
