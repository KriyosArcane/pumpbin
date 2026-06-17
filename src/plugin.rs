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

#[derive(Debug, Default, Clone)]
pub struct PluginReplace {
    pub src_prefix: Vec<u8>,
    pub size_holder: Option<Vec<u8>>,
    pub max_len: u64,
}

impl PluginReplace {
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
    ///: the default of 4096 was wrong for ~every real loader, which
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
        matches!(
            (self.executable.as_ref(), self.dynamic_library.as_ref()),
            (None, None)
        )
        .not()
    }

    pub fn supported_binary_types(&self) -> Vec<BinaryType> {
        let mut bin_types = Vec::default();
        if self.executable.as_ref().is_some() {
            bin_types.push(BinaryType::Executable);
        }
        if self.dynamic_library.as_ref().is_some() {
            bin_types.push(BinaryType::DynamicLibrary);
        }

        bin_types
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
        if self.windows.is_platform_supported() {
            platforms.push(Platform::Windows);
        }
        if self.linux.is_platform_supported() {
            platforms.push(Platform::Linux);
        }
        if self.darwin.is_platform_supported() {
            platforms.push(Platform::Darwin);
        }

        platforms
    }

    pub fn get_that_binary(&self, platform: Platform, bin_type: BinaryType) -> Option<&[u8]> {
        let platform_bins = match platform {
            Platform::Windows => &self.windows,
            Platform::Linux => &self.linux,
            Platform::Darwin => &self.darwin,
        };

        match bin_type {
            BinaryType::Executable => platform_bins.executable.as_ref().map(|v| v.as_slice()),
            BinaryType::DynamicLibrary => {
                platform_bins.dynamic_library.as_ref().map(|v| v.as_slice())
            }
        }
    }

    pub fn has_binary(&self, platform: Platform, bin_type: BinaryType) -> bool {
        let platform_bins = match platform {
            Platform::Windows => &self.windows,
            Platform::Linux => &self.linux,
            Platform::Darwin => &self.darwin,
        };
        match bin_type {
            BinaryType::Executable => platform_bins.executable.as_ref().is_some(),
            BinaryType::DynamicLibrary => platform_bins.dynamic_library.as_ref().is_some(),
        }
    }

    /// Pick a (platform, binary_type) pair to generate against.
    ///
    ///: If a caller passes both `platform` and `binary_type`, those win
    ///   (subject to that slot actually being populated).
    ///: If only one side is given, the other auto-resolves against the
    ///   populated slots that match it.
    ///: If neither is given and exactly one slot is populated, pick it.
    ///: On ambiguity (multiple candidates with no narrowing), fall back
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

/// Module references. Each string is a module id. The on-wire Cap'n Proto
/// fields are `Data`, so non-UTF-8 legacy module payloads are rejected on decode.
#[derive(Debug, Default, Clone)]
pub struct PluginPlugins {
    pub encrypt_shellcode: Option<String>,
    pub plugin_config: Vec<(String, String)>,
    pub modules: Vec<String>,
}

impl PluginPlugins {
    #[tracing::instrument(skip(self, runtime_config), fields(path = %path.display(), module = ?self.encrypt_shellcode.as_deref()))]
    pub fn run_encrypt_shellcode(
        &self,
        path: &Path,
        runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<crate::plugin_system::EncryptShellcodeOutput> {
        let shellcode = fs::read(path)?;
        if let Some(id) = self.encrypt_shellcode.as_deref() {
            let config = self.merged_runtime_config(runtime_config);
            let args = module_config_args(&config, id);
            return crate::modules::dispatch::encrypt(id, &args, &shellcode);
        }
        Ok(crate::plugin_system::EncryptShellcodeOutput {
            encrypted: shellcode,
            ..Default::default()
        })
    }

    /// Chain every post-build module in order.
    #[tracing::instrument(skip(self, binary, runtime_config), fields(binary_len = binary.len(), modules_count = self.modules.as_slice().len()))]
    pub fn run_post_binary(
        &self,
        binary: Vec<u8>,
        runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<Vec<u8>> {
        let mut out = binary;
        let config = self.merged_runtime_config(runtime_config);
        for id in self.modules.as_slice() {
            let args = config
                .get(&format!("post:{id}"))
                .map(|s| split_stored_post_args(s))
                .unwrap_or_default();
            crate::modules::dispatch::post_build(id, &args, &mut out)?;
        }
        Ok(out)
    }

    fn merged_runtime_config(
        &self,
        runtime_config: Option<&BTreeMap<String, String>>,
    ) -> BTreeMap<String, String> {
        let mut config: BTreeMap<String, String> =
            self.plugin_config.as_slice().iter().cloned().collect();
        if let Some(runtime_config) = runtime_config {
            for (key, value) in runtime_config {
                config.insert(key.clone(), value.clone());
            }
        }
        config
    }
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
                     Legacy .b1n files with embedded module bytes are not supported."
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
                                "modules[{idx}] is not a valid UTF-8 module id. Legacy .b1n files with embedded module bytes are not supported."
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
        info.set_plugin_name(&plugin_info.plugin_name);
        info.set_author(&plugin_info.author);
        info.set_version(&plugin_info.version);
        info.set_desc(&plugin_info.desc);

        let mut replace = plugin.reborrow().init_replace();
        let plugin_replace = self.replace();
        replace.set_src_prefix(&plugin_replace.src_prefix);
        if let Some(size_holder) = plugin_replace.size_holder.as_ref() {
            replace.set_size_holder(size_holder);
        }
        replace.set_max_len(plugin_replace.max_len);

        let mut bins = plugin.reborrow().init_bins();
        if self.bins.windows.is_platform_supported() {
            let mut builder = bins.reborrow().init_windows();
            let platform_bins = &self.bins.windows;

            if let Some(bin) = platform_bins.executable.as_ref() {
                builder.set_executable(bin);
            }
            if let Some(bin) = platform_bins.dynamic_library.as_ref() {
                builder.set_dynamic_library(bin);
            }
        }
        if self.bins.linux.is_platform_supported() {
            let mut builder = bins.reborrow().init_linux();
            let platform_bins = &self.bins.linux;

            if let Some(bin) = platform_bins.executable.as_ref() {
                builder.set_executable(bin);
            }
            if let Some(bin) = platform_bins.dynamic_library.as_ref() {
                builder.set_dynamic_library(bin);
            }
        }
        if self.bins.darwin.is_platform_supported() {
            let mut builder = bins.reborrow().init_darwin();
            let platform_bins = &self.bins.darwin;

            if let Some(bin) = platform_bins.executable.as_ref() {
                builder.set_executable(bin);
            }
            if let Some(bin) = platform_bins.dynamic_library.as_ref() {
                builder.set_dynamic_library(bin);
            }
        }

        let mut plugins = plugin.reborrow().init_plugins();
        let plugin_plugins = self.plugins();
        if let Some(id) = plugin_plugins.encrypt_shellcode.as_deref() {
            plugins.set_encrypt_shellcode(id.as_bytes());
        }
        let config = plugin_plugins.plugin_config.as_slice();
        if !config.is_empty() {
            let mut entries = plugins.reborrow().init_config_entries(config.len() as u32);
            for (i, (k, v)) in config.iter().enumerate() {
                let mut entry = entries.reborrow().get(i as u32);
                entry.set_key(k);
                entry.set_value(v);
            }
        }

        let mods = plugin_plugins.modules.as_slice();
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

        if let Some(id) = self.plugins.encrypt_shellcode.as_deref() {
            if let Some(w) = can_resolve(id, "encrypt_shellcode", &|id| {
                encrypt_modules().iter().any(|m| m.id() == id)
            }) {
                warnings.push(w);
            }
        }
        for (idx, id) in self.plugins.modules.as_slice().iter().enumerate() {
            if let Some(w) = can_resolve(id, &format!("modules[{idx}]"), &|id| {
                post_build_modules().iter().any(|m| m.id() == id)
            }) {
                warnings.push(w);
            }
        }

        warnings
    }

    pub fn save_type(&self) -> ShellcodeSaveType {
        if self.replace.size_holder.as_ref().is_some() {
            ShellcodeSaveType::Local
        } else {
            ShellcodeSaveType::Remote
        }
    }

    /// `shellcode_src` is skipped because for Local mode it's a path that
    /// may identify the operator's working directory; for Remote mode it
    /// may be an attacker-controlled URL. The save_type and any failure
    /// reason still surface via the returned error.
    #[tracing::instrument(skip(self, shellcode_src), fields(plugin = %self.info.plugin_name, save_type = ?self.save_type()))]
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
                // when this scope exits: even on the success path where we
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

                let marker = self.replace.src_prefix.as_slice();
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

    #[tracing::instrument(skip(self), fields(plugin = %self.info.plugin_name))]
    pub fn validate_for_generation(
        &self,
        platform: Platform,
        bin_type: BinaryType,
    ) -> anyhow::Result<()> {
        use crate::error::PumpBinError;

        let save_type = self.save_type();

        let platform_bins = match platform {
            Platform::Windows => &self.bins.windows,
            Platform::Linux => &self.bins.linux,
            Platform::Darwin => &self.bins.darwin,
        };

        let binary_exists = match bin_type {
            BinaryType::Executable => platform_bins.executable.as_ref().is_some(),
            BinaryType::DynamicLibrary => platform_bins.dynamic_library.as_ref().is_some(),
        };

        if !binary_exists {
            return Err(PumpBinError::BinaryNotInPlugin {
                platform: platform.to_string(),
                bin_type: bin_type.to_string(),
            }
            .into());
        }

        if save_type == ShellcodeSaveType::Local && self.replace.size_holder.as_ref().is_none() {
            return Err(PumpBinError::LocalRequiresSizeHolder.into());
        }

        if self.replace.max_len as usize == 0 {
            return Err(PumpBinError::MaxLenZero.into());
        }

        self.validate_post_module_constraints(platform)?;

        Ok(())
    }

    fn validate_post_module_constraints(&self, platform: Platform) -> anyhow::Result<()> {
        let chain = self.plugins.modules.as_slice();
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
        }

        Ok(())
    }

    /// Inject shellcode into a binary template and run all post-processing modules.
    ///
    /// Takes ownership of `bin` so that `post_binary` modules can resize it,
    /// and returns the fully-processed binary bytes.
    ///
    /// `#[instrument]`: every shellcode/secret argument is in `skip(...)` to
    /// keep logs free of shellcode bytes, Pass holder/replace values, and
    /// runtime config (which often contains keys/passwords).
    /// Only metadata that's safe to leak: plugin name, save_type, binary
    /// length: is logged.
    #[tracing::instrument(
        skip(self, bin, shellcode_src, pass, runtime_config),
        fields(
            plugin = %self.info.plugin_name,
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
                // invalidate their plaintext shellcode.
                let caller_holders: std::collections::HashSet<Vec<u8>> =
                    pass.iter().map(|p| p.holder.clone()).collect();
                for p in output.pass() {
                    if !caller_holders.contains(&p.holder) {
                        pass.push(p.clone());
                    }
                }

                output.encrypted().to_vec()
            }
            ShellcodeSaveType::Remote => {
                let mut src = shellcode_src.into_bytes();
                src.push(b'\0');
                src
            }
        };

        tracing::info!(encrypted_len = shellcode_bytes.len(), "shellcode processed");

        if shellcode_bytes.len() > self.replace.max_len as usize {
            return Err(crate::error::PumpBinError::ShellcodeTooLong {
                kind: match save_type {
                    ShellcodeSaveType::Local => "Shellcode",
                    ShellcodeSaveType::Remote => "Shellcode URL",
                },
                got: shellcode_bytes.len(),
                max: self.replace.max_len as usize,
            }
            .into());
        }

        utils::replace(
            &mut bin,
            self.replace.src_prefix.as_slice(),
            shellcode_bytes.as_slice(),
            self.replace.max_len as usize,
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
        //: 4-byte holder: binary u32 little-endian length. Used by
        //     scaffolded PIC loaders to skip the decimal-parse code
        //     path (no core::fmt drag-in). Caps at u32::MAX shellcode
        //     bytes: way past PumpBin's max_len limits anyway.
        //: any other length: ASCII decimal, left-padded with '0' to
        //     fill the holder slot (e.g. "000000158" in a 9-byte
        //     holder). The historical mode; matches the
        //     `$$99999$$` default and what every existing loader
        //     template parses.
        if save_type == ShellcodeSaveType::Local {
            let size_holder = self
                .replace()
                .size_holder
                .as_ref()
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
