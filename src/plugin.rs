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

#[derive(Debug, Default, Clone)]
pub struct PluginPlugins {
    pub encrypt_shellcode: Option<Vec<u8>>,
    pub format_encrypted_shellcode: Option<Vec<u8>>,
    pub format_url_remote: Option<Vec<u8>>,
    pub upload_final_shellcode_remote: Option<Vec<u8>>,
    pub plugin_config: Vec<(String, String)>,
    pub modules: Vec<Vec<u8>>,
}

impl PluginPlugins {
    pub fn run_encrypt_shellcode(
        &self,
        path: &Path,
        runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<crate::plugin_system::EncryptShellcodeOutput> {
        let shellcode = fs::read(path)?;
        let input = crate::plugin_system::EncryptShellcodeInput {
            shellcode: shellcode.clone(),
        };

        if let Some(res) = crate::plugin_system::EventManager::fire(
            self.modules(),
            "encrypt_shellcode",
            &input,
            runtime_config,
        )? {
            return Ok(res);
        }

        // Backwards compatibility with single WASM field
        if let Some(wasm) = self.encrypt_shellcode() {
            if let Some(res) =
                crate::plugin_system::run_plugin(wasm, "encrypt_shellcode", &input, runtime_config)?
            {
                return Ok(serde_json::from_slice(res.as_slice())?);
            }
        }

        Ok(crate::plugin_system::EncryptShellcodeOutput {
            encrypted: shellcode,
            ..Default::default()
        })
    }

    pub fn run_format_encrypted_shellcode(
        &self,
        shellcode: &[u8],
        runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<crate::plugin_system::FormatEncryptedShellcodeOutput> {
        let shellcode = shellcode.to_owned();
        let input = crate::plugin_system::FormatEncryptedShellcodeInput {
            shellcode: shellcode.clone(),
        };

        if let Some(res) = crate::plugin_system::EventManager::fire(
            self.modules(),
            "format_encrypted_shellcode",
            &input,
            runtime_config,
        )? {
            return Ok(res);
        }

        if let Some(wasm) = self.format_encrypted_shellcode() {
            if let Some(res) = crate::plugin_system::run_plugin(
                wasm,
                "format_encrypted_shellcode",
                &input,
                runtime_config,
            )? {
                return Ok(serde_json::from_slice(res.as_slice())?);
            }
        }

        Ok(crate::plugin_system::FormatEncryptedShellcodeOutput {
            formatted_shellcode: shellcode,
        })
    }

    pub fn run_format_url_remote(
        &self,
        url: &str,
        runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<crate::plugin_system::FormatUrlRemoteOutput> {
        let url = url.to_owned();
        let input = crate::plugin_system::FormatUrlRemoteInput { url: url.clone() };

        if let Some(res) = crate::plugin_system::EventManager::fire(
            self.modules(),
            "format_url_remote",
            &input,
            runtime_config,
        )? {
            return Ok(res);
        }

        if let Some(wasm) = self.format_url_remote() {
            if let Some(res) =
                crate::plugin_system::run_plugin(wasm, "format_url_remote", &input, runtime_config)?
            {
                return Ok(serde_json::from_slice(res.as_slice())?);
            }
        }

        Ok(crate::plugin_system::FormatUrlRemoteOutput { formatted_url: url })
    }

    pub fn run_upload_final_shellcode_remote(
        &self,
        final_shellcode: &[u8],
        runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<crate::plugin_system::UploadFinalShellcodeRemoteOutput> {
        let final_shellcode = final_shellcode.to_owned();
        let input = crate::plugin_system::UploadFinalShellcodeRemoteInput {
            final_shellcode: final_shellcode.clone(),
        };

        if let Some(res) = crate::plugin_system::EventManager::fire(
            self.modules(),
            "upload_final_shellcode_remote",
            &input,
            runtime_config,
        )? {
            return Ok(res);
        }

        if let Some(wasm) = self.upload_final_shellcode_remote() {
            if let Some(res) = crate::plugin_system::run_plugin(
                wasm,
                "upload_final_shellcode_remote",
                &input,
                runtime_config,
            )? {
                return Ok(serde_json::from_slice(res.as_slice())?);
            }
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
    pub fn run_post_binary(
        &self,
        binary: Vec<u8>,
        runtime_config: Option<&std::collections::BTreeMap<String, String>>,
    ) -> anyhow::Result<Vec<u8>> {
        crate::plugin_system::EventManager::fire_post_binary(self.modules(), binary, runtime_config)
    }
}

impl PluginPlugins {
    pub fn encrypt_shellcode(&self) -> Option<&Vec<u8>> {
        self.encrypt_shellcode.as_ref()
    }

    pub fn format_encrypted_shellcode(&self) -> Option<&Vec<u8>> {
        self.format_encrypted_shellcode.as_ref()
    }

    pub fn format_url_remote(&self) -> Option<&Vec<u8>> {
        self.format_url_remote.as_ref()
    }

    pub fn upload_final_shellcode_remote(&self) -> Option<&Vec<u8>> {
        self.upload_final_shellcode_remote.as_ref()
    }

    pub fn plugin_config(&self) -> &[(String, String)] {
        &self.plugin_config
    }

    pub fn plugin_config_mut(&mut self) -> &mut Vec<(String, String)> {
        &mut self.plugin_config
    }

    pub fn encrypt_shellcode_mut(&mut self) -> &mut Option<Vec<u8>> {
        &mut self.encrypt_shellcode
    }

    pub fn format_encrypted_shellcode_mut(&mut self) -> &mut Option<Vec<u8>> {
        &mut self.format_encrypted_shellcode
    }

    pub fn format_url_remote_mut(&mut self) -> &mut Option<Vec<u8>> {
        &mut self.format_url_remote
    }

    pub fn upload_final_shellcode_remote_mut(&mut self) -> &mut Option<Vec<u8>> {
        &mut self.upload_final_shellcode_remote
    }

    pub fn modules(&self) -> &[Vec<u8>] {
        &self.modules
    }

    pub fn modules_mut(&mut self) -> &mut Vec<Vec<u8>> {
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
                encrypt_shellcode: check_empty(plugins.get_encrypt_shellcode()?),
                format_encrypted_shellcode: check_empty(plugins.get_format_encrypted_shellcode()?),
                format_url_remote: check_empty(plugins.get_format_url_remote()?),
                upload_final_shellcode_remote: check_empty(
                    plugins.get_upload_final_shellcode_remote()?,
                ),
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
                    for m in mods {
                        decoded.push(m?.to_vec());
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
        if let Some(plugin) = plugin_plugins.encrypt_shellcode() {
            plugins.set_encrypt_shellcode(plugin);
        }
        if let Some(plugin) = plugin_plugins.format_encrypted_shellcode() {
            plugins.set_format_encrypted_shellcode(plugin);
        }
        if let Some(plugin) = plugin_plugins.format_url_remote() {
            plugins.set_format_url_remote(plugin);
        }
        if let Some(plugin) = plugin_plugins.upload_final_shellcode_remote() {
            plugins.set_upload_final_shellcode_remote(plugin);
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
                modules_list.set(i as u32, m);
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

                let data = fs::read(path).map_err(|source| PumpBinError::ShellcodeReadFailed {
                    path: shellcode_src.to_string(),
                    source,
                })?;

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

        // Embed shellcode byte-count for local loaders
        if save_type == ShellcodeSaveType::Local {
            let size_holder = self.replace().size_holder().unwrap();
            let len_str = shellcode_bytes.len().to_string();
            let len_bytes = len_str.as_bytes();

            if len_bytes.len() > size_holder.len() {
                return Err(crate::error::PumpBinError::SizeStringTooLong {
                    got: len_bytes.len(),
                    holder_len: size_holder.len(),
                }
                .into());
            }

            let mut size_bytes: Vec<u8> =
                iter::repeat_n(b'0', size_holder.len() - len_bytes.len()).collect();
            size_bytes.extend_from_slice(len_bytes);

            utils::replace(
                &mut bin,
                size_holder,
                size_bytes.as_slice(),
                size_holder.len(),
            )?;
        }

        // Run post_binary modules (signing, obfuscation, etc.)
        bin = self.plugins().run_post_binary(bin, runtime_config)?;

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
