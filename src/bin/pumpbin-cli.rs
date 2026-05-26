#![allow(unused)]

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::Local;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use dirs::home_dir;
use pumpbin::plugin::{Plugin, PluginInfo, PluginReplace};
use pumpbin::{
    get_plugin_config_schema, BinaryType, Platform, PluginConfigField, ShellcodeSaveType,
};
use std::collections::BTreeMap;
use std::ops::Not;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Disable the JSON log file sink (stderr console layer stays on).
    /// Equivalent to `PUMPBIN_NO_LOG=1`.
    #[arg(long, global = true)]
    no_log: bool,

    /// Override log level. Accepts EnvFilter syntax, e.g. `debug` or
    /// `info,extism=warn`. Takes precedence over `PUMPBIN_LOG`.
    #[arg(long, global = true, value_name = "FILTER")]
    log_level: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
}

impl From<CompletionShell> for Shell {
    fn from(value: CompletionShell) -> Self {
        match value {
            CompletionShell::Bash => Shell::Bash,
            CompletionShell::Zsh => Shell::Zsh,
            CompletionShell::Fish => Shell::Fish,
            CompletionShell::Powershell => Shell::PowerShell,
            CompletionShell::Elvish => Shell::Elvish,
        }
    }
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Generate an implant from a plugin and shellcode
    Generate {
        /// Path to the PumpBin plugin (.b1n)
        #[arg(short, long, value_hint = clap::ValueHint::FilePath)]
        plugin: PathBuf,

        /// Path to the shellcode (.bin) or a remote URL
        #[arg(short, long, value_hint = clap::ValueHint::AnyPath)]
        shellcode: String,

        /// Target platform (windows, linux, darwin)
        #[arg(long)]
        platform: String,

        /// Target binary type (exe, lib)
        #[arg(short = 't', long = "type")]
        binary_type: String,

        /// Output file path (optional)
        #[arg(short, long, value_hint = clap::ValueHint::FilePath)]
        output: Option<PathBuf>,

        /// Override module config key-values (repeatable), e.g. --module-config padding_mb=8
        #[arg(
            long = "module-config",
            alias = "plugin-config",
            value_name = "KEY=VALUE"
        )]
        module_config: Vec<String>,
    },

    /// Generate multiple implants from a directory of shellcodes
    Batch {
        /// Path to the PumpBin plugin (.b1n)
        #[arg(short, long, value_hint = clap::ValueHint::FilePath)]
        plugin: PathBuf,

        /// Path to the directory containing shellcode (.bin) files
        #[arg(short, long, value_hint = clap::ValueHint::DirPath)]
        directory: PathBuf,

        /// Target platform (windows, linux, darwin)
        #[arg(long)]
        platform: String,

        /// Target binary type (exe, lib)
        #[arg(short = 't', long = "type")]
        binary_type: String,

        /// Output directory path (optional)
        #[arg(short, long, value_hint = clap::ValueHint::DirPath)]
        output_dir: Option<PathBuf>,

        /// Override module config key-values (repeatable), e.g. --module-config padding_mb=8
        #[arg(
            long = "module-config",
            alias = "plugin-config",
            value_name = "KEY=VALUE"
        )]
        module_config: Vec<String>,
    },

    /// Create a new .b1n plugin pack from template binary and module(s)
    CreateB1n {
        /// Output .b1n file path
        #[arg(short, long, value_hint = clap::ValueHint::FilePath)]
        output: PathBuf,

        /// Plugin pack name
        #[arg(long)]
        name: String,

        /// Author string
        #[arg(long, default_value = "pumpbin-cli")]
        author: String,

        /// Plugin pack version string
        #[arg(long = "plugin-version", default_value = "0.1.0")]
        plugin_version: String,

        /// Description
        #[arg(long, default_value = "Created by pumpbin-cli create-b1n")]
        desc: String,

        /// Template binary path
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        template: PathBuf,

        /// Platform (windows, linux, darwin)
        #[arg(long)]
        platform: String,

        /// Binary type (exe, lib)
        #[arg(short = 't', long = "type")]
        binary_type: String,

        /// Save type (local or remote)
        #[arg(long, default_value = "local")]
        save_type: String,

        /// Shellcode placeholder bytes
        #[arg(long, default_value = "$$SHELLCODE$$")]
        src_prefix: String,

        /// Size placeholder bytes (used for local save type)
        #[arg(long, default_value = "$$99999$$")]
        size_holder: String,

        /// Max placeholder region size
        #[arg(long, default_value_t = 4096)]
        max_len: u64,

        /// Unified module wasm path (optional)
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        module: Option<PathBuf>,

        /// Additional post-binary modules to chain in order
        #[arg(long = "post-module", value_hint = clap::ValueHint::FilePath)]
        post_modules: Vec<PathBuf>,

        /// Per-module config block entries formatted as <index>:KEY=VALUE
        #[arg(long = "post-module-config", value_name = "IDX:KEY=VALUE")]
        post_module_config: Vec<String>,

        /// Base module config key-values (repeatable), e.g. --module-config padding_mb=8
        #[arg(long = "module-config", value_name = "KEY=VALUE")]
        module_config: Vec<String>,
    },

    /// Verify a generated binary for authenticode/checksum/module markers
    Verify {
        /// Binary to verify
        #[arg(short, long, value_hint = clap::ValueHint::FilePath)]
        binary: PathBuf,
    },

    /// Inspect a .b1n plugin pack: dump plugin info, replace config,
    /// supported platforms, embedded modules (with sha256 + declared
    /// runtime policy), and the config schema each module exports.
    ///
    /// With `--diff <other.b1n>`, prints a human-readable diff of what
    /// changed between two packs.
    Inspect {
        /// Path to the .b1n plugin pack to inspect.
        binary: PathBuf,
        /// Optional second .b1n to diff against the first.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        diff: Option<PathBuf>,
    },

    /// Build an implant from a pumpbin.toml profile file.
    ///
    /// The profile captures plugin source, target platform/binary type,
    /// shellcode source (file/url/base64/hex), module config overrides,
    /// and output path. See `pumpbin::profile` module docs for the
    /// full schema. v1.3.0 first lands the profile flow; `--json` output
    /// and SBOM emission come in follow-up chips.
    Build {
        /// Path to the pumpbin.toml profile.
        #[arg(short = 'f', long, value_hint = clap::ValueHint::FilePath)]
        profile: PathBuf,
    },

    /// Print shell completion script to stdout
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: CompletionShell,

        /// Command name to generate completions for (defaults to pumpbin-cli)
        #[arg(long, default_value = "pumpbin-cli")]
        command_name: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Install tracing subscriber driven by --no-log / --log-level flags
    // (overriding PUMPBIN_NO_LOG / PUMPBIN_LOG env vars). init() is
    // idempotent and never panics; failure to open the log file degrades
    // silently to console-only.
    let log_cfg = pumpbin::logging::LoggingConfig {
        no_log_file: cli.no_log || std::env::var_os("PUMPBIN_NO_LOG").is_some(),
        level_override: cli.log_level.clone(),
        log_dir_override: None,
    };
    let _ = pumpbin::logging::init(log_cfg);
    tracing::debug!("pumpbin-cli starting");

    match &cli.command {
        Commands::Generate {
            plugin,
            shellcode,
            platform,
            binary_type,
            output,
            module_config,
        } => {
            tracing::info!("Starting automated CLI generation...");

            let parsed_platform = parse_platform(platform)?;
            let parsed_binary_type = parse_binary_type(binary_type)?;

            tracing::info!(plugin = ?plugin, "Loading plugin");
            let plugin_buf = std::fs::read(plugin)?;
            let plugin_obj = Plugin::decode_from_slice(&plugin_buf)?;

            tracing::info!(%platform, %binary_type, "Validating plugin for target");
            plugin_obj.validate_for_generation(parsed_platform, parsed_binary_type)?;

            let bin = plugin_obj
                .bins()
                .get_that_binary(parsed_platform, parsed_binary_type)
                .ok_or(anyhow!(
                    "Failed to retrieve binary for platform/type combination"
                ))?;

            plugin_obj.validate_shellcode_source(shellcode)?;
            let final_shellcode_src = shellcode.clone();
            let runtime_config = parse_module_config(module_config)?;
            let schema_fields = plugin_schema_fields(&plugin_obj);
            let runtime_config =
                normalize_runtime_config_for_schema(runtime_config, &schema_fields)?;

            tracing::info!("Injecting shellcode");
            let bin = plugin_obj.replace_binary(
                bin,
                final_shellcode_src,
                vec![],
                Some(&runtime_config),
            )?;

            let output_path = if let Some(out) = output {
                out.clone()
            } else {
                let now = Local::now();
                let timestamp = now.format("%Y%m%d_%H%M%S").to_string();
                let plugin_name_sanitized = plugin_obj
                    .info()
                    .plugin_name()
                    .to_lowercase()
                    .replace(' ', "_");
                let platform_str = parsed_platform.to_string().to_lowercase();
                let bin_type_str = match parsed_binary_type {
                    BinaryType::Executable => "exe",
                    BinaryType::DynamicLibrary => "dll",
                };
                let ext = ext_for_output(parsed_platform, parsed_binary_type);
                PathBuf::from(format!(
                    "{}_{}_{}_{}.{}",
                    plugin_name_sanitized, platform_str, bin_type_str, timestamp, ext
                ))
            };

            tracing::info!(output = ?output_path, "Saving generated binary");
            pumpbin::utils::atomic_write(&output_path, &bin)?;
            tracing::info!(output = ?output_path, "Generation complete");

            Ok(())
        }
        Commands::Batch {
            plugin,
            directory,
            platform,
            binary_type,
            output_dir,
            module_config,
        } => {
            tracing::info!("Starting automated Batch generation");

            let parsed_platform = parse_platform(platform)?;
            let parsed_binary_type = parse_binary_type(binary_type)?;

            tracing::info!(plugin = ?plugin, "Loading plugin");
            let plugin_buf = std::fs::read(plugin)?;
            let plugin_obj = Plugin::decode_from_slice(&plugin_buf)?;
            let runtime_config = parse_module_config(module_config)?;
            let schema_fields = plugin_schema_fields(&plugin_obj);
            let runtime_config =
                normalize_runtime_config_for_schema(runtime_config, &schema_fields)?;

            tracing::info!(%platform, %binary_type, "Validating plugin for target");
            plugin_obj.validate_for_generation(parsed_platform, parsed_binary_type)?;

            let save_type = if plugin_obj.replace().size_holder().is_some() {
                ShellcodeSaveType::Local
            } else {
                ShellcodeSaveType::Remote
            };

            if save_type == ShellcodeSaveType::Remote {
                return Err(anyhow!(
                    "Batch generation does not support remote shellcode URLs at this time."
                ));
            }

            let out_dir = match output_dir {
                Some(dir) => {
                    if !dir.exists() {
                        std::fs::create_dir_all(dir)?;
                    }
                    dir.clone()
                }
                None => std::env::current_dir()?,
            };

            tracing::info!(directory = ?directory, "Scanning directory for shellcode files");
            let entries = std::fs::read_dir(directory)?;

            let mut success_count = 0;
            let mut fail_count = 0;

            for entry in entries {
                let entry = entry?;
                let path = entry.path();

                if path.is_file() {
                    let is_bin =
                        path.extension().and_then(|ext| ext.to_str()).unwrap_or("") == "bin";
                    if is_bin {
                        tracing::info!(file = ?path.file_name().unwrap_or_default(), "Processing shellcode");

                        let bin = plugin_obj
                            .bins()
                            .get_that_binary(parsed_platform, parsed_binary_type)
                            .ok_or(anyhow!(
                                "Failed to retrieve binary for platform/type combination"
                            ))?;

                        let data = match std::fs::read(&path) {
                            Ok(d) => d,
                            Err(e) => {
                                tracing::warn!(file = ?path, error = %e, "Failed to read shellcode");
                                fail_count += 1;
                                continue;
                            }
                        };

                        if data.is_empty() {
                            tracing::warn!(file = ?path, "Shellcode file is empty");
                            fail_count += 1;
                            continue;
                        }
                        if data
                            .windows(b"$$SHELLCODE$$".len())
                            .any(|w| w == b"$$SHELLCODE$$")
                        {
                            tracing::warn!(file = ?path, "Shellcode file contains placeholder");
                            fail_count += 1;
                            continue;
                        }

                        let shellcode_src = path.to_string_lossy().to_string();
                        if let Err(e) = plugin_obj.validate_shellcode_source(&shellcode_src) {
                            tracing::warn!(file = ?path, error = %e, "Invalid shellcode source");
                            fail_count += 1;
                            continue;
                        }

                        let plugin_clone = plugin_obj.clone();

                        let bin = match plugin_clone.replace_binary(
                            bin,
                            shellcode_src,
                            vec![],
                            Some(&runtime_config),
                        ) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::warn!(file = ?path, error = %e, "Failed to inject shellcode");
                                fail_count += 1;
                                continue;
                            }
                        };

                        let now = Local::now();
                        let timestamp = now.format("%H%M%S").to_string();
                        let plugin_name_sanitized = plugin_clone
                            .info()
                            .plugin_name()
                            .to_lowercase()
                            .replace(' ', "_");
                        let shellcode_name = path
                            .file_stem()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_lowercase()
                            .replace(' ', "_");
                        let ext = ext_for_output(parsed_platform, parsed_binary_type);

                        let filename = format!(
                            "{}_{}_{}.{}",
                            plugin_name_sanitized, shellcode_name, timestamp, ext
                        );
                        let output_path = out_dir.join(filename);

                        if let Err(e) = pumpbin::utils::atomic_write(&output_path, &bin) {
                            tracing::warn!(file = ?path, error = %e, "Failed to save generated binary");
                            fail_count += 1;
                            continue;
                        }

                        tracing::info!(
                            output = ?output_path.file_name().unwrap_or_default(),
                            "Saved generated implant"
                        );
                        success_count += 1;
                    }
                }
            }

            tracing::info!(
                success = success_count,
                failed = fail_count,
                "Batch generation complete"
            );

            // Exit non-zero if nothing was generated, or if any individual case
            // failed. Pre-1.1.4 batch always exited 0, so a CI pipeline that
            // pointed at the wrong dir / a dir of non-.bin files would think
            // it succeeded and ship zero implants. Exit code policy:
            //   success > 0 && fail == 0  -> 0 (all good)
            //   success > 0 && fail > 0   -> 2 (partial)
            //   success == 0              -> 1 (nothing produced)
            match (success_count, fail_count) {
                (0, _) => bail!(
                    "Batch produced zero implants (checked directory: {}). \
                     Confirm the directory contains .bin shellcode files.",
                    directory.display()
                ),
                (_, 0) => Ok(()),
                (_, _) => bail!(
                    "Batch completed with {} failure(s) out of {} total. \
                     See [!] lines above for per-file errors.",
                    fail_count,
                    success_count + fail_count
                ),
            }
        }
        Commands::CreateB1n {
            output,
            name,
            author,
            plugin_version,
            desc,
            template,
            platform,
            binary_type,
            save_type,
            src_prefix,
            size_holder,
            max_len,
            module,
            post_modules,
            post_module_config,
            module_config,
        } => {
            let parsed_platform = parse_platform(platform)?;
            let parsed_binary_type = parse_binary_type(binary_type)?;
            let parsed_save_type = parse_save_type(save_type)?;

            let template_bytes = std::fs::read(template).with_context(|| {
                format!("failed to read template binary: {}", template.display())
            })?;

            let mut plugin = Plugin {
                version: env!("CARGO_PKG_VERSION").to_string(),
                info: PluginInfo {
                    plugin_name: name.clone(),
                    author: author.clone(),
                    version: plugin_version.clone(),
                    desc: desc.clone(),
                },
                replace: PluginReplace {
                    src_prefix: src_prefix.as_bytes().to_vec(),
                    size_holder: match parsed_save_type {
                        ShellcodeSaveType::Local => Some(size_holder.as_bytes().to_vec()),
                        ShellcodeSaveType::Remote => None,
                    },
                    max_len: *max_len,
                },
                ..Default::default()
            };

            // Preflight the template using the same check the Maker GUI runs.
            // Without this, pumpbin-cli create-b1n silently produced .b1n
            // files that failed at generate-time with "Holder '...' not
            // found in binary" (the repo's own hello.b1n was an example).
            plugin
                .replace
                .preflight_template(&template_bytes)
                .with_context(|| format!("Template at '{}'", template.display()))?;

            match (parsed_platform, parsed_binary_type) {
                (Platform::Windows, BinaryType::Executable) => {
                    *plugin.bins.windows.executable_mut() = Some(template_bytes);
                }
                (Platform::Windows, BinaryType::DynamicLibrary) => {
                    *plugin.bins.windows.dynamic_library_mut() = Some(template_bytes);
                }
                (Platform::Linux, BinaryType::Executable) => {
                    *plugin.bins.linux.executable_mut() = Some(template_bytes);
                }
                (Platform::Linux, BinaryType::DynamicLibrary) => {
                    *plugin.bins.linux.dynamic_library_mut() = Some(template_bytes);
                }
                (Platform::Darwin, BinaryType::Executable) => {
                    *plugin.bins.darwin.executable_mut() = Some(template_bytes);
                }
                (Platform::Darwin, BinaryType::DynamicLibrary) => {
                    *plugin.bins.darwin.dynamic_library_mut() = Some(template_bytes);
                }
            }

            if let Some(module_path) = module {
                let wasm = std::fs::read(module_path)
                    .with_context(|| format!("failed to read module: {}", module_path.display()))?;
                plugin.plugins.modules_mut().push(wasm);
            }

            let mut cfg = parse_module_config(module_config)?;

            for (idx, module_path) in post_modules.iter().enumerate() {
                let wasm = std::fs::read(module_path).with_context(|| {
                    format!(
                        "failed to read post-module {}: {}",
                        idx,
                        module_path.display()
                    )
                })?;
                cfg.insert(
                    format!("post_chain.{}.module_b64", idx),
                    general_purpose::STANDARD.encode(wasm),
                );
            }

            for entry in post_module_config {
                let (idx, key, value) = parse_post_module_config_entry(entry)?;
                cfg.insert(format!("post_chain.{}.config.{}", idx, key), value);
            }

            *plugin.plugins.plugin_config_mut() = cfg.into_iter().collect();

            let data = plugin.encode_to_vec()?;
            pumpbin::utils::atomic_write(output, &data)
                .with_context(|| format!("failed to write output .b1n: {}", output.display()))?;

            tracing::info!(output = %output.display(), "Created .b1n plugin pack");
            Ok(())
        }
        Commands::Verify { binary } => verify_binary(binary),
        Commands::Inspect { binary, diff } => {
            let left = pumpbin::inspect::inspect(binary)?;
            if let Some(other_path) = diff {
                let right = pumpbin::inspect::inspect(other_path)?;
                print!("{}", pumpbin::inspect::render_diff(&left, &right));
            } else {
                print!("{}", pumpbin::inspect::render_text(&left));
            }
            Ok(())
        }
        Commands::Build { profile } => {
            tracing::info!(profile = ?profile, "Loading build profile");
            let profile = pumpbin::Profile::from_toml(profile)?;
            tracing::info!(
                schema = %profile.schema,
                plugin = ?profile.plugin.source,
                platform = %profile.target.platform,
                binary_type = %profile.target.binary_type,
                "Profile loaded"
            );
            let artifact = profile.execute()?;
            tracing::info!(
                output = %artifact.output_path.display(),
                bytes = artifact.bytes_written,
                "Build complete"
            );
            Ok(())
        }
        Commands::Completions {
            shell,
            command_name,
        } => {
            let mut cmd = Cli::command();
            let generator: Shell = shell.clone().into();
            generate(generator, &mut cmd, command_name, &mut std::io::stdout());
            Ok(())
        }
    }
}

fn parse_platform(s: &str) -> Result<Platform> {
    match s.to_lowercase().as_str() {
        "windows" => Ok(Platform::Windows),
        "linux" => Ok(Platform::Linux),
        "darwin" => Ok(Platform::Darwin),
        _ => Err(anyhow!(
            "Invalid platform '{}'. Expected: windows, linux, darwin",
            s
        )),
    }
}

fn parse_binary_type(s: &str) -> Result<BinaryType> {
    match s.to_lowercase().as_str() {
        "exe" => Ok(BinaryType::Executable),
        "lib" => Ok(BinaryType::DynamicLibrary),
        _ => Err(anyhow!("Invalid target type '{}'. Expected: exe, lib", s)),
    }
}

fn parse_save_type(s: &str) -> Result<ShellcodeSaveType> {
    match s.to_lowercase().as_str() {
        "local" => Ok(ShellcodeSaveType::Local),
        "remote" => Ok(ShellcodeSaveType::Remote),
        _ => Err(anyhow!(
            "Invalid save type '{}'. Expected: local, remote",
            s
        )),
    }
}

fn ext_for_output(platform: Platform, binary_type: BinaryType) -> &'static str {
    match (platform, binary_type) {
        (Platform::Windows, BinaryType::Executable) => "exe",
        (Platform::Windows, BinaryType::DynamicLibrary) => "dll",
        (Platform::Linux, BinaryType::Executable) => "elf",
        (Platform::Linux, BinaryType::DynamicLibrary) => "so",
        (Platform::Darwin, BinaryType::Executable) => "macho",
        (Platform::Darwin, BinaryType::DynamicLibrary) => "dylib",
    }
}

fn parse_module_config(entries: &[String]) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();

    for entry in entries {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(anyhow!(
                "Invalid --module-config value '{}'. Expected KEY=VALUE",
                entry
            ));
        };

        let key = key.trim();
        if key.is_empty() {
            return Err(anyhow!(
                "Invalid --module-config value '{}': empty key",
                entry
            ));
        }

        map.insert(key.to_string(), value.to_string());
    }

    Ok(map)
}

fn parse_post_module_config_entry(entry: &str) -> Result<(usize, String, String)> {
    let (idx_raw, kv) = entry.split_once(':').ok_or_else(|| {
        anyhow!(
            "Invalid --post-module-config '{}'. Expected IDX:KEY=VALUE",
            entry
        )
    })?;

    let idx = idx_raw
        .parse::<usize>()
        .map_err(|_| anyhow!("Invalid post-module index '{}' in '{}'.", idx_raw, entry))?;

    let (key, value) = kv.split_once('=').ok_or_else(|| {
        anyhow!(
            "Invalid --post-module-config '{}'. Expected IDX:KEY=VALUE",
            entry
        )
    })?;

    let key = key.trim();
    if key.is_empty() {
        bail!("Invalid --post-module-config '{}': empty key", entry);
    }

    Ok((idx, key.to_string(), value.to_string()))
}

fn plugin_schema_fields(plugin: &Plugin) -> Vec<PluginConfigField> {
    for wasm in plugin.plugins().modules() {
        if let Ok(Some(schema)) = get_plugin_config_schema(wasm) {
            return schema.fields;
        }
    }

    let wasm = plugin
        .plugins()
        .encrypt_shellcode()
        .or(plugin.plugins().format_encrypted_shellcode())
        .or(plugin.plugins().format_url_remote())
        .or(plugin.plugins().upload_final_shellcode_remote());

    if let Some(wasm) = wasm {
        if let Ok(Some(schema)) = get_plugin_config_schema(wasm) {
            return schema.fields;
        }
    }

    Vec::new()
}

fn maybe_expand_home_path(value: &str) -> PathBuf {
    if value == "~" {
        return home_dir().unwrap_or_else(|| PathBuf::from(value));
    }

    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }

    PathBuf::from(value)
}

fn looks_like_path(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with('~')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.contains('/')
        || value.contains('\\')
}

fn normalize_file_value(field_key: &str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }

    let path = maybe_expand_home_path(trimmed);
    if path.is_file() {
        let bytes = std::fs::read(&path)
            .map_err(|e| anyhow!("failed to read file for '{}': {}", field_key, e))?;
        return Ok(general_purpose::STANDARD.encode(bytes));
    }

    if general_purpose::STANDARD.decode(trimmed).is_ok() {
        return Ok(trimmed.to_string());
    }

    if looks_like_path(trimmed) {
        return Err(anyhow!(
            "file config '{}' points to '{}' but the file was not found",
            field_key,
            trimmed
        ));
    }

    Ok(value.to_string())
}

fn normalize_file_path_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    maybe_expand_home_path(trimmed)
        .to_string_lossy()
        .to_string()
}

fn is_reserved_runtime_key(key: &str) -> bool {
    key.starts_with("post_chain.")
}

fn normalize_reserved_runtime_config(
    mut config: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let keys = config.keys().cloned().collect::<Vec<_>>();

    for key in keys {
        if is_reserved_runtime_key(&key).not() {
            continue;
        }

        let Some(value) = config.get(&key).cloned() else {
            continue;
        };

        if key.ends_with(".module_b64") {
            let normalized = normalize_file_value(&key, &value)?;
            config.insert(key, normalized);
            continue;
        }

        if key.ends_with(".module_path") {
            let normalized = normalize_file_path_value(&value);
            config.insert(key, normalized);
            continue;
        }

        if key.contains(".config.") && key.ends_with("_base64") {
            let normalized = normalize_file_value(&key, &value)?;
            config.insert(key, normalized);
            continue;
        }

        if key.contains(".config.") && key.ends_with("_path") {
            let normalized = normalize_file_path_value(&value);
            config.insert(key, normalized);
            continue;
        }
    }

    Ok(config)
}

fn normalize_runtime_config_for_schema(
    mut config: BTreeMap<String, String>,
    schema: &[PluginConfigField],
) -> Result<BTreeMap<String, String>> {
    config = normalize_reserved_runtime_config(config)?;

    if schema.is_empty() {
        return Ok(config);
    }

    for key in config.keys() {
        if schema.iter().any(|f| &f.key == key).not() && is_reserved_runtime_key(key).not() {
            return Err(anyhow!(
                "Unknown --module-config key '{}'. This module schema defines: {}",
                key,
                schema
                    .iter()
                    .map(|f| f.key.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    for field in schema {
        let Some(value) = config.get_mut(&field.key) else {
            continue;
        };

        if field.required && value.trim().is_empty() {
            return Err(anyhow!(
                "Config '{}' is required and cannot be empty.",
                field.key
            ));
        }

        match field.field_type.to_ascii_lowercase().as_str() {
            "number" => {
                value.parse::<f64>().map_err(|_| {
                    anyhow!("Config '{}' expects a number, got '{}'.", field.key, value)
                })?;
            }
            "boolean" => {
                let normalized = match value.to_ascii_lowercase().as_str() {
                    "1" | "true" | "yes" | "on" => "true",
                    "0" | "false" | "no" | "off" => "false",
                    _ => {
                        return Err(anyhow!(
                            "Config '{}' expects a boolean, got '{}'.",
                            field.key,
                            value
                        ));
                    }
                };
                *value = normalized.to_string();
            }
            "choice" => {
                if field.options.is_empty().not() && field.options.contains(value).not() {
                    return Err(anyhow!(
                        "Config '{}' expects one of [{}], got '{}'.",
                        field.key,
                        field.options.join(", "),
                        value
                    ));
                }
            }
            "file" | "file_base64" => {
                *value = normalize_file_value(&field.key, value)?;
            }
            "file_path" => {
                *value = normalize_file_path_value(value);
            }
            _ => {}
        }
    }

    Ok(config)
}

#[derive(Debug)]
struct PeVerifyReport {
    is_pe: bool,
    checksum_current: Option<u32>,
    checksum_calculated: Option<u32>,
    checksum_valid: bool,
    security_dir_va: Option<u32>,
    security_dir_size: Option<u32>,
    markers: Vec<(String, usize)>,
}

fn verify_binary(binary: &PathBuf) -> Result<()> {
    let bytes = std::fs::read(binary)
        .with_context(|| format!("failed to read binary: {}", binary.display()))?;

    let pe = analyze_pe(&bytes)?;
    let auth = verify_authenticode(binary, pe.security_dir_size.unwrap_or(0));

    // Collect human-readable failure reasons. Each push here makes the final
    // exit code non-zero, so automation can `pumpbin-cli verify --binary X`
    // and trust the exit status. Pre-1.1.3 verify always returned Ok(())
    // even with `PE format: no` and `Authenticode invalid`, causing false
    // passes in CI pipelines.
    let mut failures: Vec<String> = Vec::new();

    println!("Binary: {}", binary.display());
    println!("PE format: {}", if pe.is_pe { "yes" } else { "no" });
    if !pe.is_pe {
        failures.push("input is not a valid PE binary".to_string());
    }

    if let (Some(current), Some(calculated)) = (pe.checksum_current, pe.checksum_calculated) {
        println!(
            "PE checksum: current=0x{current:08X}, calculated=0x{calculated:08X}, valid={}",
            pe.checksum_valid
        );
        if !pe.checksum_valid {
            failures.push(format!(
                "PE checksum mismatch (current=0x{current:08X}, calculated=0x{calculated:08X})"
            ));
        }
    } else {
        println!("PE checksum: unavailable");
    }

    if let (Some(va), Some(size)) = (pe.security_dir_va, pe.security_dir_size) {
        println!(
            "Authenticode directory: va=0x{va:08X}, size={} bytes{}",
            size,
            if size > 0 { " (present)" } else { "" }
        );
    } else {
        println!("Authenticode directory: unavailable");
    }

    println!("Authenticode verify: {}", auth.summary);
    if let Some(detail) = auth.detail {
        println!("Authenticode detail: {}", detail);
    }
    if matches!(auth.status, AuthCheckStatus::Failed) {
        failures.push(format!("Authenticode verify failed: {}", auth.summary));
    }

    if pe.markers.is_empty() {
        println!("Module markers: none");
    } else {
        println!("Module markers:");
        for (name, offset) in pe.markers {
            println!("- {} @ 0x{:X} ({})", name, offset, offset);
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        bail!(
            "verify reported {} failure(s):\n  - {}",
            failures.len(),
            failures.join("\n  - ")
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthCheckStatus {
    /// osslsigncode verify returned success.
    Valid,
    /// osslsigncode verify returned non-zero exit.
    Failed,
    /// We could not run a verification (no osslsigncode on PATH, or no
    /// signature blob present). Reported neutrally — does NOT count as
    /// failure for exit-code purposes.
    NotApplicable,
}

#[derive(Debug)]
struct AuthVerifyStatus {
    summary: String,
    detail: Option<String>,
    status: AuthCheckStatus,
}

fn verify_authenticode(path: &Path, security_dir_size: u32) -> AuthVerifyStatus {
    let output = Command::new("osslsigncode")
        .arg("verify")
        .arg("-in")
        .arg(path)
        .output();

    match output {
        Ok(out) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let first_line = combined
                .lines()
                .find(|l| l.trim().is_empty().not())
                .unwrap_or("no output")
                .trim()
                .to_string();

            if out.status.success() {
                AuthVerifyStatus {
                    summary: "valid (osslsigncode verify succeeded)".to_string(),
                    detail: Some(first_line),
                    status: AuthCheckStatus::Valid,
                }
            } else {
                AuthVerifyStatus {
                    summary: "invalid (osslsigncode verify failed)".to_string(),
                    detail: Some(first_line),
                    status: AuthCheckStatus::Failed,
                }
            }
        }
        Err(_) => {
            if security_dir_size > 0 {
                AuthVerifyStatus {
                    summary:
                        "signature blob present, but osslsigncode is unavailable for cryptographic verification"
                            .to_string(),
                    detail: None,
                    status: AuthCheckStatus::NotApplicable,
                }
            } else {
                AuthVerifyStatus {
                    summary: "no signature blob detected".to_string(),
                    detail: None,
                    status: AuthCheckStatus::NotApplicable,
                }
            }
        }
    }
}

fn analyze_pe(bytes: &[u8]) -> Result<PeVerifyReport> {
    let markers = collect_markers(bytes);

    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return Ok(PeVerifyReport {
            is_pe: false,
            checksum_current: None,
            checksum_calculated: None,
            checksum_valid: false,
            security_dir_va: None,
            security_dir_size: None,
            markers,
        });
    }

    let e_lfanew = read_u32(bytes, 0x3C)
        .ok_or_else(|| anyhow!("invalid DOS header: missing e_lfanew"))?
        as usize;
    if e_lfanew + 24 > bytes.len() {
        bail!("invalid PE header offset");
    }
    if &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Ok(PeVerifyReport {
            is_pe: false,
            checksum_current: None,
            checksum_calculated: None,
            checksum_valid: false,
            security_dir_va: None,
            security_dir_size: None,
            markers,
        });
    }

    let coff = e_lfanew + 4;
    let size_of_optional_header =
        read_u16(bytes, coff + 16).ok_or_else(|| anyhow!("invalid COFF header"))? as usize;
    let opt = coff + 20;
    if opt + size_of_optional_header > bytes.len() {
        bail!("invalid optional header size");
    }

    let magic = read_u16(bytes, opt).ok_or_else(|| anyhow!("invalid optional header magic"))?;
    let data_dir_off = match magic {
        0x10B => opt + 96,
        0x20B => opt + 112,
        _ => {
            return Ok(PeVerifyReport {
                is_pe: true,
                checksum_current: None,
                checksum_calculated: None,
                checksum_valid: false,
                security_dir_va: None,
                security_dir_size: None,
                markers,
            })
        }
    };

    let checksum_off = opt + 64;
    let checksum_current = read_u32(bytes, checksum_off);
    let checksum_calculated = checksum_current.map(|_| compute_pe_checksum(bytes, checksum_off));

    let security_entry_off = data_dir_off + 8 * 4;
    let security_dir_va = read_u32(bytes, security_entry_off);
    let security_dir_size = read_u32(bytes, security_entry_off + 4);

    let checksum_valid = match (checksum_current, checksum_calculated) {
        (Some(c), Some(calc)) => c == calc,
        _ => false,
    };

    Ok(PeVerifyReport {
        is_pe: true,
        checksum_current,
        checksum_calculated,
        checksum_valid,
        security_dir_va,
        security_dir_size,
        markers,
    })
}

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let bytes = data.get(off..end)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let bytes = data.get(off..end)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn compute_pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    let mut i = 0usize;

    while i + 1 < data.len() {
        if i == checksum_offset || i == checksum_offset + 2 {
            i += 2;
            continue;
        }

        let word = u16::from_le_bytes([data[i], data[i + 1]]) as u64;
        sum += word;
        sum = (sum & 0xFFFF) + (sum >> 16);
        i += 2;
    }

    if data.len() % 2 == 1 {
        sum += data[data.len() - 1] as u64;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = sum + (sum >> 16);

    ((sum & 0xFFFF) as u32).wrapping_add(data.len() as u32)
}

fn collect_markers(data: &[u8]) -> Vec<(String, usize)> {
    let patterns = ["PB-AUTHSIG", "PB-ICON"];
    let mut out = Vec::new();

    for pattern in patterns {
        for offset in find_all_occurrences(data, pattern.as_bytes()) {
            out.push((pattern.to_string(), offset));
        }
    }

    out.sort_by_key(|(_, off)| *off);
    out
}

fn find_all_occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.push(i);
            i += needle.len();
        } else {
            i += 1;
        }
    }

    out
}
