use anyhow::{anyhow, bail, Context, Result};
use chrono::Local;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use owo_colors::OwoColorize;
use pumpbin::plugin::Plugin;
use pumpbin::{BinaryType, Platform, ShellcodeSaveType};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn use_color() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stderr()) && std::env::var_os("NO_COLOR").is_none()
}

macro_rules! pb_info {
    ($label:expr, $target:expr, $($arg:tt)*) => {
        if use_color() {
            eprintln!("{}  {:<20}  {}  {} {}", "PB".cyan(), $label, $target, "[*]".cyan(), format_args!($($arg)*));
        } else {
            eprintln!("PB  {:<20}  {}  [*] {}", $label, $target, format_args!($($arg)*));
        }
    };
}

macro_rules! pb_ok {
    ($label:expr, $target:expr, $($arg:tt)*) => {
        if use_color() {
            eprintln!("{}  {:<20}  {}  {} {}", "PB".cyan(), $label, $target, "[+]".green(), format_args!($($arg)*));
        } else {
            eprintln!("PB  {:<20}  {}  [+] {}", $label, $target, format_args!($($arg)*));
        }
    };
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Override log level. Accepts EnvFilter syntax, e.g. `debug` or
    /// `pumpbin=debug`. Takes precedence over `PUMPBIN_LOG`.
    #[arg(long, global = true, value_name = "FILTER", help_heading = "Output")]
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
    /// Stamp shellcode into a .b1n loader pack.
    Generate {
        /// Path to the .b1n loader pack (or a crate directory containing
        /// a packed .b1n).
        #[arg(short = 'p', long = "pack", value_name = "PACK", value_hint = clap::ValueHint::FilePath)]
        plugin: PathBuf,

        /// Shellcode file (.bin) or remote URL.
        #[arg(short, long, value_hint = clap::ValueHint::AnyPath)]
        shellcode: String,

        /// Output file path.
        #[arg(short, long, value_hint = clap::ValueHint::FilePath)]
        output: Option<PathBuf>,

        /// Post-build module to apply. Repeat to chain multiple.
        /// Plain id: `--post byte-patch`
        /// With one arg: `--post byte-patch:patches=4831d2:4833d2`
        #[arg(long = "post", value_name = "ID[:K=V]")]
        post: Vec<String>,

        /// Preview what would be generated without writing anything.
        #[arg(long)]
        dry_run: bool,

        // --- Advanced ---
        /// Target platform (windows, linux, darwin). Auto-detected from
        /// the .b1n if omitted.
        #[arg(long, help_heading = "Advanced")]
        platform: Option<String>,

        /// Target binary type (exe, lib). Auto-detected from the .b1n.
        #[arg(short = 't', long = "type", help_heading = "Advanced")]
        binary_type: Option<String>,
    },

    /// Stamp every matching shellcode file in a directory.
    Batch {
        /// Path to the PumpBin loader pack (.b1n)
        #[arg(short = 'p', long = "pack", value_name = "PACK", value_hint = clap::ValueHint::FilePath)]
        plugin: PathBuf,

        /// Path to the directory containing shellcode (.bin) files
        #[arg(short, long, value_hint = clap::ValueHint::DirPath)]
        directory: PathBuf,

        /// Target platform (windows, linux, darwin). Auto-detected from
        /// the .b1n if omitted.
        #[arg(long)]
        platform: Option<String>,

        /// Target binary type (exe, lib). Auto-detected from the .b1n
        /// if omitted.
        #[arg(short = 't', long = "type")]
        binary_type: Option<String>,

        /// Output directory path (optional)
        #[arg(short, long, value_hint = clap::ValueHint::DirPath)]
        output_dir: Option<PathBuf>,

        /// File extension to match in the shellcode directory (without
        /// the leading dot). Default: "bin".
        #[arg(long, default_value = "bin")]
        extension: String,
    },

    /// Wrap a compiled loader binary as a reusable .b1n pack.
    CreateB1n {
        /// Output .b1n file path
        #[arg(short, long, value_hint = clap::ValueHint::FilePath)]
        output: PathBuf,

        /// Loader pack name. Defaults to the output file stem.
        #[arg(long)]
        name: Option<String>,

        /// Template binary path
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        template: PathBuf,

        /// Platform (windows, linux, darwin). Auto-detected from the template if omitted.
        #[arg(long)]
        platform: Option<String>,

        /// Binary type (exe, lib).
        #[arg(short = 't', long = "type", default_value = "exe")]
        binary_type: String,

        /// Shellcode placeholder marker bytes.
        #[arg(long, default_value = "$$SHELLCODE$$")]
        marker: String,

        /// Size placeholder bytes (local save type).
        #[arg(long, default_value = "$$99999$$")]
        size_holder: String,

        /// Encryption module to bake in (runs BEFORE shellcode is stamped).
        /// Encrypts the shellcode and stamps key/nonce holders into the binary.
        /// Use an `encrypt` kind module: `aes-gcm` or `xor`.
        /// Run `pumpbin-cli module list` to see available ids.
        /// Distinct from `--post` (which runs AFTER stamping).
        #[arg(long = "encrypt-module", value_name = "ID")]
        encrypt_module: Option<String>,

        /// Post-build module to bake into this .b1n.
        /// Accepts `--post <id>` or `--post <id>:<key=value>`.
        #[arg(long = "post", value_name = "ID[:K=V]")]
        post_modules: Vec<String>,

        // --- Advanced ---
        /// Max placeholder region size (auto-measured from template if omitted).
        #[arg(long, help_heading = "Advanced")]
        max_len: Option<u64>,

        /// Base module config key-values.
        #[arg(
            long = "module-config",
            value_name = "KEY=VALUE",
            help_heading = "Advanced"
        )]
        module_config: Vec<String>,

        /// Save type (local or remote).
        #[arg(long, default_value = "local", help_heading = "Advanced")]
        save_type: String,
    },

    /// Stamp shellcode into a compiled loader binary.
    Stamp {
        /// Compiled loader binary (PE, ELF, or Mach-O).
        /// Must contain a shellcode placeholder (default: $$SHELLCODE$$).
        /// Loaders built with `new-loader` already satisfy this.
        #[arg(value_hint = clap::ValueHint::FilePath)]
        loader: PathBuf,

        /// Raw shellcode file (.bin) to stamp into the loader.
        #[arg(value_hint = clap::ValueHint::AnyPath)]
        shellcode: String,

        /// Output path for the generated implant.
        #[arg(short, long, value_hint = clap::ValueHint::FilePath)]
        output: Option<PathBuf>,

        /// Post-build module to apply. Repeat to chain multiple.
        /// Plain id: `--post cert-graft`
        /// With one arg: `--post cert-graft:donor=/path/to/signed.exe`
        #[arg(long = "post", value_name = "ID[:K=V]")]
        post: Vec<String>,

        /// Also write the intermediate .b1n pack to this path for reuse
        /// with `pumpbin-cli generate`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        save_b1n: Option<PathBuf>,

        /// Preview what would be stamped without writing output files.
        #[arg(long)]
        dry_run: bool,

        // --- Advanced ---
        /// Target platform (windows, linux, darwin).
        /// Auto-detected from the loader binary magic bytes.
        #[arg(long, help_heading = "Advanced")]
        platform: Option<String>,

        /// Target binary type (exe, lib).
        #[arg(
            short = 't',
            long = "type",
            default_value = "exe",
            help_heading = "Advanced"
        )]
        binary_type: String,

        /// Shellcode placeholder marker in the loader binary.
        #[arg(long, default_value = "$$SHELLCODE$$", help_heading = "Advanced")]
        marker: String,

        /// Size-holder marker the loader reads at runtime.
        #[arg(long, default_value = "$$99999$$", help_heading = "Advanced")]
        size_holder: String,
    },

    /// Build a scaffolded loader crate and assemble its .b1n pack.
    Pack {
        /// Path to the scaffolded loader crate. Defaults to the current
        /// directory.
        #[arg(default_value = ".", value_hint = clap::ValueHint::DirPath)]
        crate_dir: PathBuf,

        /// Cargo profile to build with. Default `release` matches what
        /// `new-loader` recommends.
        #[arg(long, default_value = "release")]
        profile: String,

        /// Output .b1n path. Defaults to `<crate-dir>/<name>.b1n` where
        /// `<name>` is the metadata's `name` field.
        #[arg(short, long, value_hint = clap::ValueHint::FilePath)]
        output: Option<PathBuf>,

        /// Skip `cargo build`: assume the artifact is already on disk.
        /// Useful for repacking after a manual rebuild or when the build
        /// happens in CI.
        #[arg(long)]
        skip_build: bool,
    },

    /// Inspect a .b1n pack, loader binary, or generated implant.
    Inspect {
        /// Path to a .b1n loader pack or a compiled loader/implant binary.
        binary: PathBuf,
    },

    /// List and test modules.
    #[command(subcommand)]
    Module(ModuleCommands),

    /// Scaffold a marker-ready Rust loader crate.
    NewLoader {
        /// Path to write the new crate to. Must not exist.
        dest: PathBuf,

        /// Crate name. Defaults to the basename of <dest>.
        #[arg(long)]
        name: Option<String>,

        /// Target platform: linux | windows | darwin. Defaults to
        /// the current host's platform.
        #[arg(long, default_value_t = default_scaffold_platform())]
        platform: String,

        /// Shellcode placeholder capacity. PIC loaders want this
        /// tight; the 1 MiB default is sized for fat PE wrappers.
        /// Minimum 64 bytes (one cache line of slack for any
        /// shellcode the operator might stamp).
        #[arg(long, default_value_t = pumpbin::scaffold::DEFAULT_PAD_BYTES, value_name = "BYTES")]
        padding_bytes: usize,

        /// After scaffolding, immediately run `cargo build --release` and
        /// pack the resulting binary into a `.b1n`. Equivalent to running
        /// `pumpbin-cli pack <dest>` right after, but in one command.
        /// If the build or pack fails, the scaffold is still kept on disk.
        #[arg(long)]
        pack: bool,
    },

    /// Print shell completion script to stdout.
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: CompletionShell,
    },
}

/// Subcommands for `pumpbin-cli module`.
#[derive(clap::Subcommand)]
enum ModuleCommands {
    /// List all installed modules (built-in and drop-in).
    ///
    /// Shows each module's id, source, and description.
    /// Use `--options` to also show the per-module argument schema.
    List {
        /// Show each module's argument schema (key, type, required,
        /// default, description).
        #[arg(long)]
        options: bool,

        /// Limit output to one module id.
        #[arg(long, value_name = "ID")]
        id: Option<String>,
    },

    /// Run a module against a sample input (module author dev loop).
    ///
    /// Reads the payload from INPUT (or stdin with `-`), forwards
    /// `--arg` key=value pairs as the module's args, writes the response
    /// to `--output` (or stdout with `-`).
    Test {
        /// Module id. Looks up both built-in and drop-in registries.
        #[arg(value_name = "ID")]
        id: String,

        /// Input payload path, or `-`/omitted for stdin.
        #[arg(default_value = "-", value_hint = clap::ValueHint::AnyPath)]
        input: String,

        /// Repeatable key=value args forwarded to the module.
        #[arg(short = 'a', long = "arg", value_name = "KEY=VALUE")]
        args: Vec<String>,

        /// Output path or `-` for stdout.
        #[arg(short, long, default_value = "-")]
        output: String,

        /// Dump the wire protocol frames to stderr (for debugging
        /// external/drop-in modules).
        #[arg(long)]
        debug: bool,
    },
}

fn main() -> Result<()> {
    std::panic::set_hook(Box::new(|info| {
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("unknown panic");
        let loc = info
            .location()
            .map(|l| format!(" ({}:{})", l.file(), l.line()))
            .unwrap_or_default();
        eprintln!("pumpbin-cli: PANIC{loc}: {msg}");
        eprintln!("This is a bug. Please report it at https://github.com/pumpbin/pumpbin/issues");
    }));

    let cli = Cli::parse();

    // Install tracing subscriber driven by --log-level / PUMPBIN_LOG.
    let log_cfg = pumpbin::logging::LoggingConfig {
        level_override: cli.log_level.clone(),
    };
    let _ = pumpbin::logging::init(log_cfg);
    tracing::debug!("pumpbin-cli starting");

    dispatch(&cli)
}

/// Exit codes:
///   0: success
///   1: error (bad input, I/O failure, plugin error)
///   2: partial batch success
fn dispatch(cli: &Cli) -> Result<()> {
    match &cli.command {
        Commands::Generate {
            plugin,
            shellcode,
            platform,
            binary_type,
            output,
            dry_run,
            post,
        } => {
            let explicit_platform = platform.as_deref().map(parse_platform).transpose()?;
            let explicit_binary_type = binary_type.as_deref().map(parse_binary_type).transpose()?;

            let plugin_path = resolve_plugin_path(plugin)?;
            let plugin_label = plugin_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("pack");

            let plugin_buf = std::fs::read(&plugin_path)?;
            let mut plugin_obj = Plugin::decode_from_slice(&plugin_buf)?;

            let (parsed_platform, parsed_binary_type) = plugin_obj
                .bins()
                .auto_select_target(explicit_platform, explicit_binary_type)?;

            let target_label = format_target_label(parsed_platform, parsed_binary_type);

            pb_info!(plugin_label, target_label, "loading pack");

            let bin = plugin_obj
                .bins()
                .get_that_binary(parsed_platform, parsed_binary_type)
                .map(|b| b.to_vec())
                .ok_or(anyhow!(
                    "failed to retrieve binary for platform/type combination"
                ))?;

            plugin_obj.validate_shellcode_source(shellcode)?;
            let final_shellcode_src = shellcode.clone();
            let mut runtime_config = BTreeMap::new();

            // Append CLI-supplied post-build modules to the .b1n's chain.
            // Two forms accepted:
            //   --post <id>               plain id
            //   --post <id>:<k=v>        id with one key=value arg
            for entry in post {
                append_post_entry(&mut plugin_obj.plugins.modules, &mut runtime_config, entry)?;
            }
            plugin_obj.validate_for_generation(parsed_platform, parsed_binary_type)?;

            // Resolve output path before dry-run so we can show it in the preview.
            let output_path = resolve_output_path(
                output.as_ref(),
                &plugin_obj.info.plugin_name,
                parsed_platform,
                parsed_binary_type,
            );

            if *dry_run {
                println!("DRY RUN: nothing will be written\n");
                println!(
                    "  Pack:         {} (v{})",
                    plugin_obj.info.plugin_name, plugin_obj.info.version
                );
                println!(
                    "  Target:       {} / {}",
                    parsed_platform, parsed_binary_type
                );
                println!("  Output:       {}", output_path.display());
                let sc_size = std::fs::metadata(shellcode).map(|m| m.len()).ok();
                if let Some(sz) = sc_size {
                    println!("  Shellcode:    {shellcode} ({sz} B)");
                } else {
                    println!("  Shellcode:    {shellcode}");
                }
                // Show full pipeline: encrypt hook → post-build chain
                let encrypt_hook = plugin_obj.plugins.encrypt_shellcode.as_deref();
                let chain = plugin_obj.plugins.modules.as_slice();
                if encrypt_hook.is_none() && chain.is_empty() {
                    println!("  Module chain: (none)");
                } else {
                    let mut steps: Vec<String> = Vec::new();
                    if let Some(enc) = encrypt_hook {
                        steps.push(format!("{enc} (encrypt)"));
                    }
                    steps.extend(chain.iter().cloned());
                    println!("  Module chain: {}", steps.join(" → "));
                }
                for (k, v) in &runtime_config {
                    println!("  Config:       {k} = {v}");
                }
                return Ok(());
            }

            let sc_size = std::fs::metadata(shellcode).map(|m| m.len()).unwrap_or(0);
            let chain = plugin_obj.plugins.modules.as_slice().to_vec();
            if chain.is_empty() {
                pb_info!(
                    plugin_label,
                    target_label,
                    "injecting shellcode ({} B)",
                    sc_size
                );
            } else {
                pb_info!(
                    plugin_label,
                    target_label,
                    "injecting shellcode ({} B) + {}",
                    sc_size,
                    chain.join(", ")
                );
            }

            let bin = plugin_obj.replace_binary(
                bin,
                final_shellcode_src,
                vec![],
                Some(&runtime_config),
            )?;

            pumpbin::utils::atomic_write(&output_path, &bin)?;
            let display_path = output_path
                .canonicalize()
                .unwrap_or_else(|_| output_path.clone());
            pb_ok!(
                plugin_label,
                target_label,
                "wrote {}",
                display_path.display()
            );
            println!("{}", display_path.display());

            Ok(())
        }
        Commands::Batch {
            plugin,
            directory,
            platform,
            binary_type,
            output_dir,
            extension,
        } => {
            tracing::info!("Starting automated Batch generation");

            let explicit_platform = platform.as_deref().map(parse_platform).transpose()?;
            let explicit_binary_type = binary_type.as_deref().map(parse_binary_type).transpose()?;

            let plugin_path = resolve_plugin_path(plugin)?;
            let plugin_label = plugin_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("pack");

            tracing::info!(pack = ?plugin_path, "Loading pack");
            let plugin_buf = std::fs::read(&plugin_path)?;
            let plugin_obj = Plugin::decode_from_slice(&plugin_buf)?;
            let runtime_config = BTreeMap::new();

            let (parsed_platform, parsed_binary_type) = plugin_obj
                .bins()
                .auto_select_target(explicit_platform, explicit_binary_type)?;
            if explicit_platform.is_none() || explicit_binary_type.is_none() {
                tracing::info!(
                    platform = %parsed_platform,
                    binary_type = %parsed_binary_type,
                    "Auto-detected target from .b1n"
                );
            }

            let target_label = format_target_label(parsed_platform, parsed_binary_type);

            tracing::info!(%parsed_platform, %parsed_binary_type, "Validating plugin for target");
            plugin_obj.validate_for_generation(parsed_platform, parsed_binary_type)?;

            let save_type = if plugin_obj.replace.size_holder.as_ref().is_some() {
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

            let ext_filter = extension.as_str();

            // Collect matching files first so we know the total for progress.
            let mut bin_files: Vec<PathBuf> = Vec::new();
            let mut seen_extensions: std::collections::BTreeSet<String> =
                std::collections::BTreeSet::new();
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let file_ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
                    if file_ext == ext_filter {
                        bin_files.push(path);
                    } else if !file_ext.is_empty() {
                        seen_extensions.insert(file_ext.to_string());
                    }
                }
            }

            if bin_files.is_empty() {
                let diag = if seen_extensions.is_empty() {
                    format!(
                        "Batch found zero .{ext_filter} files in {}. The directory contains no files with extensions.",
                        directory.display()
                    )
                } else {
                    format!(
                        "Batch found zero .{ext_filter} files in {}. Extensions found: {}. \
                         Use --extension to match a different extension.",
                        directory.display(),
                        seen_extensions
                            .iter()
                            .map(|e| format!(".{e}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                bail!("{}", diag);
            }

            let total = bin_files.len();
            let mut success_count = 0;
            let mut fail_count = 0;

            for (idx_0, path) in bin_files.iter().enumerate() {
                let idx = idx_0 + 1;
                let progress_filename = path.file_name().unwrap_or_default().to_string_lossy();
                pb_info!(
                    plugin_label,
                    target_label,
                    "{idx}/{total} {progress_filename}"
                );

                tracing::info!(file = ?path.file_name().unwrap_or_default(), "Processing shellcode");

                let bin = plugin_obj
                    .bins()
                    .get_that_binary(parsed_platform, parsed_binary_type)
                    .map(|b| b.to_vec())
                    .ok_or(anyhow!(
                        "failed to retrieve binary for platform/type combination"
                    ))?;

                let data = match std::fs::read(path) {
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
                    .plugin_name
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
                     Confirm the directory contains .{} shellcode files.",
                    directory.display(),
                    ext_filter
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
            template,
            platform,
            binary_type,
            save_type,
            marker,
            size_holder,
            max_len,
            encrypt_module,
            post_modules,
            module_config,
        } => {
            let template_bytes = std::fs::read(template).with_context(|| {
                format!("failed to read template binary: {}", template.display())
            })?;
            let parsed_platform = match platform.as_deref() {
                Some(platform) => parse_platform(platform)?,
                None => detect_platform_from_binary(&template_bytes).ok_or_else(|| {
                    anyhow!(
                        "could not auto-detect template platform; pass --platform windows|linux|darwin"
                    )
                })?,
            };
            let parsed_binary_type = parse_binary_type(binary_type)?;
            let parsed_save_type = parse_save_type(save_type)?;
            let pack_name = name.clone().unwrap_or_else(|| {
                output
                    .file_stem()
                    .or_else(|| template.file_stem())
                    .and_then(|s| s.to_str())
                    .unwrap_or("loader")
                    .to_string()
            });

            // Validate that --encrypt-module is actually an encrypt-kind module.
            if let Some(id) = encrypt_module.as_deref() {
                let known: Vec<&str> = pumpbin::modules::encrypt_modules()
                    .iter()
                    .map(|m| m.id())
                    .collect();
                if !known.contains(&id) {
                    bail!(
                        "--encrypt-module '{id}' is not an encrypt module. \
                         Available encrypt modules: {}. \
                         For post-build transforms use --post instead.",
                        known.join(", ")
                    );
                }
            }

            let mut cfg = parse_module_config(module_config)?;

            // post_modules accepts both `--post id` and `--post id:k=v`.
            let mut resolved_post_modules = vec![];
            for entry in post_modules {
                append_post_entry(&mut resolved_post_modules, &mut cfg, entry)?;
            }

            let data = pumpbin::pack::B1nBuilder {
                template_bytes,
                name: pack_name,
                author: "pumpbin-cli".to_string(),
                plugin_version: "0.1.0".to_string(),
                desc: "Created by pumpbin-cli create-b1n".to_string(),
                platform: parsed_platform,
                binary_type: parsed_binary_type,
                save_type: parsed_save_type,
                src_prefix: marker.clone(),
                size_holder: size_holder.clone(),
                max_len_override: *max_len,
                primary_module: encrypt_module.clone(),
                post_modules: resolved_post_modules,
                module_config: cfg,
            }
            .assemble()
            .with_context(|| format!("template at '{}'", template.display()))?;

            pumpbin::utils::atomic_write(output, &data)
                .with_context(|| format!("failed to write output .b1n: {}", output.display()))?;

            tracing::info!(output = %output.display(), "Created .b1n loader pack");
            Ok(())
        }
        Commands::Stamp {
            loader,
            shellcode,
            output,
            platform,
            binary_type,
            marker,
            size_holder,
            save_b1n,
            dry_run,
            post,
        } => {
            let template_bytes = std::fs::read(loader)
                .with_context(|| format!("failed to read loader: {}", loader.display()))?;

            let loader_label = loader
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("loader");

            let parsed_platform = if let Some(p) = platform.as_deref() {
                parse_platform(p)?
            } else {
                detect_platform_from_binary(&template_bytes).ok_or_else(|| {
                    anyhow!(
                        "could not detect platform from '{}' (unrecognized magic bytes); \
                         pass --platform explicitly",
                        loader.display()
                    )
                })?
            };
            let parsed_binary_type = parse_binary_type(binary_type)?;

            let target_label = format_target_label(parsed_platform, parsed_binary_type);

            eprintln!(
                "PB  {:<20}  {}  [*] reading loader",
                loader_label, target_label
            );
            let b1n_bytes = pumpbin::pack::B1nBuilder {
                template_bytes,
                name: loader
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("stamp")
                    .to_string(),
                author: "pumpbin-cli stamp".to_string(),
                plugin_version: "0.1.0".to_string(),
                desc: "Created by pumpbin-cli stamp".to_string(),
                platform: parsed_platform,
                binary_type: parsed_binary_type,
                save_type: ShellcodeSaveType::Local,
                src_prefix: marker.clone(),
                size_holder: size_holder.clone(),
                max_len_override: None,
                primary_module: None,
                post_modules: vec![],
                module_config: BTreeMap::new(),
            }
            .assemble()
            .map_err(|e| {
                if e.chain()
                    .any(|c| c.to_string().contains("not found in binary"))
                {
                    anyhow!(
                        "{loader} does not contain the shellcode marker \"{marker}\".\n\n\
                         The loader must include this exact byte sequence at compile time \
                         so PumpBin knows where to write your shellcode.\n\n\
                         Options:\n  \
                         1. Build a marker-ready loader:  pumpbin-cli new-loader myloader --platform {platform_hint} --pack\n  \
                         2. Verify an existing binary:    pumpbin-cli inspect {loader}",
                        loader = loader.display(),
                        marker = marker,
                        platform_hint = platform
                            .as_deref()
                            .unwrap_or(match parsed_platform {
                                Platform::Windows => "windows",
                                Platform::Linux => "linux",
                                Platform::Darwin => "darwin",
                            }),
                    )
                } else {
                    e.context(format!("assembling .b1n from '{}'", loader.display()))
                }
            })?;

            if let Some(b1n_path) = save_b1n {
                pumpbin::utils::atomic_write(b1n_path, &b1n_bytes)
                    .with_context(|| format!("saving .b1n to '{}'", b1n_path.display()))?;
                eprintln!(
                    "PB  {:<20}  {}  [*] saved .b1n -> {}",
                    loader_label,
                    target_label,
                    b1n_path.display()
                );
            }

            let mut plugin_obj = Plugin::decode_from_slice(&b1n_bytes)?;

            let mut runtime_config = parse_module_config(&[])?;
            for entry in post {
                append_post_entry(&mut plugin_obj.plugins.modules, &mut runtime_config, entry)?;
            }

            let (resolved_platform, resolved_binary_type) = plugin_obj
                .bins()
                .auto_select_target(Some(parsed_platform), Some(parsed_binary_type))?;
            plugin_obj.validate_for_generation(resolved_platform, resolved_binary_type)?;

            let bin = plugin_obj
                .bins()
                .get_that_binary(resolved_platform, resolved_binary_type)
                .map(|b| b.to_vec())
                .ok_or_else(|| {
                    anyhow!("failed to retrieve binary for platform/type combination")
                })?;

            plugin_obj.validate_shellcode_source(shellcode)?;

            let sc_bytes = std::fs::read(shellcode.as_str())
                .with_context(|| format!("failed to read shellcode: {}", shellcode))?;
            let sc_size = sc_bytes.len();
            let chain = plugin_obj.plugins.modules.as_slice().to_vec();

            let output_base = loader
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("stamp");
            let output_path = resolve_output_path(
                output.as_ref(),
                output_base,
                resolved_platform,
                resolved_binary_type,
            );

            if *dry_run {
                println!("DRY RUN: nothing will be written\n");
                println!("  Loader:       {}", loader.display());
                println!("  Pack:         {}", plugin_obj.info.plugin_name);
                println!(
                    "  Target:       {} / {}",
                    resolved_platform, resolved_binary_type
                );
                println!("  Output:       {}", output_path.display());
                if let Some(b1n_path) = save_b1n {
                    println!("  Save pack:    {}", b1n_path.display());
                }
                println!("  Shellcode:    {shellcode} ({sc_size} B)");
                if chain.is_empty() {
                    println!("  Module chain: (none)");
                } else {
                    println!("  Module chain: {}", chain.join(" -> "));
                }
                for (k, v) in &runtime_config {
                    println!("  Config:       {k} = {v}");
                }
                return Ok(());
            }

            if chain.is_empty() {
                eprintln!(
                    "PB  {:<20}  {}  [*] injecting shellcode ({} B)",
                    loader_label, target_label, sc_size
                );
            } else {
                eprintln!(
                    "PB  {:<20}  {}  [*] injecting shellcode ({} B) + {}",
                    loader_label,
                    target_label,
                    sc_size,
                    chain.join(", ")
                );
            }

            let implant =
                plugin_obj.replace_binary(bin, shellcode.clone(), vec![], Some(&runtime_config))?;

            pumpbin::utils::atomic_write(&output_path, &implant)
                .with_context(|| format!("writing implant to '{}'", output_path.display()))?;
            let display_path = output_path
                .canonicalize()
                .unwrap_or_else(|_| output_path.clone());
            eprintln!(
                "PB  {:<20}  {}  [+] wrote {}",
                loader_label,
                target_label,
                display_path.display()
            );
            println!("{}", display_path.display());

            Ok(())
        }
        Commands::Pack {
            crate_dir,
            profile,
            output,
            skip_build,
        } => pack_crate(crate_dir, profile, output.as_deref(), *skip_build),
        Commands::Inspect { binary } => {
            let bytes = std::fs::read(binary)
                .with_context(|| format!("failed to read '{}'", binary.display()))?;
            let is_b1n = pumpbin::plugin::Plugin::decode_from_slice(&bytes).is_ok();
            if !is_b1n {
                inspect_loader_binary(binary, &bytes);
                return Ok(());
            }

            let report = pumpbin::inspect::inspect(binary)?;
            print!("{}", pumpbin::inspect::render_text(&report));
            Ok(())
        }
        Commands::Module(sub) => match sub {
            ModuleCommands::List { options, id } => list_modules(*options, id.as_deref()),
            ModuleCommands::Test {
                id,
                input,
                args,
                output,
                debug,
            } => {
                use pumpbin::modules::external::wire::WireKind;
                use std::io::{Read, Write};

                if *debug {
                    // SAFETY: single-threaded CLI; env var is read only inside
                    // external::invoke() on this same thread.
                    unsafe { std::env::set_var("PUMPBIN_MODULE_DEBUG", "1") };
                }

                let payload: Vec<u8> = if input == "-" {
                    let mut buf = Vec::new();
                    std::io::stdin().read_to_end(&mut buf)?;
                    buf
                } else {
                    std::fs::read(input)?
                };

                let kind = pumpbin::modules::wire_kind_for(id).ok_or_else(|| {
                anyhow!(
                    "module test: id '{id}' not registered. Run `pumpbin-cli module list` to see what's installed."
                )
            })?;

                let result: Vec<u8> = match kind {
                    WireKind::Encrypt => {
                        let out = pumpbin::modules::dispatch::encrypt(id, args, &payload)?;
                        eprintln!(
                            "module '{id}' encrypted {} → {} bytes; {} pass entries:",
                            payload.len(),
                            out.encrypted.len(),
                            out.pass.len(),
                        );
                        for p in &out.pass {
                            eprintln!(
                                "  holder={}  replace_by=<{} bytes>",
                                String::from_utf8_lossy(&p.holder),
                                p.replace_by.len()
                            );
                        }
                        out.encrypted
                    }
                    WireKind::PostBuild => {
                        let before = payload.clone();
                        let mut buf = payload;
                        pumpbin::modules::dispatch::post_build(id, args, &mut buf)?;
                        let changed = before
                            .iter()
                            .zip(buf.iter())
                            .filter(|(a, b)| a != b)
                            .count();
                        eprintln!(
                            "module '{id}' post-build: {} → {} bytes ({changed} bytes changed)",
                            before.len(),
                            buf.len()
                        );
                        buf
                    }
                };

                if output == "-" {
                    std::io::stdout().write_all(&result)?;
                } else {
                    std::fs::write(output, &result)?;
                    if output != "-" {
                        eprintln!("wrote {output}");
                    }
                }
                Ok(())
            }
        }, // end Commands::Module
        Commands::NewLoader {
            dest,
            name,
            platform,
            padding_bytes,
            pack,
        } => {
            let dest = dest.as_path();
            let crate_name = name.clone().unwrap_or_else(|| {
                dest.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("loader")
                    .to_string()
            });
            let parsed_platform = parse_platform(platform)?;
            if *padding_bytes < 64 {
                return Err(anyhow!(
                    "--padding-bytes must be at least 64 (got {padding_bytes}); the placeholder needs enough room for any shellcode the operator will stamp"
                ));
            }
            let opts = pumpbin::scaffold::LoaderOpts {
                padding_bytes: *padding_bytes,
            };
            pumpbin::scaffold::write_loader_scaffold(dest, &crate_name, parsed_platform, opts)?;
            tracing::info!(
                dest = %dest.display(),
                name = %crate_name,
                platform = %parsed_platform,
                padding_bytes = padding_bytes,
                "Scaffolded loader crate",
            );
            if *pack {
                if let Err(e) = pack_crate(dest, "release", None, false) {
                    eprintln!("warning: scaffold succeeded but pack failed: {e}");
                    eprintln!("  retry with: pumpbin-cli pack {}", dest.display());
                } else {
                    println!(
                        "Scaffolded and packed: {0}/{1}.b1n",
                        dest.display(),
                        crate_name
                    );
                }
            } else {
                println!(
                    "Scaffolded loader crate at {0}.\n  pumpbin-cli pack {0}    # build + assemble .b1n in one step",
                    dest.display(),
                );
            }
            Ok(())
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let generator: Shell = shell.clone().into();
            generate(generator, &mut cmd, "pumpbin-cli", &mut std::io::stdout());
            Ok(())
        }
    }
}

fn list_modules(show_options: bool, only_id: Option<&str>) -> Result<()> {
    use pumpbin::modules::external::registry;

    let ext = registry();
    let descriptors = pumpbin::modules::descriptors();

    let print_section = |title: &str, kind: &str| {
        let filtered: Vec<_> = descriptors
            .iter()
            .filter(|descriptor| descriptor.kind == kind)
            .filter(|descriptor| only_id.is_none_or(|want| descriptor.id == want))
            .collect();
        if filtered.is_empty() {
            return;
        }
        println!("{title}:");
        for descriptor in filtered {
            println!(
                "  {} ({}): {}",
                descriptor.id, descriptor.source, descriptor.description
            );
            if show_options {
                let constraints = descriptor.constraints.display_strings();
                if !constraints.is_empty() {
                    println!("    constraints: {}", constraints.join(", "));
                }
                if descriptor.args.is_empty() {
                    println!("    (no documented args)");
                } else {
                    for arg in &descriptor.args {
                        let req = if arg.required { " (required)" } else { "" };
                        let dflt = arg
                            .default
                            .as_deref()
                            .map(|d| format!(" [default: {d}]"))
                            .unwrap_or_default();
                        println!(
                            "    {key}: {ty}{req}{dflt}",
                            key = arg.key,
                            ty = arg.arg_type,
                            req = req,
                            dflt = dflt,
                        );
                        if !arg.description.is_empty() {
                            println!("        {}", arg.description);
                        }
                    }
                }
            }
        }
    };

    let found_any = only_id
        .map(|want| descriptors.iter().any(|descriptor| descriptor.id == want))
        .unwrap_or_else(|| !descriptors.is_empty());

    print_section("encrypt", "encrypt");
    print_section("post_build", "post-build");

    if let Some(want) = only_id {
        if !found_any {
            return Err(anyhow!(
                "module list: no module with id '{want}'. Drop --id to see what's installed."
            ));
        }
    }

    for w in ext.warnings() {
        eprintln!("warning: {w}");
    }
    Ok(())
}

/// If `plugin` is a directory, resolve to `<dir>/<name>.b1n` using
/// `[package.metadata.pumpbin]` in that crate's Cargo.toml.
/// Returns the path unchanged when it's already a file.
fn resolve_plugin_path(plugin: &Path) -> Result<PathBuf> {
    if plugin.is_dir() {
        let (_, md) = pumpbin::pack::read_loader_metadata(plugin)?;
        let b1n = plugin.join(format!("{}.b1n", md.name));
        if !b1n.exists() {
            bail!(
                "no .b1n at {}; run `pumpbin-cli pack {}` first",
                b1n.display(),
                plugin.display()
            );
        }
        Ok(b1n)
    } else {
        Ok(plugin.to_path_buf())
    }
}

/// Inspect a raw loader binary for PumpBin shellcode markers.
/// Called by `inspect` when the path is not a recognisable .b1n.
fn inspect_loader_binary(path: &Path, bytes: &[u8]) {
    use pumpbin::scaffold::{DEFAULT_PREFIX, DEFAULT_SIZE_HOLDER};

    let file_size = bytes.len();
    let platform = detect_platform_from_binary(bytes)
        .map(|p| p.to_string().to_lowercase())
        .unwrap_or_else(|| "unknown".to_string());

    // Scan for the shellcode prefix.
    let prefix = DEFAULT_PREFIX.as_bytes();
    let size_holder = DEFAULT_SIZE_HOLDER.as_bytes();

    let prefix_offset = memchr::memmem::find(bytes, prefix);
    let size_holder_offset = memchr::memmem::find(bytes, size_holder);

    // Measure padding capacity: count constant bytes after the prefix.
    let capacity = prefix_offset.map(|off| {
        let start = off + prefix.len();
        if start >= bytes.len() {
            return 0;
        }
        let pad = bytes[start];
        bytes[start..].iter().take_while(|&&b| b == pad).count()
    });

    let marker_found = prefix_offset.is_some();
    let holder_found = size_holder_offset.is_some();
    let suitable = marker_found && holder_found;

    println!("file:      {} ({} bytes)", path.display(), file_size);
    println!("format:    {}", platform);
    println!();
    println!("markers:");
    match prefix_offset {
        Some(off) => println!("  shellcode    {:?}   offset 0x{:X}", DEFAULT_PREFIX, off),
        None => println!("  shellcode    {:?}   NOT FOUND", DEFAULT_PREFIX),
    }
    match size_holder_offset {
        Some(off) => println!(
            "  size-holder  {:?}   offset 0x{:X}",
            DEFAULT_SIZE_HOLDER, off
        ),
        None => println!("  size-holder  {:?}   NOT FOUND", DEFAULT_SIZE_HOLDER),
    }
    println!();
    match capacity {
        Some(n) if n > 0 => println!("capacity:  {} bytes ({} KiB)", n, n / 1024),
        _ => println!("capacity:  unknown"),
    }
    println!();
    if suitable {
        println!("verdict:   SUITABLE: ready for pumpbin-cli stamp");
    } else {
        println!("verdict:   NOT SUITABLE: add markers before stamping");
    }
}

fn default_scaffold_platform() -> String {
    if cfg!(target_os = "linux") {
        "linux".to_string()
    } else if cfg!(target_os = "windows") {
        "windows".to_string()
    } else if cfg!(target_os = "macos") {
        "darwin".to_string()
    } else {
        "linux".to_string()
    }
}

fn pack_crate(
    crate_dir: &Path,
    profile: &str,
    output_override: Option<&Path>,
    skip_build: bool,
) -> Result<()> {
    let (cargo_pkg_name, md) = pumpbin::pack::read_loader_metadata(crate_dir)?;
    let platform = parse_platform(&md.platform)?;
    let binary_type = parse_binary_type(&md.binary_type)?;
    let save_type = parse_save_type(&md.save_type)?;

    let crate_label = crate_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("loader");
    let target_str = format_target_label(platform, binary_type);

    // 1. Build the crate (unless --skip-build).
    if !skip_build {
        eprintln!(
            "PB  {:<20}  {}  [*] cargo build ({})",
            crate_label, target_str, profile
        );
        let cargo_args: &[&str] = if profile == "release" {
            &["build", "--release"]
        } else if profile == "dev" || profile == "debug" {
            &["build"]
        } else {
            // Custom Cargo profiles: pass --profile <name>.
            &["build", "--profile"]
        };
        let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        cmd.current_dir(crate_dir);
        for a in cargo_args {
            cmd.arg(a);
        }
        if cargo_args.last() == Some(&"--profile") {
            cmd.arg(profile);
        }
        let status = cmd
            .status()
            .with_context(|| format!("failed to invoke cargo in {}", crate_dir.display()))?;
        if !status.success() {
            bail!(
                "cargo build (profile `{}`) failed in {} with status {}",
                profile,
                crate_dir.display(),
                status
            );
        }
    }

    // 2. Locate the built artifact.
    // Cargo's `dev`/`debug` profile writes to target/debug, not target/dev.
    let artifact_subdir = if profile == "dev" { "debug" } else { profile };
    let template_path = pumpbin::pack::expected_artifact_path(
        crate_dir,
        &cargo_pkg_name,
        platform,
        binary_type,
        artifact_subdir,
    );
    let template_bytes = std::fs::read(&template_path).with_context(|| {
        format!(
            "no built artifact at {} -- did `cargo build --{}` succeed?",
            template_path.display(),
            profile
        )
    })?;

    // 3. Assemble baseline module config + bake in the metadata's
    // default post chain.
    let mut cfg = BTreeMap::new();
    let mut post_modules = Vec::new();
    for post in &md.post {
        post_modules.push(post.id.clone());
        if !post.config.is_empty() {
            let args = post
                .config
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(";");
            cfg.insert(format!("post:{}", post.id), args);
        }
    }

    let data = pumpbin::pack::B1nBuilder {
        template_bytes,
        name: md.name.clone(),
        author: md.author,
        plugin_version: md.plugin_version,
        desc: md.description,
        platform,
        binary_type,
        save_type,
        src_prefix: md.src_prefix,
        size_holder: md.size_holder,
        max_len_override: md.max_len,
        primary_module: None,
        post_modules,
        module_config: cfg,
    }
    .assemble()
    .with_context(|| format!("assembling .b1n from {}", template_path.display()))?;

    // 4. Resolve output path: explicit > <crate>/<name>.b1n.
    let output_path = match output_override {
        Some(p) => p.to_path_buf(),
        None => crate_dir.join(format!("{}.b1n", md.name)),
    };

    pumpbin::utils::atomic_write(&output_path, &data)
        .with_context(|| format!("writing {}", output_path.display()))?;

    eprintln!(
        "PB  {:<20}  {}  [+] packed -> {}",
        crate_label,
        target_str,
        output_path.display()
    );
    println!("wrote {}", output_path.display());
    Ok(())
}

fn parse_platform(s: &str) -> Result<Platform> {
    match s.to_lowercase().as_str() {
        "windows" | "win" => Ok(Platform::Windows),
        "linux" => Ok(Platform::Linux),
        "darwin" | "macos" | "osx" | "mac" => Ok(Platform::Darwin),
        _ => Err(anyhow!(
            "Invalid platform '{}'. Expected: windows (win), linux, darwin (macos/osx)",
            s
        )),
    }
}

/// Infer the target platform from a binary's magic bytes.
/// Returns `None` when the format is unknown (raw shellcode, custom binary, etc.).
fn detect_platform_from_binary(bytes: &[u8]) -> Option<Platform> {
    if bytes.starts_with(b"MZ") {
        return Some(Platform::Windows);
    }
    if bytes.starts_with(b"\x7fELF") {
        return Some(Platform::Linux);
    }
    // Mach-O 64-bit and 32-bit little-endian magic
    if bytes.starts_with(b"\xcf\xfa\xed\xfe") || bytes.starts_with(b"\xce\xfa\xed\xfe") {
        return Some(Platform::Darwin);
    }
    None
}

fn parse_binary_type(s: &str) -> Result<BinaryType> {
    match s.to_lowercase().as_str() {
        "exe" => Ok(BinaryType::Executable),
        "lib" | "dll" | "so" | "dylib" | "shared" => Ok(BinaryType::DynamicLibrary),
        _ => Err(anyhow!(
            "Invalid target type '{}'. Expected: exe, lib (dll/so/dylib)",
            s
        )),
    }
}

fn format_target_label(platform: Platform, binary_type: BinaryType) -> String {
    let platform = match platform {
        Platform::Windows => "win",
        Platform::Linux => "linux",
        Platform::Darwin => "darwin",
    };
    let binary_type = match binary_type {
        BinaryType::Executable => "exe",
        BinaryType::DynamicLibrary => "lib",
    };
    format!("{platform}/{binary_type}")
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

fn resolve_output_path(
    output: Option<&PathBuf>,
    base_name: &str,
    platform: Platform,
    binary_type: BinaryType,
) -> PathBuf {
    if let Some(output) = output {
        return output.clone();
    }

    let ext = ext_for_output(platform, binary_type);
    let base = base_name.to_lowercase().replace(' ', "_");
    let candidate = PathBuf::from(format!("{base}.{ext}"));
    if candidate.exists() {
        let ts = Local::now().format("%Y%m%d_%H%M%S").to_string();
        PathBuf::from(format!("{base}_{ts}.{ext}"))
    } else {
        candidate
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

fn parse_post_entry(entry: &str) -> Result<(String, Option<String>)> {
    let (id, arg) = match entry.split_once(':') {
        Some((id, arg)) => (id.trim(), Some(arg.trim())),
        None => (entry.trim(), None),
    };

    if id.is_empty() {
        bail!("Invalid --post value '{}': empty module id", entry);
    }
    if let Some(arg) = arg {
        let Some((key, _)) = arg.split_once('=') else {
            bail!("Invalid --post value '{}': expected id:key=value", entry);
        };
        if key.trim().is_empty() {
            bail!("Invalid --post value '{}': empty arg key", entry);
        }
    }

    Ok((id.to_string(), arg.map(str::to_string)))
}

fn append_post_entry(
    modules: &mut Vec<String>,
    config: &mut BTreeMap<String, String>,
    entry: &str,
) -> Result<()> {
    let (id, arg) = parse_post_entry(entry)?;
    if modules.last() != Some(&id) {
        modules.push(id.clone());
    }
    if let Some(arg) = arg {
        config
            .entry(format!("post:{id}"))
            .and_modify(|existing| {
                if !existing.is_empty() {
                    existing.push(';');
                }
                existing.push_str(&arg);
            })
            .or_insert(arg);
    }
    Ok(())
}
