#![allow(unused)]

use std::path::PathBuf;
use clap::{Parser, Subcommand};
use anyhow::{anyhow, Result};
use pumpbin::plugin::Plugin;
use pumpbin::{Platform, ShellcodeSaveType};
use chrono::Local;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate an implant from a plugin and shellcode
    Generate {
        /// Path to the PumpBin plugin (.b1n)
        #[arg(short, long)]
        plugin: PathBuf,

        /// Path to the shellcode (.bin) or a remote URL
        #[arg(short, long)]
        shellcode: String,

        /// Target platform (windows, linux, darwin)
        #[arg(long)]
        platform: String,

        /// Target binary type (exe, lib)
        #[arg(short = 't', long = "type")]
        binary_type: String,

        /// Output file path (optional)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Generate multiple implants from a directory of shellcodes
    Batch {
        /// Path to the PumpBin plugin (.b1n)
        #[arg(short, long)]
        plugin: PathBuf,

        /// Path to the directory containing shellcode (.bin) files
        #[arg(short, long)]
        directory: PathBuf,

        /// Target platform (windows, linux, darwin)
        #[arg(long)]
        platform: String,

        /// Target binary type (exe, lib)
        #[arg(short = 't', long = "type")]
        binary_type: String,

        /// Output directory path (optional)
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Generate {
            plugin,
            shellcode,
            platform,
            binary_type,
            output,
        } => {
            println!("Starting automated CLI generation...");
            
            // Validate arguments
            let parsed_platform = parse_platform(platform)?;
            let parsed_binary_type = parse_binary_type(binary_type)?;

            // Rest of generation logic will go here
            println!("Loading plugin from {:?}", plugin);
            let plugin_buf = std::fs::read(&plugin)?;
            let mut plugin_obj = Plugin::decode_from_slice(&plugin_buf)?;
            
            println!("Validating plugin for platform {} and type {}...", platform, binary_type);
            plugin_obj.validate_for_generation(parsed_platform, parsed_binary_type)?;

            // Extract the skeleton binary
            let mut bin = plugin_obj.bins().get_that_binary(parsed_platform, parsed_binary_type);

            plugin_obj.validate_shellcode_source(shellcode)?;
            let final_shellcode_src = shellcode.clone();

            println!("Injecting shellcode...");
            // We pass an empty password vector for the CLI by default as headless generation
            // typically assumes raw shellcode or handles encryption out of band for now.
            plugin_obj.replace_binary(&mut bin, final_shellcode_src, vec![])?;

            // Determine output path filename
            let output_path = if let Some(out) = output {
                out.clone()
            } else {
                let now = Local::now();
                let timestamp = now.format("%Y%m%d_%H%M%S").to_string();
                let plugin_name_sanitized = plugin_obj.info().plugin_name().to_lowercase().replace(' ', "_");
                let platform_str = parsed_platform.to_string().to_lowercase();
                let bin_type_str = match parsed_binary_type {
                    pumpbin::BinaryType::Executable => "exe",
                    pumpbin::BinaryType::DynamicLibrary => "dll"
                };
                let ext = match (parsed_platform, parsed_binary_type) {
                    (Platform::Windows, pumpbin::BinaryType::Executable) => "exe",
                    (Platform::Windows, pumpbin::BinaryType::DynamicLibrary) => "dll",
                    (Platform::Linux, pumpbin::BinaryType::Executable) => "elf",
                    (Platform::Linux, pumpbin::BinaryType::DynamicLibrary) => "so",
                    (Platform::Darwin, pumpbin::BinaryType::Executable) => "macho",
                    (Platform::Darwin, pumpbin::BinaryType::DynamicLibrary) => "dylib",
                };
                PathBuf::from(format!("{}_{}_{}_{}.{}", plugin_name_sanitized, platform_str, bin_type_str, timestamp, ext))
            };

            println!("Saving to {:?}", output_path);
            std::fs::write(&output_path, bin)?;
            println!("Generation complete!");

            Ok(())
        }
        Commands::Batch {
            plugin,
            directory,
            platform,
            binary_type,
            output_dir,
        } => {
            println!("Starting automated Batch generation...");
            
            let parsed_platform = parse_platform(platform)?;
            let parsed_binary_type = parse_binary_type(binary_type)?;

            println!("Loading plugin from {:?}", plugin);
            let plugin_buf = std::fs::read(&plugin)?;
            let plugin_obj = Plugin::decode_from_slice(&plugin_buf)?;
            
            println!("Validating plugin for platform {} and type {}...", platform, binary_type);
            plugin_obj.validate_for_generation(parsed_platform, parsed_binary_type)?;

            // Determine save type
            let save_type = if plugin_obj.replace().size_holder().is_some() {
                ShellcodeSaveType::Local
            } else {
                ShellcodeSaveType::Remote
            };

            if save_type == ShellcodeSaveType::Remote {
                return Err(anyhow!("Batch generation does not support remote shellcode URLs at this time."));
            }

            // Ensure output directory exists if provided
            let out_dir = match output_dir {
                Some(dir) => {
                    if !dir.exists() {
                        std::fs::create_dir_all(&dir)?;
                    }
                    dir.clone()
                },
                None => std::env::current_dir()?,
            };

            // Scan directory
            println!("Scanning directory {:?} for shellcode files...", directory);
            let entries = std::fs::read_dir(directory)?;
            
            let mut success_count = 0;
            let mut fail_count = 0;

            for entry in entries {
                let entry = entry?;
                let path = entry.path();

                if path.is_file() {
                    let is_bin = path.extension().and_then(|ext| ext.to_str()).unwrap_or("") == "bin";
                    if is_bin {
                        println!("[-] Processing {:?}", path.file_name().unwrap_or_default());
                        
                        // Extract fresh binary each iteration
                        let mut bin = plugin_obj.bins().get_that_binary(parsed_platform, parsed_binary_type);
                        
                        let data = match std::fs::read(&path) {
                            Ok(d) => d,
                            Err(e) => {
                                eprintln!("  [!] Failed to read {:?}: {}", path, e);
                                fail_count += 1;
                                continue;
                            }
                        };

                        if data.is_empty() {
                            eprintln!("  [!] Shellcode file is empty: {:?}", path);
                            fail_count += 1;
                            continue;
                        }
                        if data.windows(b"$$SHELLCODE$$".len()).any(|w| w == b"$$SHELLCODE$$") {
                            eprintln!("  [!] Shellcode file contains placeholder: {:?}", path);
                            fail_count += 1;
                            continue;
                        }

                        let shellcode_src = path.to_string_lossy().to_string();
                        if let Err(e) = plugin_obj.validate_shellcode_source(&shellcode_src) {
                            eprintln!("  [!] Invalid shellcode source: {}", e);
                            fail_count += 1;
                            continue;
                        }
                        // Need a mutable clone of the plugin to allow `replace_binary` to mutate internal state if needed
                        let mut plugin_clone = plugin_obj.clone();
                        
                        if let Err(e) = plugin_clone.replace_binary(&mut bin, shellcode_src, vec![]) {
                            eprintln!("  [!] Failed to inject shellcode: {}", e);
                            fail_count += 1;
                            continue;
                        }

                        // Determine output path filename
                        let now = Local::now();
                        let timestamp = now.format("%H%M%S").to_string();
                        let plugin_name_sanitized = plugin_clone.info().plugin_name().to_lowercase().replace(' ', "_");
                        let shellcode_name = path.file_stem().unwrap_or_default().to_string_lossy().to_lowercase().replace(' ', "_");
                        let ext = match (parsed_platform, parsed_binary_type) {
                            (Platform::Windows, pumpbin::BinaryType::Executable) => "exe",
                            (Platform::Windows, pumpbin::BinaryType::DynamicLibrary) => "dll",
                            (Platform::Linux, pumpbin::BinaryType::Executable) => "elf",
                            (Platform::Linux, pumpbin::BinaryType::DynamicLibrary) => "so",
                            (Platform::Darwin, pumpbin::BinaryType::Executable) => "macho",
                            (Platform::Darwin, pumpbin::BinaryType::DynamicLibrary) => "dylib",
                        };
                        
                        let filename = format!("{}_{}_{}.{}", plugin_name_sanitized, shellcode_name, timestamp, ext);
                        let output_path = out_dir.join(filename);

                        if let Err(e) = std::fs::write(&output_path, bin) {
                            eprintln!("  [!] Failed to save generated binary: {}", e);
                            fail_count += 1;
                            continue;
                        }

                        println!("  [+] Saved as {:?}", output_path.file_name().unwrap_or_default());
                        success_count += 1;
                    }
                }
            }

            println!("Batch generation complete! Success: {}, Failed: {}", success_count, fail_count);
            Ok(())
        }
    }
}

// Helpers to avoid tightly coupling clap to our library enums.
fn parse_platform(s: &str) -> Result<Platform> {
    match s.to_lowercase().as_str() {
        "windows" => Ok(Platform::Windows),
        "linux" => Ok(Platform::Linux),
        "darwin" => Ok(Platform::Darwin),
        _ => Err(anyhow!("Invalid platform '{}'. Expected: windows, linux, darwin", s)),
    }
}

fn parse_binary_type(s: &str) -> Result<pumpbin::BinaryType> {
    match s.to_lowercase().as_str() {
        "exe" => Ok(pumpbin::BinaryType::Executable),
        "lib" => Ok(pumpbin::BinaryType::DynamicLibrary),
        _ => Err(anyhow!("Invalid target type '{}'. Expected: exe, lib", s)),
    }
}
