use std::fs;
use std::path::{Path, PathBuf};
use std::io::{self};
use anyhow::{Result, Context, bail};
use regex::Regex;

#[derive(Debug, Clone)]
struct ConversionConfig {
    project_path: PathBuf,
    plugin_name: String,
    shellcode_size_mb: usize,
    backup_original: bool,
    _force_overwrite: bool,
}

#[derive(Debug)]
struct ShellcodePattern {
    pattern_type: String,
    description: String,
    suggestions: Vec<String>,
}

fn main() -> Result<()> {
    println!("🚀 PumpBin Automatic Converter Tool");
    println!("=====================================");
    println!("This tool will automatically convert your Rust shellcode project to PumpBin compatibility.\n");

    let config = get_user_config()?;
    
    println!("🔍 Analyzing project...");
    let analysis = analyze_project(&config.project_path)?;
    
    println!("📝 Analysis Results:");
    display_analysis(&analysis);
    
    if !confirm_conversion()? {
        println!("❌ Conversion cancelled by user.");
        return Ok(());
    }
    
    println!("🔄 Converting project...");
    convert_project(&config, &analysis)?;
    
    println!("✅ Conversion completed successfully!");
    println!("\n📋 Next Steps:");
    println!("1. Build your project: cargo build --release");
    println!("2. Open PumpBin Maker");
    println!("3. Use these settings:");
    println!("   - Plugin Name: {}", config.plugin_name);
    println!("   - Prefix: $$SHELLCODE$$");
    println!("   - Max Len: {}", 1024 * 1024 * config.shellcode_size_mb + 13);
    println!("   - Type: Local");
    println!("   - Size Holder: $$99999$$");
    println!("4. Select your compiled binary and generate!");
    
    Ok(())
}

fn get_user_config() -> Result<ConversionConfig> {
    println!("📁 Enter the path to your Rust shellcode project:");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let project_path = PathBuf::from(input.trim());
    
    if !project_path.exists() {
        bail!("Project path does not exist: {}", project_path.display());
    }
    
    if !project_path.join("Cargo.toml").exists() {
        bail!("Not a valid Rust project (no Cargo.toml found)");
    }
    
    println!("🏷️  Enter a name for your plugin (default: project folder name):");
    let mut plugin_name = String::new();
    io::stdin().read_line(&mut plugin_name)?;
    let plugin_name = plugin_name.trim();
    let plugin_name = if plugin_name.is_empty() {
        project_path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    } else {
        plugin_name.to_string()
    };
    
    println!("💾 Shellcode buffer size in MB (default: 1):");
    let mut size_input = String::new();
    io::stdin().read_line(&mut size_input)?;
    let shellcode_size_mb = size_input.trim().parse().unwrap_or(1);
    
    println!("🔒 Create backup of original files? (y/n, default: y):");
    let mut backup_input = String::new();
    io::stdin().read_line(&mut backup_input)?;
    let backup_original = !backup_input.trim().eq_ignore_ascii_case("n");
    
    Ok(ConversionConfig {
        project_path,
        plugin_name,
        shellcode_size_mb,
        backup_original,
        _force_overwrite: false,
    })
}

#[derive(Debug)]
struct ProjectAnalysis {
    _has_main_rs: bool,
    has_build_rs: bool,
    main_rs_path: PathBuf,
    shellcode_patterns: Vec<ShellcodePattern>,
    dependencies: Vec<String>,
    target_os: Vec<String>,
}

fn analyze_project(project_path: &Path) -> Result<ProjectAnalysis> {
    let main_rs_candidates = vec![
        project_path.join("src/main.rs"),
        project_path.join("src/lib.rs"),
        project_path.join("main.rs"),
    ];
    
    let main_rs_path = main_rs_candidates.into_iter()
        .find(|p| p.exists())
        .context("Could not find main.rs or lib.rs")?;
    
    let main_content = fs::read_to_string(&main_rs_path)?;
    let cargo_content = fs::read_to_string(project_path.join("Cargo.toml"))?;
    
    let shellcode_patterns = detect_shellcode_patterns(&main_content);
    let dependencies = extract_dependencies(&cargo_content);
    let target_os = detect_target_os(&main_content, &cargo_content);
    
    Ok(ProjectAnalysis {
        _has_main_rs: true,
        has_build_rs: project_path.join("build.rs").exists(),
        main_rs_path,
        shellcode_patterns,
        dependencies,
        target_os,
    })
}

fn detect_shellcode_patterns(content: &str) -> Vec<ShellcodePattern> {
    let mut patterns = Vec::new();
    
    // Network download patterns
    if content.contains("TcpStream") || content.contains("reqwest") || content.contains("ureq") {
        patterns.push(ShellcodePattern {
            pattern_type: "Network Download".to_string(),
            description: "Downloads shellcode from remote server".to_string(),
            suggestions: vec![
                "Consider creating a Remote type plugin".to_string(),
                "Move download logic to WASM plugin".to_string(),
            ],
        });
    }
    
    // File reading patterns
    if content.contains("fs::read") || content.contains("File::open") {
        patterns.push(ShellcodePattern {
            pattern_type: "File Reading".to_string(),
            description: "Reads shellcode from file system".to_string(),
            suggestions: vec![
                "Replace with PumpBin placeholder system".to_string(),
            ],
        });
    }
    
    // Embedded bytes patterns
    if content.contains("include_bytes!") {
        patterns.push(ShellcodePattern {
            pattern_type: "Embedded Bytes".to_string(),
            description: "Uses include_bytes! for shellcode".to_string(),
            suggestions: vec![
                "Already partially compatible - just need to update path".to_string(),
            ],
        });
    }
    
    // Hardcoded arrays
    let array_regex = Regex::new(r"let\s+\w+\s*=\s*\[.*0x[0-9a-fA-F]").unwrap();
    if array_regex.is_match(content) {
        patterns.push(ShellcodePattern {
            pattern_type: "Hardcoded Array".to_string(),
            description: "Uses hardcoded byte arrays for shellcode".to_string(),
            suggestions: vec![
                "Replace with PumpBin placeholder system".to_string(),
            ],
        });
    }
    
    // Memory allocation patterns
    if content.contains("VirtualAlloc") || content.contains("mmap") {
        patterns.push(ShellcodePattern {
            pattern_type: "Memory Allocation".to_string(),
            description: "Allocates memory for shellcode execution".to_string(),
            suggestions: vec![
                "Good - keep this execution logic unchanged".to_string(),
            ],
        });
    }
    
    patterns
}

fn extract_dependencies(cargo_content: &str) -> Vec<String> {
    let dep_regex = Regex::new(r#"^(\w+)\s*="#).unwrap();
    let mut deps = Vec::new();
    
    let mut in_dependencies = false;
    for line in cargo_content.lines() {
        if line.trim() == "[dependencies]" {
            in_dependencies = true;
            continue;
        }
        if line.starts_with('[') && line != "[dependencies]" {
            in_dependencies = false;
        }
        if in_dependencies {
            if let Some(captures) = dep_regex.captures(line) {
                deps.push(captures[1].to_string());
            }
        }
    }
    
    deps
}

fn detect_target_os(main_content: &str, cargo_content: &str) -> Vec<String> {
    let mut targets = Vec::new();
    
    if main_content.contains("windows_sys") || main_content.contains("winapi") || 
       main_content.contains("VirtualAlloc") || cargo_content.contains("windows") {
        targets.push("Windows".to_string());
    }
    
    if main_content.contains("libc") || main_content.contains("mmap") ||
       main_content.contains("#[cfg(target_os = \"linux\")]") {
        targets.push("Linux".to_string());
    }
    
    if main_content.contains("#[cfg(target_os = \"macos\")]") ||
       main_content.contains("darwin") {
        targets.push("macOS".to_string());
    }
    
    if targets.is_empty() {
        targets.push("Unknown/Cross-platform".to_string());
    }
    
    targets
}

fn display_analysis(analysis: &ProjectAnalysis) {
    println!("  📄 Main file: {}", analysis.main_rs_path.display());
    println!("  🔧 Has build.rs: {}", if analysis.has_build_rs { "Yes" } else { "No" });
    println!("  🎯 Target OS: {}", analysis.target_os.join(", "));
    println!("  📦 Dependencies: {}", analysis.dependencies.join(", "));
    println!("  🔍 Detected shellcode patterns:");
    
    for pattern in &analysis.shellcode_patterns {
        println!("    • {} - {}", pattern.pattern_type, pattern.description);
        for suggestion in &pattern.suggestions {
            println!("      → {}", suggestion);
        }
    }
}

fn confirm_conversion() -> Result<bool> {
    println!("\n❓ Proceed with automatic conversion? (y/n):");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

fn convert_project(config: &ConversionConfig, analysis: &ProjectAnalysis) -> Result<()> {
    // Step 1: Backup original files if requested
    if config.backup_original {
        backup_files(config, analysis)?;
    }
    
    // Step 2: Create or update build.rs
    create_build_rs(config)?;
    
    // Step 3: Update main.rs
    update_main_rs(config, analysis)?;
    
    // Step 4: Update Cargo.toml if needed
    update_cargo_toml(config)?;
    
    Ok(())
}

fn backup_files(config: &ConversionConfig, analysis: &ProjectAnalysis) -> Result<()> {
    let backup_dir = config.project_path.join("pumpbin_backup");
    fs::create_dir_all(&backup_dir)?;
    
    // Backup main.rs
    if let Some(file_name) = analysis.main_rs_path.file_name() {
        fs::copy(&analysis.main_rs_path, backup_dir.join(file_name))?;
    }
    
    // Backup build.rs if exists
    let build_rs = config.project_path.join("build.rs");
    if build_rs.exists() {
        fs::copy(&build_rs, backup_dir.join("build.rs"))?;
    }
    
    // Backup Cargo.toml
    fs::copy(
        config.project_path.join("Cargo.toml"), 
        backup_dir.join("Cargo.toml")
    )?;
    
    println!("  💾 Backed up original files to: {}", backup_dir.display());
    Ok(())
}

fn create_build_rs(config: &ConversionConfig) -> Result<()> {
    let build_rs_path = config.project_path.join("build.rs");
    let shellcode_size = 1024 * 1024 * config.shellcode_size_mb;
    
    let content = format!(r#"use std::{{fs, iter}};

fn main() {{
    let mut shellcode = "$$SHELLCODE$$".as_bytes().to_vec();
    shellcode.extend(iter::repeat(b'0').take({}));
    fs::write("shellcode", shellcode.as_slice()).unwrap();
}}
"#, shellcode_size);
    
    fs::write(&build_rs_path, content)?;
    println!("  ✅ Created build.rs");
    Ok(())
}

fn update_main_rs(_config: &ConversionConfig, analysis: &ProjectAnalysis) -> Result<()> {
    let mut content = fs::read_to_string(&analysis.main_rs_path)?;
    
    // Add required imports at the top
    if !content.contains("use std::hint::black_box;") {
        let use_regex = Regex::new(r"(use\s+[^;]+;)\s*\n").unwrap();
        if let Some(last_use) = use_regex.find_iter(&content).last() {
            let insert_pos = last_use.end();
            content.insert_str(insert_pos, "use std::hint::black_box;\n");
        } else {
            content = format!("use std::hint::black_box;\n\n{}", content);
        }
    }
    
    // Add PumpBin helper functions
    let helper_functions = r#"
// Force the size holder to be embedded in the binary by preventing optimization
#[inline(never)]
fn get_size_holder() -> &'static str {
    // Use a valid numeric string that can be parsed
    black_box("$$99999$$")
}

// Force the shellcode data to be preserved
#[inline(never)]
fn get_shellcode() -> &'static [u8] {
    black_box(include_bytes!("../shellcode"))
}

"#;
    
    if !content.contains("fn get_size_holder()") {
        // Find a good place to insert the functions (after imports, before main)
        if let Some(main_pos) = content.find("fn main()") {
            content.insert_str(main_pos, helper_functions);
        } else {
            content.push_str(helper_functions);
        }
    }
    
    // Try to automatically replace common shellcode loading patterns
    content = replace_shellcode_patterns(content);
    
    fs::write(&analysis.main_rs_path, content)?;
    println!("  ✅ Updated main.rs with PumpBin compatibility");
    
    // Provide manual instructions for complex cases
    println!("  ⚠️  MANUAL STEP REQUIRED:");
    println!("     Replace your shellcode source in main() with:");
    println!("     ```");
    println!("     let shellcode = get_shellcode();");
    println!("     let size_holder_str = get_size_holder();");
    println!("     let shellcode_len = usize::from_str_radix(size_holder_str, 10).unwrap();");
    println!("     let shellcode = &shellcode[0..shellcode_len];");
    println!("     ```");
    
    Ok(())
}

fn replace_shellcode_patterns(mut content: String) -> String {
    // Replace common patterns
    
    // Pattern 1: include_bytes! with different paths
    let include_bytes_regex = Regex::new(r#"include_bytes!\("([^"]+)"\)"#).unwrap();
    content = include_bytes_regex.replace_all(&content, r#"include_bytes!("../shellcode")"#).to_string();
    
    // Pattern 2: Simple file reading
    let file_read_regex = Regex::new(r"fs::read\([^)]+\)").unwrap();
    if file_read_regex.is_match(&content) {
        // Add a comment suggesting replacement
        content = file_read_regex.replace_all(&content, 
            "/* TODO: Replace with PumpBin shellcode loading */\n    get_shellcode().to_vec()").to_string();
    }
    
    content
}

fn update_cargo_toml(config: &ConversionConfig) -> Result<()> {
    let cargo_path = config.project_path.join("Cargo.toml");
    let mut content = fs::read_to_string(&cargo_path)?;
    
    // Ensure we have a build script entry
    if !content.contains("build =") {
        if let Some(package_end) = content.find("\n[dependencies]") {
            content.insert_str(package_end, "\nbuild = \"build.rs\"\n");
        } else if let Some(package_start) = content.find("[package]") {
            if let Some(package_end) = content[package_start..].find("\n\n") {
                let insert_pos = package_start + package_end;
                content.insert_str(insert_pos, "\nbuild = \"build.rs\"\n");
            }
        }
    }
    
    fs::write(&cargo_path, content)?;
    println!("  ✅ Updated Cargo.toml");
    Ok(())
}
