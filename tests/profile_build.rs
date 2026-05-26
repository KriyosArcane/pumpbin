//! v1.3.0 `pumpbin.toml` profile parse + execute end-to-end.
//!
//! Builds a fixture plugin in-memory, writes it as a `.b1n`, writes a
//! profile pointing at it, calls `Profile::from_toml` + `Profile::execute`,
//! asserts the output file exists with the expected byte count.

use pumpbin::plugin::{Plugin, PluginBins, PluginInfo, PluginPlugins, PluginReplace};
use pumpbin::Profile;

fn make_fixture_plugin() -> Plugin {
    let mut bins = PluginBins::default();
    let mut template = vec![0xAAu8; 64];
    template.extend_from_slice(b"$$SHELLCODE$$");
    template.extend(std::iter::repeat_n(b'0', 4096 - b"$$SHELLCODE$$".len()));
    template.extend_from_slice(&[0xCCu8; 32]);
    template.extend_from_slice(b"$$99999$$");
    *bins.windows.executable_mut() = Some(template);

    Plugin {
        version: "1.0.0".into(),
        info: PluginInfo {
            plugin_name: "profile-fixture".into(),
            author: "tests".into(),
            version: "1.0.0".into(),
            desc: String::new(),
        },
        replace: PluginReplace {
            src_prefix: b"$$SHELLCODE$$".to_vec(),
            size_holder: Some(b"$$99999$$".to_vec()),
            max_len: 4096,
        },
        bins,
        plugins: PluginPlugins::default(),
    }
}

#[test]
fn profile_from_toml_round_trips_schema() {
    let dir = tempfile::tempdir().unwrap();
    let profile_path = dir.path().join("p.toml");
    std::fs::write(
        &profile_path,
        r#"
schema = "pumpbin.profile/v1"

[plugin]
source = "/no/such/path.b1n"

[target]
platform = "windows"
binary_type = "exe"

[shellcode]
source = "file"
path = "/no/such/sc.bin"

[output]
path = "/tmp/out.exe"
"#,
    )
    .unwrap();

    let p = Profile::from_toml(&profile_path).expect("valid profile parses");
    assert_eq!(p.schema, pumpbin::PROFILE_SCHEMA);
    assert_eq!(p.target.platform, "windows");
}

#[test]
fn profile_rejects_wrong_schema() {
    let dir = tempfile::tempdir().unwrap();
    let profile_path = dir.path().join("p.toml");
    std::fs::write(
        &profile_path,
        r#"
schema = "pumpbin.profile/v999"

[plugin]
source = "x"
[target]
platform = "windows"
binary_type = "exe"
[shellcode]
source = "file"
path = "x"
[output]
path = "x"
"#,
    )
    .unwrap();

    let err = Profile::from_toml(&profile_path).unwrap_err();
    assert!(
        err.to_string().contains("schema"),
        "expected schema mismatch error, got: {err}"
    );
}

#[test]
fn profile_execute_end_to_end() {
    let dir = tempfile::tempdir().unwrap();

    // 1. Encode the fixture plugin as a .b1n.
    let plugin = make_fixture_plugin();
    let plugin_bytes = plugin.encode_to_vec().unwrap();
    let plugin_path = dir.path().join("fixture.b1n");
    std::fs::write(&plugin_path, &plugin_bytes).unwrap();

    // 2. Write a shellcode file.
    let shellcode_path = dir.path().join("sc.bin");
    std::fs::write(&shellcode_path, vec![0x90u8; 128]).unwrap();

    // 3. Write a profile pointing at both.
    let output_path = dir.path().join("implant.exe");
    let profile_path = dir.path().join("pumpbin.toml");
    let profile_toml = format!(
        r#"
schema = "pumpbin.profile/v1"

[plugin]
source = {plugin:?}

[target]
platform = "windows"
binary_type = "exe"

[shellcode]
source = "file"
path = {shellcode:?}

[output]
path = {output:?}
"#,
        plugin = plugin_path,
        shellcode = shellcode_path,
        output = output_path
    );
    std::fs::write(&profile_path, profile_toml).unwrap();

    // 4. Execute.
    let p = Profile::from_toml(&profile_path).unwrap();
    let artifact = p.execute().expect("Profile::execute must succeed");

    // 5. Assertions.
    assert_eq!(artifact.output_path, output_path);
    assert!(output_path.exists(), "output file must exist");
    let written = std::fs::read(&output_path).unwrap();
    assert_eq!(written.len(), artifact.bytes_written);
    // Output length equals template length (4201 bytes: 64 prefix + 4096
    // placeholder slot + 32 mid-padding + 9 size_holder = 4201).
    assert_eq!(written.len(), 4201);
    // Shellcode bytes are present in the output.
    let needle = vec![0x90u8; 128];
    assert!(
        written.windows(128).any(|w| w == needle.as_slice()),
        "shellcode bytes must be present in output"
    );
}

#[test]
fn profile_execute_with_hex_shellcode() {
    let dir = tempfile::tempdir().unwrap();
    let plugin = make_fixture_plugin();
    let plugin_bytes = plugin.encode_to_vec().unwrap();
    let plugin_path = dir.path().join("fixture.b1n");
    std::fs::write(&plugin_path, &plugin_bytes).unwrap();

    let output_path = dir.path().join("hex-implant.exe");
    let profile_path = dir.path().join("hex.toml");
    // 8 NOP bytes as hex with separators
    let profile_toml = format!(
        r#"
schema = "pumpbin.profile/v1"

[plugin]
source = {plugin:?}

[target]
platform = "windows"
binary_type = "exe"

[shellcode]
source = "hex"
data = "90:90:90:90 90 90,90,90"

[output]
path = {output:?}
"#,
        plugin = plugin_path,
        output = output_path
    );
    std::fs::write(&profile_path, profile_toml).unwrap();

    let p = Profile::from_toml(&profile_path).unwrap();
    let artifact = p.execute().expect("hex shellcode execute must succeed");
    let written = std::fs::read(&artifact.output_path).unwrap();
    assert!(written.windows(8).any(|w| w == [0x90u8; 8]));
}
