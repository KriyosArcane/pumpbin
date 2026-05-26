//! v1.3.1 `pumpbin::inspect` end-to-end.
//!
//! Builds a fixture plugin pack, inspects it, asserts every reported
//! field matches what was put in. Verifies the diff path too.

use pumpbin::inspect::{inspect, render_diff, render_text};
use pumpbin::plugin::{Plugin, PluginBins, PluginInfo, PluginPlugins, PluginReplace};

fn fixture_plugin(name: &str) -> Plugin {
    let mut bins = PluginBins::default();
    let mut template = vec![0xAAu8; 64];
    template.extend_from_slice(b"$$SHELLCODE$$");
    template.extend(std::iter::repeat_n(b'0', 4096 - b"$$SHELLCODE$$".len()));
    template.extend_from_slice(b"$$99999$$");
    *bins.windows.executable_mut() = Some(template);

    Plugin {
        version: "1.0.0".into(),
        info: PluginInfo {
            plugin_name: name.into(),
            author: "tests".into(),
            version: "0.2.0".into(),
            desc: "fixture for inspect tests".into(),
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

fn write_plugin(name: &str, dir: &tempfile::TempDir) -> std::path::PathBuf {
    let plugin = fixture_plugin(name);
    let bytes = plugin.encode_to_vec().unwrap();
    let path = dir.path().join(format!("{name}.b1n"));
    std::fs::write(&path, &bytes).unwrap();
    path
}

#[test]
fn inspect_reports_plugin_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_plugin("inspect-fixture", &dir);

    let report = inspect(&path).expect("inspect must succeed");

    assert_eq!(report.plugin_name, "inspect-fixture");
    assert_eq!(report.author, "tests");
    assert_eq!(report.plugin_version, "0.2.0");
    assert_eq!(report.description, "fixture for inspect tests");
    assert_eq!(report.src_prefix, b"$$SHELLCODE$$".to_vec());
    assert_eq!(report.size_holder, Some(b"$$99999$$".to_vec()));
    assert_eq!(report.max_len, 4096);
    assert_eq!(report.save_type, "Local");
    assert_eq!(report.platforms.len(), 1);
    assert_eq!(report.platforms[0].name, "Windows");
    assert_eq!(report.platforms[0].binary_types, vec!["exe"]);
    assert_eq!(report.modules.len(), 0); // fixture has no WASM modules
    assert_eq!(report.legacy_module_count, 0);
}

#[test]
fn render_text_contains_key_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_plugin("render-fixture", &dir);
    let report = inspect(&path).unwrap();
    let text = render_text(&report);

    for needle in [
        "render-fixture",
        "tests",
        "0.2.0",
        "$$SHELLCODE$$",
        "$$99999$$",
        "Windows",
        "exe",
    ] {
        assert!(
            text.contains(needle),
            "render_text output must contain {needle:?}; got:\n{text}"
        );
    }
}

#[test]
fn render_diff_shows_name_change_only() {
    let dir = tempfile::tempdir().unwrap();
    let path_a = write_plugin("variant-a", &dir);
    let path_b = write_plugin("variant-b", &dir);

    let report_a = inspect(&path_a).unwrap();
    let report_b = inspect(&path_b).unwrap();
    let diff = render_diff(&report_a, &report_b);

    assert!(diff.contains("--- "));
    assert!(diff.contains("+++ "));
    assert!(diff.contains("variant-a"));
    assert!(diff.contains("variant-b"));
    assert!(diff.contains("name:"));
    // Same template content → no module diff lines.
    assert!(!diff.contains("modules:"));
}

#[test]
fn render_diff_on_identical_b1n_reports_no_differences() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_plugin("same", &dir);
    let report = inspect(&path).unwrap();
    let diff = render_diff(&report, &report);
    assert!(
        diff.contains("no differences"),
        "diff of identical reports must say 'no differences', got:\n{diff}"
    );
}
