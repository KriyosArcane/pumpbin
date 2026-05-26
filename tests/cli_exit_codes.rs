//! End-to-end CLI exit-code tests.
//!
//! Runs the built `pumpbin-cli` binary against scratch fixtures and asserts
//! the documented exit-code policy (see CHANGELOG v1.1.3 + v1.1.4):
//!
//! - generate / create-b1n / verify: 0 on success, 1 on any failure.
//! - batch:
//!   - `success > 0 && failed == 0`  -> 0
//!   - `success == 0`                -> 1 (would-be silent no-op pre-1.1.4)
//!   - `success > 0 && failed > 0`   -> non-zero (partial)
//!
//! These tests require the release or debug binary to be built. They are
//! skipped cleanly (early-return with eprintln!) if the binary is missing
//! rather than failing, so `cargo test` in a fresh checkout doesn't break.

use std::path::PathBuf;
use std::process::Command;

fn cli_path() -> Option<PathBuf> {
    let candidates = [
        "target/release/pumpbin-cli",
        "target/debug/pumpbin-cli",
        "../target/release/pumpbin-cli",
        "../target/debug/pumpbin-cli",
    ];
    for c in &candidates {
        let p = PathBuf::from(c);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn skip_if_no_binary() -> Option<PathBuf> {
    match cli_path() {
        Some(p) => Some(p),
        None => {
            eprintln!(
                "[cli_exit_codes] skipping: pumpbin-cli binary not built. \
                 Run `cargo build --release --bin pumpbin-cli` first."
            );
            None
        }
    }
}

fn build_local_b1n(cli: &PathBuf, tmp: &tempfile::TempDir) -> PathBuf {
    let template = tmp.path().join("template.exe");
    let placeholder = b"$$SHELLCODE$$";
    let size_holder = b"$$99999$$";
    let mut data = vec![0xAAu8; 64];
    data.extend_from_slice(placeholder);
    data.extend(std::iter::repeat_n(b'0', 4096 - placeholder.len()));
    data.extend_from_slice(&[0xCCu8; 32]);
    data.extend_from_slice(size_holder);
    data.extend_from_slice(&[0xDDu8; 32]);
    std::fs::write(&template, &data).unwrap();

    let b1n = tmp.path().join("test.b1n");
    let status = Command::new(cli)
        .args(["create-b1n", "--output"])
        .arg(&b1n)
        .args(["--name", "test", "--template"])
        .arg(&template)
        .args(["--platform", "windows", "--type", "exe"])
        .status()
        .unwrap();
    assert!(status.success(), "create-b1n failed: {:?}", status);
    b1n
}

#[test]
fn batch_empty_dir_exits_nonzero() {
    let Some(cli) = skip_if_no_binary() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let b1n = build_local_b1n(&cli, &tmp);
    let empty_dir = tmp.path().join("empty");
    std::fs::create_dir(&empty_dir).unwrap();
    let out_dir = tmp.path().join("out");
    std::fs::create_dir(&out_dir).unwrap();

    let status = Command::new(&cli)
        .args(["batch", "--plugin"])
        .arg(&b1n)
        .args(["--directory"])
        .arg(&empty_dir)
        .args(["--platform", "windows", "--type", "exe", "--output-dir"])
        .arg(&out_dir)
        .status()
        .unwrap();

    assert!(
        !status.success(),
        "batch on empty dir must exit non-zero (pre-1.1.4 returned 0); got {:?}",
        status
    );
}

#[test]
fn batch_dir_of_non_bin_files_exits_nonzero() {
    let Some(cli) = skip_if_no_binary() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let b1n = build_local_b1n(&cli, &tmp);
    let sc_dir = tmp.path().join("scs");
    std::fs::create_dir(&sc_dir).unwrap();
    std::fs::write(sc_dir.join("notes.txt"), b"not a shellcode").unwrap();
    std::fs::write(sc_dir.join("readme.md"), b"# nope").unwrap();
    let out_dir = tmp.path().join("out");
    std::fs::create_dir(&out_dir).unwrap();

    let status = Command::new(&cli)
        .args(["batch", "--plugin"])
        .arg(&b1n)
        .args(["--directory"])
        .arg(&sc_dir)
        .args(["--platform", "windows", "--type", "exe", "--output-dir"])
        .arg(&out_dir)
        .status()
        .unwrap();

    assert!(
        !status.success(),
        "batch on dir of non-.bin files must exit non-zero; got {:?}",
        status
    );
}

#[test]
fn batch_with_valid_shellcode_succeeds() {
    let Some(cli) = skip_if_no_binary() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let b1n = build_local_b1n(&cli, &tmp);
    let sc_dir = tmp.path().join("scs");
    std::fs::create_dir(&sc_dir).unwrap();
    std::fs::write(sc_dir.join("sc1.bin"), vec![0x90u8; 64]).unwrap();
    let out_dir = tmp.path().join("out");
    std::fs::create_dir(&out_dir).unwrap();

    let status = Command::new(&cli)
        .args(["batch", "--plugin"])
        .arg(&b1n)
        .args(["--directory"])
        .arg(&sc_dir)
        .args(["--platform", "windows", "--type", "exe", "--output-dir"])
        .arg(&out_dir)
        .status()
        .unwrap();

    assert!(
        status.success(),
        "batch with valid input must exit 0; got {:?}",
        status
    );
}

#[test]
fn verify_on_non_pe_exits_nonzero() {
    let Some(cli) = skip_if_no_binary() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let f = tmp.path().join("not-a-pe.bin");
    std::fs::write(&f, b"this is not a PE binary").unwrap();

    let status = Command::new(&cli)
        .args(["verify", "--binary"])
        .arg(&f)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1), "verify on non-PE must exit 1");
}

#[test]
fn create_b1n_with_bad_template_exits_nonzero() {
    let Some(cli) = skip_if_no_binary() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let bad_template = tmp.path().join("bad.exe");
    std::fs::write(&bad_template, b"no placeholders here").unwrap();
    let out_b1n = tmp.path().join("bad.b1n");

    let status = Command::new(&cli)
        .args(["create-b1n", "--output"])
        .arg(&out_b1n)
        .args(["--name", "bad", "--template"])
        .arg(&bad_template)
        .args(["--platform", "windows", "--type", "exe"])
        .status()
        .unwrap();

    assert!(
        !status.success(),
        "create-b1n with template missing src_prefix must exit non-zero"
    );
    assert!(
        !out_b1n.exists(),
        "no .b1n should be written on preflight failure"
    );
}
