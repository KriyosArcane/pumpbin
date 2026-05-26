//! Execution-QA harness: stamp a real loader with a sentinel
//! shellcode, run the artifact (Linux locally / Windows via ssh), and
//! prove the shellcode actually executed by checking for the sentinel
//! file `PB-QA-OK` on disk.
//!
//! Both tests are `#[ignore]` so `cargo test` stays fast and offline.
//! Run explicitly with:
//!
//!     cargo test --test qa_execute -- --ignored
//!     cargo test --test qa_execute -- --ignored linux
//!     cargo test --test qa_execute -- --ignored windows
//!
//! The Windows test additionally requires:
//!   - A `pumpbin-w10` host alias in ~/.ssh/config (or
//!     `PUMPBIN_QA_SSH_HOST=...`) reachable with key auth.
//!   - The win10 VM accessible at that host.
//!
//! It skips (not fails) if ssh isn't reachable.

use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_harness(extra_args: &[&str]) -> std::process::Output {
    let script = repo_root().join("scripts/qa-execute.sh");
    assert!(
        script.exists(),
        "missing harness script at {}",
        script.display()
    );
    Command::new("bash")
        .arg(&script)
        .args(extra_args)
        .output()
        .expect("failed to spawn qa-execute.sh")
}

#[test]
#[ignore = "execute-QA: runs a real implant; opt in with --ignored"]
fn linux_implant_writes_sentinel() {
    let out = run_harness(&["--linux-only"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "qa-execute.sh failed:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        stdout.contains("linux:   pass"),
        "expected Linux pass in summary, got:\n{stdout}"
    );
}

#[test]
#[ignore = "execute-QA: runs a real implant on the win10 VM via ssh; opt in with --ignored"]
fn windows_implant_writes_sentinel() {
    // Skip-don't-fail when ssh isn't wired up — this lets the test
    // run on dev machines without a VM, while still being mandatory
    // for the pre-tag hook (which runs without --windows-only-skip).
    let host = std::env::var("PUMPBIN_QA_SSH_HOST").unwrap_or_else(|_| "pumpbin-w10".to_string());
    let probe = Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            &host,
            r"C:\Windows\System32\cmd.exe",
            "/c",
            "echo PING",
        ])
        .output();
    let reachable = matches!(probe, Ok(p) if p.status.success());
    if !reachable {
        eprintln!("ssh {host} not reachable; skipping windows execute-QA");
        return;
    }

    let out = run_harness(&["--windows-only"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "qa-execute.sh failed:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        stdout.contains("windows: pass"),
        "expected Windows pass in summary, got:\n{stdout}"
    );
}
