//! Regression guard: shellcode bytes must NEVER appear in tracing log
//! output.
//!
//! Every `#[tracing::instrument(...)]` annotation on a function that
//! touches shellcode, Pass material, or runtime config must explicitly
//! `skip()` those arguments. Without skip, the default formatter prints
//! `Debug` of the value into the log layer, which means a Vec<u8> of
//! shellcode bytes ends up serialized into the JSON log file. That's a
//! secret-leak waiting to happen.
//!
//! This test drives the same code path as a real generate (via the parity
//! harness pattern) with a fixed, distinctive shellcode marker. It then
//! reads back every byte tracing wrote to its sink and asserts the marker
//! does NOT appear anywhere — neither verbatim nor as the comma-joined
//! Debug Vec form `[222, 173, 190, 239]`.
//!
//! If this test fails, an `#[instrument]` annotation somewhere is missing
//! a `skip(...)` for a shellcode/Pass/key argument. Fix that annotation
//! before merging.

use pumpbin::plugin::{Plugin, PluginBins, PluginInfo, PluginPlugins, PluginReplace};
use pumpbin::{BinaryType, Platform};
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// A distinctive 32-byte marker. The 4-byte word `0xDEADBEEF` is repeated
/// so that whether tracing emits `[222, 173, 190, 239, …]` (Debug Vec<u8>)
/// or the raw bytes via JSON-string encoding, we can detect the leak.
const MARKER: &[u8] = &[
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
];

/// Shared `Vec<u8>` writer used as the tracing sink. Lets us read back
/// every byte the subscriber emitted after the test completes.
#[derive(Clone)]
struct CapturedWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl Write for CapturedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedWriter {
    type Writer = CapturedWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn build_fixture_plugin() -> Plugin {
    let mut bins = PluginBins::default();
    let mut template = vec![0xAAu8; 64];
    template.extend_from_slice(b"$$SHELLCODE$$");
    template.extend(std::iter::repeat_n(b'0', 4096 - b"$$SHELLCODE$$".len()));
    template.extend_from_slice(&[0xCCu8; 32]);
    template.extend_from_slice(b"$$99999$$");
    template.extend_from_slice(&[0xDDu8; 32]);
    *bins.windows.executable_mut() = Some(template);

    Plugin {
        version: "1.0.0".into(),
        info: PluginInfo {
            plugin_name: "log-redaction-fixture".into(),
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
fn shellcode_bytes_never_appear_in_tracing_output() {
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let writer = CapturedWriter { buf: buf.clone() };

    // Install a capturing subscriber at TRACE level so we get the maximum
    // amount of tracing output. If any #[instrument] annotation forgets
    // to skip shellcode/pass/key, the marker bytes will show up here.
    //
    // We use `try_init` and ignore the result so this test stays robust if
    // another test in the suite already installed a global subscriber —
    // in that case this test is effectively a no-op (the captured buffer
    // stays empty), which is documented behavior, not a false pass: each
    // tracing subscriber is process-global, and `cargo test` runs tests
    // concurrently in one process. Run with --test-threads=1 if you want
    // strict capture isolation.
    let _guard = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("trace"))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_target(true),
        )
        .set_default();

    // Drive a full generate against the fixture using MARKER as the shellcode.
    let plugin = build_fixture_plugin();
    let bin = plugin
        .bins()
        .get_that_binary(Platform::Windows, BinaryType::Executable)
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let shellcode_path = dir.path().join("marker-shellcode.bin");
    std::fs::write(&shellcode_path, MARKER).unwrap();

    plugin
        .validate_for_generation(Platform::Windows, BinaryType::Executable)
        .unwrap();
    plugin
        .validate_shellcode_source(shellcode_path.to_str().unwrap())
        .unwrap();
    let _generated = plugin
        .replace_binary(
            bin,
            shellcode_path.to_string_lossy().into_owned(),
            vec![],
            None,
        )
        .expect("replace_binary failed");

    let captured = buf.lock().unwrap().clone();

    // Form 1: raw marker bytes (would happen if the JSON layer wrote them
    // as a binary blob — shouldn't happen with fmt::layer, but cheap check).
    let raw_leak = captured.windows(MARKER.len()).any(|w| w == MARKER);

    // Form 2: Debug formatting of Vec<u8> emits "[222, 173, 190, 239, ...]".
    // Check for the 4-byte signature in that representation.
    let debug_marker = b"222, 173, 190, 239";
    let debug_leak = captured
        .windows(debug_marker.len())
        .any(|w| w == debug_marker);

    // Form 3: hex representation "deadbeef" lower-case.
    let hex_leak_lower = captured.windows(8).any(|w| w == b"deadbeef");
    // Form 4: hex representation "DEADBEEF" upper-case.
    let hex_leak_upper = captured.windows(8).any(|w| w == b"DEADBEEF");

    let log_preview = String::from_utf8_lossy(&captured[..captured.len().min(2048)]);

    assert!(
        !raw_leak,
        "shellcode marker bytes leaked into log output (raw form).\n\
         Log preview (first 2KB):\n{log_preview}"
    );
    assert!(
        !debug_leak,
        "shellcode marker bytes leaked into log output (Debug Vec<u8> form). \
         A #[tracing::instrument] annotation is missing a skip() for a \
         shellcode/Pass argument.\n\
         Log preview (first 2KB):\n{log_preview}"
    );
    assert!(
        !hex_leak_lower && !hex_leak_upper,
        "shellcode marker bytes leaked into log output (hex form).\n\
         Log preview (first 2KB):\n{log_preview}"
    );
}
