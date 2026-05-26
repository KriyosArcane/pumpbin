//! v1.1.12 dispatcher semantics for `RuntimeConfig::on_error`.
//!
//! Pre-v1.1.12 the `OnError::Skip` variant existed on the enum but the
//! `EventManager::fire_post_binary` dispatcher always treated a module
//! error as fatal. v1.1.12 wires `Skip` through: a failing module whose
//! schema declares `on_error = Skip` logs a `warn!` and the chain
//! continues with the unmodified binary.
//!
//! The dispatcher is a pure function over `&[Vec<u8>]` + serialized
//! inputs, but exercising it end-to-end requires real WASM modules.
//! These tests use the existing `aes_gcm_encrypt.wasm` example (which
//! does NOT export `post_binary` and therefore returns `Ok(None)` from
//! `run_module`) to verify the no-op-skip path, plus an empty-modules
//! and missing-binary test to lock the contract.

use pumpbin::plugin_system::EventManager;

const TEST_BINARY: &[u8] = b"this is just bytes for the post_binary chain to pass through";

#[test]
fn empty_modules_returns_input_unchanged() {
    let modules: Vec<Vec<u8>> = Vec::new();
    let out = EventManager::fire_post_binary(&modules, TEST_BINARY.to_vec(), None)
        .expect("empty chain must succeed");
    assert_eq!(out, TEST_BINARY);
}

#[test]
fn module_without_post_binary_export_is_skipped_silently() {
    // The bundled aes-gcm-encrypt wasm exports encrypt_shellcode but
    // not post_binary. The dispatcher must treat that as "module had
    // nothing to do for this hook" and proceed with the input
    // unchanged — the behavior pre- AND post-v1.1.12.
    let wasm_path = "plugin-examples/target/wasm32-wasip1/release/aes_gcm_encrypt.wasm";
    let Ok(wasm) = std::fs::read(wasm_path) else {
        eprintln!(
            "[on_error_skip] skipping: {wasm_path} not built. \
             Run `cargo build --release --target wasm32-wasip1 -p aes-gcm-encrypt` first."
        );
        return;
    };
    let modules = vec![wasm];
    let out = EventManager::fire_post_binary(&modules, TEST_BINARY.to_vec(), None)
        .expect("post_binary chain on a module that doesn't export post_binary must succeed");
    assert_eq!(out, TEST_BINARY);
}

#[test]
fn invalid_wasm_with_default_policy_returns_err() {
    // A garbage WASM module under the default OnError::Abort policy
    // must surface the underlying error. v1.1.12 changed the chain
    // logic to *match* on the error; this test guards against the
    // refactor accidentally swallowing errors when on_error=Abort.
    let modules = vec![b"not wasm bytes".to_vec()];
    let result = EventManager::fire_post_binary(&modules, TEST_BINARY.to_vec(), None);
    assert!(
        result.is_err(),
        "invalid WASM under default (Abort) policy must error, got: {result:?}"
    );
}
