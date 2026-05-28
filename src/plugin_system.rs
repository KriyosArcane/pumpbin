use anyhow::Context;
use std::{collections::BTreeMap, time::Duration};

use extism::{Manifest, PluginBuilder, Wasm};
use serde::{Deserialize, Serialize};

use crate::error::PumpBinError;
use crate::host_helpers;

/// Bounds on the per-module timeout declared in `RuntimeConfig::timeout_ms`.
/// A 10-minute upper bound is enough for any realistic signing or
/// obfuscation pass; a 1ms lower bound rejects obviously-wrong values
/// without making local debug-tracing impossible.
const TIMEOUT_MS_MIN: u64 = 1;
const TIMEOUT_MS_MAX: u64 = 600_000;

/// Module-load policy resolved from the WASM's `plugin_schema()` export
/// (or built explicitly by the caller for compatibility paths). Carries
/// only what the host actually applies to the Extism `Manifest` — the
/// `on_error` and `sdk_version` checks happen elsewhere in the dispatch
/// pipeline.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    /// Used for log spans and error variants; doesn't change behavior.
    pub module_name: String,
    pub timeout: Duration,
    pub allowed_hosts: Vec<String>,
}

impl ResolvedPolicy {
    /// Build a policy from a deserialized [`RuntimeConfig`]. Validates the
    /// timeout bounds and returns [`PumpBinError::WasmTimeoutInvalid`] for
    /// out-of-range values.
    pub fn from_runtime(
        module_name: impl Into<String>,
        runtime: &RuntimeConfig,
    ) -> Result<Self, PumpBinError> {
        let module_name = module_name.into();
        if !(TIMEOUT_MS_MIN..=TIMEOUT_MS_MAX).contains(&runtime.timeout_ms) {
            return Err(PumpBinError::WasmTimeoutInvalid {
                module: module_name,
                timeout_ms: runtime.timeout_ms,
            });
        }
        Ok(Self {
            module_name,
            timeout: Duration::from_millis(runtime.timeout_ms),
            allowed_hosts: runtime.allowed_hosts.clone(),
        })
    }

    /// Default policy applied to schema-less WASM modules (every module
    /// shipped before v1.1.7). Safe defaults: 3-second timeout, no network.
    pub fn defaults(module_name: impl Into<String>) -> Self {
        Self {
            module_name: module_name.into(),
            timeout: Duration::from_millis(default_timeout_ms()),
            allowed_hosts: Vec::new(),
        }
    }
}

/// Build an Extism `Manifest` for a WASM module under the given policy.
/// Pre-v1.1.7 this function unconditionally set `with_allowed_host("*")`
/// and a fixed 5-second timeout. v1.1.7 enforces policy: the timeout
/// comes from `policy.timeout`, and only hosts explicitly listed in
/// `policy.allowed_hosts` get an allowlist entry. A module that calls
/// `extism_pdk::http::request` to a non-allowlisted host gets a runtime
/// error from Extism, which the dispatcher will surface as
/// [`PumpBinError::WasmHostDenied`].
pub fn manifest_from_wasm_with_policy(
    wasm: &[u8],
    policy: &ResolvedPolicy,
) -> anyhow::Result<Manifest> {
    let manifest = if wasm.starts_with(b"\0asm") {
        Manifest::new([Wasm::data(wasm.to_vec())])
    } else {
        serde_json::from_slice::<Manifest>(wasm).with_context(|| {
            "module bytes are neither raw wasm (\\0asm) nor valid Extism Manifest JSON"
        })?
    };

    let mut manifest = manifest.with_timeout(policy.timeout);
    for host in &policy.allowed_hosts {
        manifest = manifest.with_allowed_host(host);
    }
    Ok(manifest)
}

/// Build an `extism::Plugin` from a `Manifest`, attaching the v1.5.0
/// host-helper ABI (`host_helpers::host_functions()`) so plugins can
/// call the `pumpbin:host/v1` extern imports declared by SDK v2.
///
/// Pre-v1.5.0 this was a bare `extism::Plugin::new(manifest, [], true)`;
/// host helpers required switching to `PluginBuilder` to pass the
/// function table.
fn build_plugin(manifest: Manifest) -> Result<extism::Plugin, extism::Error> {
    PluginBuilder::new(manifest)
        .with_wasi(true)
        .with_functions(host_helpers::host_functions())
        .build()
}

/// Read the `plugin_schema` export from `wasm`, validate the embedded
/// `RuntimeConfig`, and return a [`ResolvedPolicy`] ready to feed
/// [`manifest_from_wasm_with_policy`].
///
/// - Modules without a `plugin_schema` export get
///   [`ResolvedPolicy::defaults`] (3-second timeout, no network).
/// - Modules with `runtime: None` in their schema also get defaults.
/// - Modules with an explicit `runtime` block get those values, after
///   SDK-version and timeout-bound checks.
pub fn resolve_policy(
    wasm: &[u8],
    module_name: impl Into<String>,
) -> Result<ResolvedPolicy, PumpBinError> {
    let module_name = module_name.into();

    // Read schema via a bootstrap Extism instance with defaults. We're
    // about to read the schema, so we have to load the module under
    // *some* policy — use defaults, then enforce the real policy when
    // the caller actually invokes hooks.
    let bootstrap = ResolvedPolicy::defaults(&module_name);
    let manifest = match manifest_from_wasm_with_policy(wasm, &bootstrap) {
        Ok(m) => m,
        Err(_) => return Ok(bootstrap), // module won't load anyway; defaults are fine
    };
    let mut plugin = match build_plugin(manifest) {
        Ok(p) => p,
        Err(_) => return Ok(bootstrap),
    };

    let raw = match plugin.call::<Vec<u8>, Vec<u8>>("plugin_schema", Vec::new()) {
        Ok(out) => out,
        Err(_) => return Ok(bootstrap), // no schema exported → defaults
    };

    let schema: PluginConfigSchema = match serde_json::from_slice(&raw) {
        Ok(s) => s,
        Err(_) => return Ok(bootstrap),
    };

    let Some(runtime) = schema.runtime else {
        return Ok(bootstrap);
    };

    // SDK version check. None = "any" for backward compat with pre-1.1.7
    // plugins that ship no runtime block. Pre-v1.5.0 policy was strict
    // equality; v1.5.0 relaxed it to "declared <= host" so the additive
    // v1→v2 host-helper ABI didn't strand every shipped plugin.
    if let Some(declared) = runtime.sdk_version {
        if declared > PUMPBIN_SDK_VERSION {
            return Err(PumpBinError::WasmSdkVersionMismatch {
                module: module_name,
                declared,
                host_version: PUMPBIN_SDK_VERSION,
            });
        }
    }

    ResolvedPolicy::from_runtime(module_name, &runtime)
}

fn is_missing_export(message: &str) -> bool {
    let msg = message.to_ascii_lowercase();
    (msg.contains("not found") || msg.contains("missing"))
        && (msg.contains("function") || msg.contains("export"))
}

// ── Schema types (mirrored in plugin-sdk for WASM authors) ────────────────────

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PluginConfigField {
    pub key: String,
    #[serde(default, rename = "type")]
    pub field_type: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub options: Vec<String>,
}

/// Current PumpBin SDK version. Bump on breaking schema changes only.
/// Plugins declare what they target via `RuntimeConfig::sdk_version`;
/// the host accepts any `declared <= PUMPBIN_SDK_VERSION` (additive
/// host evolution doesn't break old plugins). Mirrors the constant in
/// `pumpbin-plugin-sdk`.
///
/// v1 (1.1.7): per-module runtime policy.
/// v2 (1.5.0): host helper ABI via Extism with_function.
pub const PUMPBIN_SDK_VERSION: u32 = 2;

/// Per-module runtime policy declared by the plugin author. Mirrors
/// `pumpbin_plugin_sdk::RuntimeConfig` so the host can deserialize what
/// modules export from their `plugin_schema()` function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub on_error: OnError,
    #[serde(default)]
    pub sdk_version: Option<u32>,
}

fn default_timeout_ms() -> u64 {
    3000
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout_ms(),
            allowed_hosts: Vec::new(),
            on_error: OnError::default(),
            sdk_version: Some(PUMPBIN_SDK_VERSION),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    #[default]
    Abort,
    Skip,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PluginConfigSchema {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub fields: Vec<PluginConfigField>,
    /// Per-module runtime policy. `None` means the host applies safe
    /// defaults (3s timeout, no network, abort-on-error). Plugins built
    /// before v1.1.7 will not have this field; deserialization treats
    /// missing as `None`.
    #[serde(default)]
    pub runtime: Option<RuntimeConfig>,
}

// ── Module invocation ─────────────────────────────────────────────────────────

/// Call a single WASM module's exported function with JSON input.
/// Returns `None` if the function is not exported (optional hook).
///
/// As of v1.1.7, the module's per-call policy (timeout, allowed_hosts) is
/// resolved from its own `plugin_schema()` export before this call. Modules
/// without a schema get safe defaults (3s timeout, no network). SDK-version
/// mismatch fails fast with [`PumpBinError::WasmSdkVersionMismatch`].
#[tracing::instrument(skip(wasm, input, config), fields(func, wasm_len = wasm.len()))]
pub fn run_module<T: Serialize>(
    wasm: &[u8],
    func: &str,
    input: &T,
    config: Option<&BTreeMap<String, String>>,
) -> anyhow::Result<Option<Vec<u8>>> {
    let policy = resolve_policy(wasm, func)?;
    tracing::debug!(
        timeout_ms = policy.timeout.as_millis() as u64,
        allowed_hosts = policy.allowed_hosts.len(),
        "applying WASM policy"
    );
    let mut manifest = manifest_from_wasm_with_policy(wasm, &policy)?;

    if let Some(cfg) = config {
        manifest = manifest.with_config(cfg.clone().into_iter());
    }

    let mut plugin = build_plugin(manifest)?;

    match plugin.call::<Vec<u8>, Vec<u8>>(func, serde_json::to_vec(input)?) {
        Ok(output) => Ok(Some(output)),
        Err(e) => {
            // Modules don't have to export every hook — treat missing exports as no-op.
            let msg = e.to_string();
            if is_missing_export(&msg) {
                return Ok(None);
            }
            // Distinguish network-denial errors so the user gets PB-E0021
            // instead of a generic WasmCallFailed. Extism surfaces these
            // through the inner wasmtime/wasi-http error chain as either
            // "Host not allowed" or "url is not in the allow list".
            let lower = msg.to_ascii_lowercase();
            if lower.contains("not allowed") || lower.contains("not in the allow list") {
                let host = extract_host_hint(&msg).unwrap_or_else(|| "<unknown>".to_string());
                return Err(crate::error::PumpBinError::WasmHostDenied {
                    module: func.to_string(),
                    host,
                }
                .into());
            }
            Err(crate::error::PumpBinError::WasmCallFailed {
                hook: func.to_string(),
                detail: msg,
            }
            .into())
        }
    }
}

/// Best-effort: pull a hostname out of an extism "host not allowed"-style
/// error message. Returns `None` if no obvious host token is present.
fn extract_host_hint(msg: &str) -> Option<String> {
    // Patterns we've seen from extism / wasmtime:
    //   "Host not allowed: example.com"
    //   "url is not in the allow list: https://example.com/path"
    for marker in ["allowed: ", "allow list: ", "host: "] {
        if let Some(idx) = msg.find(marker) {
            let tail = &msg[idx + marker.len()..];
            let host: String = tail
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != '"' && *c != ',')
                .collect();
            if !host.is_empty() {
                return Some(host);
            }
        }
    }
    None
}

/// Kept for backwards-compatibility callers inside plugin.rs.
#[inline]
pub fn run_plugin<T: Serialize>(
    wasm: &[u8],
    func: &str,
    input: &T,
    config: Option<&BTreeMap<String, String>>,
) -> anyhow::Result<Option<Vec<u8>>> {
    run_module(wasm, func, input, config)
}

/// Load and call `plugin_schema` from a WASM module.
/// Returns `None` if the module does not export the function.
///
/// Uses [`ResolvedPolicy::defaults`] for the bootstrap call (3s timeout,
/// no network) — by definition the module's own runtime policy can't be
/// applied yet because reading it is what we're doing.
pub fn get_plugin_config_schema(wasm: &[u8]) -> anyhow::Result<Option<PluginConfigSchema>> {
    let policy = ResolvedPolicy::defaults("plugin_schema");
    let manifest = manifest_from_wasm_with_policy(wasm, &policy)?;

    let mut plugin = build_plugin(manifest)?;

    match plugin.call::<Vec<u8>, Vec<u8>>("plugin_schema", Vec::new()) {
        Ok(output) => Ok(Some(serde_json::from_slice(output.as_slice())?)),
        Err(e) => {
            if is_missing_export(&e.to_string()) {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

// ── Event dispatch ────────────────────────────────────────────────────────────

pub struct EventManager;

impl EventManager {
    /// Call the first module that exports `hook_name` and return its output.
    /// Modules that don't export the hook are skipped transparently.
    /// Use this for all hooks except `post_binary`.
    pub fn fire<T: Serialize, R: serde::de::DeserializeOwned>(
        modules: &[Vec<u8>],
        hook_name: &str,
        input: &T,
        config: Option<&BTreeMap<String, String>>,
    ) -> anyhow::Result<Option<R>> {
        for wasm in modules {
            if let Some(res) = run_module(wasm, hook_name, input, config)? {
                return Ok(Some(serde_json::from_slice(&res)?));
            }
        }
        Ok(None)
    }

    /// Run `post_binary` through ALL modules in order, passing the output of
    /// each into the next. This allows chaining: e.g. strip → sign → obfuscate.
    /// A module that doesn't export `post_binary` is skipped.
    ///
    /// Per-module `OnError` policy (v1.1.12): if a module returns an
    /// error AND its schema declares `runtime.on_error = Skip`, the
    /// dispatcher logs a `warn!` with the module's policy name + error
    /// detail and continues the chain with the unmodified binary. The
    /// default `OnError::Abort` behavior bubbles the error up as before.
    /// Modules without a schema fall through to defaults (Abort).
    pub fn fire_post_binary(
        modules: &[Vec<u8>],
        initial: Vec<u8>,
        config: Option<&BTreeMap<String, String>>,
    ) -> anyhow::Result<Vec<u8>> {
        let mut binary = initial;

        for (idx, wasm) in modules.iter().enumerate() {
            // Look up this module's on_error policy. resolve_policy
            // already gave us a ResolvedPolicy, but that doesn't carry
            // on_error (which is dispatcher-only, not extism-side).
            // Read the schema directly here.
            let on_error = match get_plugin_config_schema(wasm) {
                Ok(Some(schema)) => schema
                    .runtime
                    .as_ref()
                    .map(|r| r.on_error)
                    .unwrap_or(OnError::Abort),
                _ => OnError::Abort,
            };

            let input = PostBinaryInput {
                final_binary: binary.clone(),
                binary: vec![],
            };

            match run_module(wasm, "post_binary", &input, config) {
                Ok(Some(raw)) => match serde_json::from_slice::<PostBinaryOutput>(&raw) {
                    Ok(output) => {
                        if output.changed && !output.final_binary.is_empty() {
                            binary = output.final_binary;
                        }
                    }
                    Err(e) => {
                        if matches!(on_error, OnError::Skip) {
                            tracing::warn!(
                                module_index = idx,
                                error = %e,
                                "post_binary module returned invalid JSON; skipping per on_error=Skip"
                            );
                        } else {
                            return Err(e.into());
                        }
                    }
                },
                Ok(None) => {
                    // Module doesn't export post_binary — silently skip.
                }
                Err(e) => {
                    if matches!(on_error, OnError::Skip) {
                        tracing::warn!(
                            module_index = idx,
                            error = %e,
                            "post_binary module failed; skipping per on_error=Skip"
                        );
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Ok(binary)
    }
}

// ── I/O types (host side) ─────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EncryptShellcodeInput {
    pub shellcode: Vec<u8>,
}

/// A placeholder-replacement pair returned by `encrypt_shellcode`.
///
/// `holder` must be present as a fixed-length byte sequence in the binary
/// template. PumpBin finds it with memmem and overwrites it with `replace_by`,
/// padded to the holder's length.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Pass {
    pub holder: Vec<u8>,
    pub replace_by: Vec<u8>,
}

impl Pass {
    pub fn holder(&self) -> &[u8] {
        &self.holder
    }
    pub fn replace_by(&self) -> &[u8] {
        &self.replace_by
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EncryptShellcodeOutput {
    pub encrypted: Vec<u8>,
    pub pass: Vec<Pass>,
}

impl EncryptShellcodeOutput {
    pub fn encrypted(&self) -> &[u8] {
        &self.encrypted
    }
    pub fn pass(&self) -> &[Pass] {
        &self.pass
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FormatEncryptedShellcodeInput {
    pub shellcode: Vec<u8>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FormatEncryptedShellcodeOutput {
    pub formatted_shellcode: Vec<u8>,
}

impl FormatEncryptedShellcodeOutput {
    pub fn formatted_shellcode(&self) -> &[u8] {
        &self.formatted_shellcode
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FormatUrlRemoteInput {
    pub url: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FormatUrlRemoteOutput {
    pub formatted_url: String,
}

impl FormatUrlRemoteOutput {
    pub fn formatted_url(&self) -> &str {
        &self.formatted_url
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UploadFinalShellcodeRemoteInput {
    pub final_shellcode: Vec<u8>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UploadFinalShellcodeRemoteOutput {
    pub url: String,
}

impl UploadFinalShellcodeRemoteOutput {
    pub fn url(&self) -> &str {
        &self.url
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PostBinaryInput {
    pub final_binary: Vec<u8>,
    #[serde(default)]
    pub binary: Vec<u8>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PostBinaryOutput {
    #[serde(default, alias = "binary")]
    pub final_binary: Vec<u8>,
    #[serde(default)]
    pub changed: bool,
}
