pub mod byte_patch;
pub mod cert_graft;
pub mod pe_version_info;

/// Parse a slice of `key=value` strings into `(key, value)` pairs.
/// Returns an error if any argument lacks an `=`.
pub(crate) fn parse_kv_args(args: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    args.iter()
        .map(|a| {
            a.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| anyhow::anyhow!("expected key=value, got: {a}"))
        })
        .collect()
}
