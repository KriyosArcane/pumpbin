//! Identity URL formatter. Replaces the `plugin-examples/url-format`
//! WASM plugin's prefix/suffix branch; the base64 branch is deferred
//! until the post-build chain (Step 9) provides arg plumbing.

use anyhow::Result;

use crate::modules::FormatUrlModule;

pub struct PassThrough;

impl FormatUrlModule for PassThrough {
    fn id(&self) -> &'static str {
        "url-passthrough"
    }

    fn description(&self) -> &'static str {
        "Embeds the operator URL verbatim"
    }

    fn format(&self, url: &str) -> Result<String> {
        Ok(url.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity() {
        let m = PassThrough;
        assert_eq!(m.format("https://example.com/x").unwrap(), "https://example.com/x");
    }
}
