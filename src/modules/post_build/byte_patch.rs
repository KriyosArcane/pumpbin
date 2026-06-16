//! `PostBuildModule` that applies in-place byte substitutions across
//! the generated implant. Useful for breaking specific YARA byte
//! patterns when an equivalent-encoding swap is known (e.g. swapping
//! `48 31 D2` → `48 33 D2` to break the Metasploit x64 PEB-walk
//! signature without changing program behavior).
//!
//! Each patch is a `<hex_from>:<hex_to>` pair; from and to must be the
//! same number of bytes. All occurrences are replaced by default.
//!
//! Example:
//!   --post byte-patch:patches=4831d2:4833d2,4831c0:4833c0
//!
//! Args:
//!   `patches=<from>:<to>[,<from>:<to>...]` (required)
//!   `mode=first` | `mode=all` (optional, default `all`)

use anyhow::{anyhow, bail, Result};
use memchr::memmem;

use crate::modules::post_build::parse_kv_args;
use crate::modules::{ArgSpec, PostBuildModule};

pub struct BytePatch;

impl PostBuildModule for BytePatch {
    fn id(&self) -> &'static str {
        "byte-patch"
    }

    fn description(&self) -> &'static str {
        "Apply in-place hex byte substitutions to the implant (equal-length pairs only)"
    }

    fn args(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::new("patches", "string").required().described(
                "Comma-separated <hex_from>:<hex_to> pairs; each pair must be equal length",
            ),
            ArgSpec::new("mode", "string")
                .default_val("all")
                .described("`all` (replace every occurrence) or `first` (replace only first)"),
        ]
    }

    fn apply(&self, args: &[String], implant: &mut Vec<u8>) -> Result<()> {
        let kv = parse_kv_args(args)?;
        let patches_str = kv
            .iter()
            .find(|(k, _)| k == "patches")
            .map(|(_, v)| v.as_str())
            .ok_or_else(|| {
                anyhow!("byte-patch: missing required arg 'patches=<from>:<to>[,...]'")
            })?;
        let mode = kv
            .iter()
            .find(|(k, _)| k == "mode")
            .map(|(_, v)| v.as_str())
            .unwrap_or("all");
        let replace_all = match mode {
            "all" => true,
            "first" => false,
            other => bail!("byte-patch: mode must be 'all' or 'first', got '{other}'"),
        };

        let patches = parse_patches(patches_str)?;

        // Detect chain collisions: warn if any patch's output bytes appear
        // as a substring in another patch's input pattern.
        for (i, (_from_i, to_i)) in patches.iter().enumerate() {
            for (j, (from_j, _to_j)) in patches.iter().enumerate() {
                if i == j {
                    continue;
                }
                if memmem::find(from_j, to_i).is_some() {
                    tracing::warn!("byte-patch: patch {i} output may be consumed by patch {j}");
                }
            }
        }

        for (from, to) in &patches {
            apply_patch(implant, from, to, replace_all);
        }
        Ok(())
    }
}

fn parse_patches(spec: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out = Vec::new();
    for (idx, pair) in spec.split(',').enumerate() {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (from_hex, to_hex) = pair.split_once(':').ok_or_else(|| {
            anyhow!("byte-patch: pair {idx} missing ':' (expected '<from_hex>:<to_hex>')")
        })?;
        let from = decode_hex(from_hex)
            .map_err(|e| anyhow!("byte-patch: pair {idx} 'from' invalid hex: {e}"))?;
        let to = decode_hex(to_hex)
            .map_err(|e| anyhow!("byte-patch: pair {idx} 'to' invalid hex: {e}"))?;
        if from.len() != to.len() {
            bail!(
                "byte-patch: pair {idx} length mismatch (from={} B, to={} B); must be equal-length for in-place patching",
                from.len(),
                to.len()
            );
        }
        if from.is_empty() {
            bail!("byte-patch: pair {idx} is empty");
        }
        out.push((from, to));
    }
    if out.is_empty() {
        bail!("byte-patch: no patches parsed from 'patches' arg");
    }
    Ok(out)
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let trimmed: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !trimmed.len().is_multiple_of(2) {
        bail!("hex must have even number of digits, got {}", trimmed.len());
    }
    (0..trimmed.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&trimmed[i..i + 2], 16).map_err(|e| anyhow!("{e}")))
        .collect()
}

fn apply_patch(buf: &mut [u8], from: &[u8], to: &[u8], replace_all: bool) {
    let mut start = 0;
    while start + from.len() <= buf.len() {
        if let Some(pos) = find_subslice(&buf[start..], from) {
            let abs = start + pos;
            buf[abs..abs + to.len()].copy_from_slice(to);
            if !replace_all {
                return;
            }
            start = abs + to.len();
        } else {
            return;
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_all_occurrences_by_default() {
        let m = BytePatch;
        let mut buf = vec![0x48, 0x31, 0xd2, 0xaa, 0x48, 0x31, 0xd2, 0xbb];
        m.apply(&["patches=4831d2:4833d2".into()], &mut buf)
            .unwrap();
        assert_eq!(buf, vec![0x48, 0x33, 0xd2, 0xaa, 0x48, 0x33, 0xd2, 0xbb]);
    }

    #[test]
    fn mode_first_replaces_only_first() {
        let m = BytePatch;
        let mut buf = vec![0x48, 0x31, 0xd2, 0xaa, 0x48, 0x31, 0xd2];
        m.apply(
            &["patches=4831d2:4833d2".into(), "mode=first".into()],
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf, vec![0x48, 0x33, 0xd2, 0xaa, 0x48, 0x31, 0xd2]);
    }

    #[test]
    fn multiple_pairs_applied_in_order() {
        let m = BytePatch;
        let mut buf = vec![0x48, 0x31, 0xd2, 0x48, 0x31, 0xc0];
        m.apply(&["patches=4831d2:4833d2,4831c0:4833c0".into()], &mut buf)
            .unwrap();
        assert_eq!(buf, vec![0x48, 0x33, 0xd2, 0x48, 0x33, 0xc0]);
    }

    #[test]
    fn length_mismatch_errors() {
        let m = BytePatch;
        let mut buf = vec![0u8; 16];
        let err = m
            .apply(&["patches=4831d2:4833".into()], &mut buf)
            .unwrap_err();
        assert!(err.to_string().contains("length mismatch"));
    }

    #[test]
    fn missing_patches_arg_errors() {
        let m = BytePatch;
        let mut buf = Vec::new();
        let err = m.apply(&[], &mut buf).unwrap_err();
        assert!(err.to_string().contains("patches"));
    }

    #[test]
    fn no_match_is_noop() {
        let m = BytePatch;
        let mut buf = vec![0u8; 8];
        m.apply(&["patches=4831d2:4833d2".into()], &mut buf)
            .unwrap();
        assert_eq!(buf, vec![0u8; 8]);
    }
}
