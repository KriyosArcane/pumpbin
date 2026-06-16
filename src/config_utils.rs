//! Shared configuration utilities used by both the Generator and Maker workspaces.
//!
//! These free functions were previously copy-pasted between `Pumpbin` and `Maker`.
//! All call sites now delegate here.

use std::path::PathBuf;

use base64::{engine::general_purpose, Engine as _};
use dirs::home_dir;

use crate::plugin_system::PluginConfigField;

// ── Path helpers ─────────────────────────────────────────────────────────────

/// Expands a leading `~` to the user's home directory.
pub fn maybe_expand_home_path(value: &str) -> PathBuf {
    if value == "~" {
        return home_dir().unwrap_or_else(|| PathBuf::from("."));
    }

    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }

    PathBuf::from(value)
}

/// Returns `true` if the value looks like an absolute path (`/`, `~`, or
/// a Windows drive letter like `C:\`).
pub fn looks_like_absolute_path(value: &str) -> bool {
    if value.starts_with('/') || value.starts_with('~') {
        return true;
    }
    let bytes = value.as_bytes();
    bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'\\' && bytes[0].is_ascii_alphabetic()
}

/// Returns `true` if the value resembles any kind of filesystem path.
pub fn looks_like_path(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with('~')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.contains('/')
        || value.contains('\\')
}

// ── Schema / field helpers ────────────────────────────────────────────────────

/// Returns the schema field for `key`, or `None` if not in schema.
pub fn schema_field_for_key<'a>(
    schema: &'a [PluginConfigField],
    key: &str,
) -> Option<&'a PluginConfigField> {
    schema.iter().find(|f| f.key == key)
}

/// Returns `true` if the key name alone suggests a file-type config entry.
pub fn config_key_is_file_like(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "file", "path", "icon", "image", "cert", "pfx", "pem", "keystore",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

/// Returns `true` if the field's schema type OR the key name indicates a file field.
pub fn config_key_is_file_like_with_schema(schema: &[PluginConfigField], key: &str) -> bool {
    if let Some(field) = schema_field_for_key(schema, key) {
        if field.field_type.eq_ignore_ascii_case("file")
            || field.field_type.eq_ignore_ascii_case("file_base64")
            || field.field_type.eq_ignore_ascii_case("file_path")
        {
            return true;
        }
    }
    config_key_is_file_like(key)
}

// ── Config validation ─────────────────────────────────────────────────────────

/// Validates a single config entry. Returns an error message string, or `None`
/// if the entry is valid.
pub fn config_value_error(
    field: Option<&PluginConfigField>,
    key: &str,
    value: &str,
) -> Option<String> {
    let key = key.trim();
    if key.is_empty() {
        return Some("key is required".to_string());
    }

    let trimmed = value.trim();
    if let Some(field) = field {
        if field.required && trimmed.is_empty() {
            return Some("value is required".to_string());
        }

        match field.field_type.to_ascii_lowercase().as_str() {
            "number" if !trimmed.is_empty() && trimmed.parse::<f64>().is_err() => {
                return Some("expected a number".to_string());
            }
            "boolean" if !trimmed.is_empty() => match trimmed.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" | "0" | "false" | "no" | "off" => {}
                _ => return Some("expected true/false".to_string()),
            },
            "choice" if !trimmed.is_empty() && !field.options.contains(&trimmed.to_string()) => {
                return Some(format!("expected one of: {}", field.options.join(", ")));
            }
            "file" | "file_base64" if !trimmed.is_empty() => {
                let file_path = maybe_expand_home_path(trimmed);
                if file_path.is_file() {
                    return None;
                }
                if looks_like_path(trimmed) {
                    return Some("file path does not exist".to_string());
                }
                if general_purpose::STANDARD
                    .decode(trimmed.as_bytes())
                    .is_err()
                {
                    return Some("expected file path or base64 bytes".to_string());
                }
            }
            _ => {}
        }
    }

    None
}

// ── Config merging ────────────────────────────────────────────────────────────

/// Merges a plugin's existing config with its schema, optionally applying
/// schema defaults for empty/missing keys.
pub fn merge_config_with_schema(
    config: &[(String, String)],
    schema: &[PluginConfigField],
    apply_defaults: bool,
) -> Vec<(String, String)> {
    if schema.is_empty() {
        return config.to_vec();
    }

    let mut merged: Vec<(String, String)> = schema
        .iter()
        .filter(|f| !f.key.trim().is_empty())
        .map(|f| {
            let initial = if apply_defaults {
                f.default.clone().unwrap_or_default()
            } else {
                String::new()
            };
            (f.key.clone(), initial)
        })
        .collect();

    for (key, value) in config {
        if let Some((_, existing)) = merged.iter_mut().find(|(k, _)| k == key) {
            if value.trim().is_empty() && apply_defaults {
                continue;
            }
            *existing = value.clone();
        } else {
            merged.push((key.clone(), value.clone()));
        }
    }

    merged
}

/// Strips absolute paths from file-like config entries so the saved state is
/// portable across machines.
pub fn sanitize_config(
    entries: &[(String, String)],
    schema: &[PluginConfigField],
) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(k, v)| {
            if config_key_is_file_like_with_schema(schema, k) && looks_like_absolute_path(v) {
                (k.clone(), String::new())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}
