//! Module dispatch by string id.
//!
//! Lookup checks built-ins where they exist, then external user drop-ins.
//! Unknown ids return a clear error listing what
//! IS available so operators can fix typos.

use anyhow::{anyhow, Result};
use std::collections::BTreeMap;
use std::path::Path;

use crate::modules::external::{self, wire::WireKind};
use crate::modules::{encrypt_modules, post_build_modules, ModuleArg, ModuleKind};
use crate::plugin_system::EncryptShellcodeOutput;

pub fn encrypt(id: &str, args: &[String], shellcode: &[u8]) -> Result<EncryptShellcodeOutput> {
    if let Some(m) = encrypt_modules().iter().find(|m| m.id() == id) {
        let descriptor = crate::modules::descriptor_for(ModuleKind::Encrypt, id)
            .ok_or_else(|| anyhow!("module descriptor not found for '{id}'"))?;
        let _args = validate_descriptor_args(id, args, &descriptor)?;
        return m.encrypt(shellcode);
    }
    if let Some(ext) = external::registry().get(id) {
        if ext.kind() == WireKind::Encrypt {
            tracing::debug!(module = id, "invoking encrypt module");
            let descriptor = crate::modules::descriptor_for(ModuleKind::Encrypt, id)
                .ok_or_else(|| anyhow!("module descriptor not found for '{id}'"))?;
            let args = validate_descriptor_args(id, args, &descriptor)?;
            let (resp, body) = external::invoke(ext, WireKind::Encrypt, &args, shellcode)?;
            let pass = resp
                .pass
                .iter()
                .map(|p| p.decode())
                .collect::<Result<Vec<_>>>()?;
            return Ok(EncryptShellcodeOutput {
                encrypted: body,
                pass,
            });
        }
        return Err(anyhow!(
            "module '{id}' exists but is kind {:?}, not encrypt",
            ext.kind()
        ));
    }
    Err(anyhow!(
        "encrypt module not found: '{}' (available: {})",
        id,
        available_ids_for(WireKind::Encrypt).join(", ")
    ))
}

pub fn post_build(id: &str, args: &[String], implant: &mut Vec<u8>) -> Result<()> {
    if let Some(m) = post_build_modules().iter().find(|m| m.id() == id) {
        let descriptor = crate::modules::descriptor_for(ModuleKind::PostBuild, id)
            .ok_or_else(|| anyhow!("module descriptor not found for '{id}'"))?;
        let args = validate_descriptor_args(id, args, &descriptor)?;
        return m.apply(&args, implant);
    }
    if let Some(ext) = external::registry().get(id) {
        if ext.kind() == WireKind::PostBuild {
            tracing::debug!(module = id, "invoking post-build module");
            let descriptor = crate::modules::descriptor_for(ModuleKind::PostBuild, id)
                .ok_or_else(|| anyhow!("module descriptor not found for '{id}'"))?;
            let args = validate_descriptor_args(id, args, &descriptor)?;
            let (_resp, body) = external::invoke(ext, WireKind::PostBuild, &args, implant)?;
            *implant = body;
            return Ok(());
        }
        return Err(anyhow!(
            "module '{id}' exists but is kind {:?}, not post_build",
            ext.kind()
        ));
    }
    Err(anyhow!(
        "post_build module not found: '{}' (available: {})",
        id,
        available_ids_for(WireKind::PostBuild).join(", ")
    ))
}

fn available_ids_for(kind: WireKind) -> Vec<String> {
    let mut out: Vec<String> = match kind {
        WireKind::Encrypt => encrypt_modules()
            .iter()
            .map(|m| m.id().to_string())
            .collect(),
        WireKind::PostBuild => post_build_modules()
            .iter()
            .map(|m| m.id().to_string())
            .collect(),
    };
    for ext in external::registry().all() {
        if ext.kind() == kind {
            out.push(ext.id().to_string());
        }
    }
    out
}

pub fn validate_args_only(kind: ModuleKind, id: &str, args: &[String]) -> Result<Vec<String>> {
    let descriptor = crate::modules::descriptor_for(kind, id).ok_or_else(|| {
        anyhow!(
            "{} module not found: '{}'",
            kind.as_str().replace('-', "_"),
            id
        )
    })?;
    validate_descriptor_args(id, args, &descriptor)
}

fn validate_descriptor_args(
    module_id: &str,
    args: &[String],
    descriptor: &crate::modules::ModuleDescriptor,
) -> Result<Vec<String>> {
    validate_args(
        module_id,
        args,
        &descriptor.args,
        descriptor.allows_arbitrary_args_without_schema(),
    )
}

fn validate_args(
    module_id: &str,
    args: &[String],
    rules: &[ModuleArg],
    allow_arbitrary_without_schema: bool,
) -> Result<Vec<String>> {
    if rules.is_empty() {
        if allow_arbitrary_without_schema || args.is_empty() {
            return Ok(args.to_vec());
        }
        return Err(anyhow!(
            "module '{module_id}' does not declare any args, but got: {}",
            args.join(", ")
        ));
    }

    let mut values = BTreeMap::new();
    let mut provided = std::collections::BTreeSet::new();
    for arg in args {
        let (key, value) = arg
            .split_once('=')
            .ok_or_else(|| anyhow!("module '{module_id}': expected key=value arg, got '{arg}'"))?;
        let key = key.trim();
        if key.is_empty() {
            return Err(anyhow!("module '{module_id}': empty arg key in '{arg}'"));
        }
        provided.insert(key.to_string());
        values.insert(key.to_string(), value.to_string());
    }

    for key in values.keys() {
        if !rules.iter().any(|rule| rule.key == *key) {
            let valid = rules
                .iter()
                .map(|rule| rule.key.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(anyhow!(
                "module '{module_id}': unknown arg '{key}' (valid: {valid})"
            ));
        }
    }

    for rule in rules {
        if !values.contains_key(&rule.key) {
            if let Some(default) = &rule.default {
                values.insert(rule.key.clone(), default.clone());
            }
        }
        let Some(value) = values.get_mut(&rule.key) else {
            if rule.required {
                return Err(anyhow!(
                    "module '{module_id}': missing required arg '{}'. Run `pumpbin-cli module list --options --id {module_id}`.",
                    rule.key
                ));
            }
            continue;
        };
        if rule.required && value.trim().is_empty() {
            return Err(anyhow!(
                "module '{module_id}': required arg '{}' cannot be empty",
                rule.key
            ));
        }
        validate_arg_type(module_id, &rule.key, &rule.arg_type, value)?;
    }

    Ok(values
        .into_iter()
        .filter(|(key, value)| !value.is_empty() || provided.contains(key))
        .map(|(key, value)| format!("{key}={value}"))
        .collect())
}

fn validate_arg_type(module_id: &str, key: &str, arg_type: &str, value: &mut String) -> Result<()> {
    match arg_type.to_ascii_lowercase().as_str() {
        "" | "string" => Ok(()),
        "number" => {
            value.parse::<f64>().map_err(|_| {
                anyhow!("module '{module_id}': arg '{key}' expects a number, got '{value}'")
            })?;
            Ok(())
        }
        "boolean" | "bool" => {
            let normalized = match value.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => "true",
                "0" | "false" | "no" | "off" => "false",
                _ => {
                    return Err(anyhow!(
                        "module '{module_id}': arg '{key}' expects a boolean, got '{value}'"
                    ));
                }
            };
            *value = normalized.to_string();
            Ok(())
        }
        "path" | "file" | "file_path" => {
            if Path::new(value).is_file() {
                Ok(())
            } else {
                Err(anyhow!(
                    "module '{module_id}': arg '{key}' points to missing file '{value}'"
                ))
            }
        }
        _ => Ok(()),
    }
}
