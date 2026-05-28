//! `host::pe::*` — PE32/PE32+ inspection and patching, host-provided.
//!
//! `set_version_info` lifts the v1.4-era hand-rolled VS_VERSION_INFO
//! TLV walker out of `plugin-examples/pe-version-info` so the plugin
//! can shrink from 277 LOC to a thin SDK call. Byte-for-byte
//! equivalence is enforced by the existing `tests/golden.rs`.

use extism::{Function, UserData, ValType};
use goblin::pe::PE;
use pumpbin_plugin_sdk::host::pe::{
    GetSectionInput, GetSectionOutput, SetIconInput, SetVersionInfoInput,
};

use super::{decode, encode_response, HOST_HELPER_NAMESPACE};

/// Register all PE host functions.
pub fn register() -> Vec<Function> {
    vec![
        make("pe_recompute_checksum", handle_recompute_checksum),
        make("pe_get_section", handle_get_section),
        make("pe_strip_debug", handle_strip_debug),
        make("pe_set_version_info", handle_set_version_info),
        make("pe_set_icon", handle_set_icon),
    ]
}

/// Builds an Extism Function from a `fn(&[u8]) -> Vec<u8>` handler.
fn make(name: &'static str, handler: fn(&[u8]) -> Vec<u8>) -> Function {
    Function::new(
        name,
        [ValType::I64],
        [ValType::I64],
        UserData::<()>::default(),
        move |current, inputs, outputs, _ud| {
            let raw = current
                .memory_get_val::<Vec<u8>>(&inputs[0])
                .map_err(|e| anyhow::anyhow!("read input memory: {e}"))?;
            let bytes = handler(&raw);
            current
                .memory_set_val(&mut outputs[0], bytes)
                .map_err(|e| anyhow::anyhow!("write output memory: {e}"))?;
            Ok(())
        },
    )
    .with_namespace(HOST_HELPER_NAMESPACE)
}

// ── handlers ─────────────────────────────────────────────────────────

fn handle_recompute_checksum(raw: &[u8]) -> Vec<u8> {
    encode_response::<Vec<u8>>(do_recompute_checksum(raw))
}

fn do_recompute_checksum(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut bin: Vec<u8> = decode(raw)?;
    // utils::recompute_pe_checksum returns `false` on non-PE input
    // and leaves the buffer untouched. The SDK contract says the
    // helper is a no-op on non-PE — return the input verbatim.
    crate::utils::recompute_pe_checksum(&mut bin);
    Ok(bin)
}

fn handle_get_section(raw: &[u8]) -> Vec<u8> {
    encode_response::<Option<GetSectionOutput>>(do_get_section(raw))
}

fn do_get_section(raw: &[u8]) -> Result<Option<GetSectionOutput>, String> {
    let input: GetSectionInput = decode(raw)?;
    let pe = PE::parse(&input.bin).map_err(|e| format!("PE parse: {e}"))?;
    for section in pe.sections {
        // section.name is [u8; 8], NUL-padded.
        let name = section
            .name()
            .map_err(|e| format!("section name decode: {e}"))?
            .trim_end_matches('\0');
        if name == input.name {
            return Ok(Some(GetSectionOutput {
                offset: section.pointer_to_raw_data,
                size: section.size_of_raw_data,
            }));
        }
    }
    Ok(None)
}

fn handle_strip_debug(raw: &[u8]) -> Vec<u8> {
    encode_response::<Vec<u8>>(do_strip_debug(raw))
}

fn do_strip_debug(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut bin: Vec<u8> = decode(raw)?;
    // Parse to locate the debug data directory + its entries; then
    // drop back to byte-level mutation so we don't depend on goblin's
    // PE writer (which doesn't exist).
    let (debug_dir_rva, debug_dir_size, sections) = {
        let pe = PE::parse(&bin).map_err(|e| format!("PE parse: {e}"))?;
        let opt = pe
            .header
            .optional_header
            .ok_or_else(|| "missing optional header".to_string())?;
        let dd = match opt.data_directories.get_debug_table() {
            Some(d) => d,
            None => return Ok(bin), // no debug directory → nothing to strip
        };
        let sections: Vec<(u32, u32, u32, u32)> = pe
            .sections
            .iter()
            .map(|s| {
                (
                    s.virtual_address,
                    s.virtual_size,
                    s.pointer_to_raw_data,
                    s.size_of_raw_data,
                )
            })
            .collect();
        (dd.virtual_address, dd.size, sections)
    };

    // Map debug-dir RVA → file offset
    let Some(dir_off) = rva_to_file_offset(&sections, debug_dir_rva) else {
        // RVA didn't land in a section; nothing safe to strip
        return Ok(bin);
    };

    // Each IMAGE_DEBUG_DIRECTORY entry is 28 bytes (0x1C). Zero the
    // backing data (PointerToRawData..+SizeOfData) for each, then
    // zero the directory entries themselves.
    let entry_size: usize = 28;
    let dir_size = debug_dir_size as usize;
    if dir_off + dir_size > bin.len() {
        return Ok(bin);
    }
    let n = dir_size / entry_size;
    for i in 0..n {
        let off = dir_off + i * entry_size;
        // SizeOfData @ +0x10 (u32), PointerToRawData @ +0x18 (u32)
        let size_of_data =
            u32::from_le_bytes(bin[off + 0x10..off + 0x14].try_into().unwrap()) as usize;
        let ptr_raw_data =
            u32::from_le_bytes(bin[off + 0x18..off + 0x1C].try_into().unwrap()) as usize;
        if ptr_raw_data != 0 && size_of_data != 0 && ptr_raw_data + size_of_data <= bin.len() {
            bin[ptr_raw_data..ptr_raw_data + size_of_data].fill(0);
        }
    }
    bin[dir_off..dir_off + dir_size].fill(0);
    Ok(bin)
}

/// Convert an RVA to a file offset by walking section headers.
fn rva_to_file_offset(sections: &[(u32, u32, u32, u32)], rva: u32) -> Option<usize> {
    for &(vaddr, vsize, praw, _sraw) in sections {
        if rva >= vaddr && rva < vaddr + vsize {
            return Some((praw + (rva - vaddr)) as usize);
        }
    }
    None
}

fn handle_set_version_info(raw: &[u8]) -> Vec<u8> {
    encode_response::<Vec<u8>>(do_set_version_info(raw))
}

fn do_set_version_info(raw: &[u8]) -> Result<Vec<u8>, String> {
    let input: SetVersionInfoInput = decode(raw)?;
    let SetVersionInfoInput { mut bin, fields } = input;
    // The walker mutates in place and returns whether anything
    // matched; the SDK contract returns the (possibly unchanged)
    // binary either way, so the bool is discarded.
    let patches: Vec<(&str, String)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    let _changed = patch_version_info(&mut bin, &patches);
    Ok(bin)
}

fn handle_set_icon(raw: &[u8]) -> Vec<u8> {
    encode_response::<Vec<u8>>(do_set_icon(raw))
}

fn do_set_icon(raw: &[u8]) -> Result<Vec<u8>, String> {
    // Declared in the SDK contract but not implemented in v1.5.0.
    // Surfacing a structured error keeps the wire schema stable so a
    // follow-up release can fill this in without an SDK bump.
    let _input: SetIconInput = decode(raw)?;
    Err(
        "pe_set_icon is declared in SDK v2 but not implemented in PumpBin 1.5.0; see CHANGELOG"
            .to_string(),
    )
}

// ── VS_VERSION_INFO TLV walker (lifted from plugin-examples/pe-version-info) ──
//
// All wLength fields are in bytes, all DWORD alignment is RELATIVE to the
// start of the containing block (not the absolute file offset).
//
//   Root block @ root_start:
//     [u16 wLength][u16 wValueLength][u16 wType=0]
//     UTF-16LE "VS_VERSION_INFO\0"
//     DWORD pad (rel to root_start)
//     VS_FIXEDFILEINFO (wValueLength bytes, always 52)
//     DWORD pad (rel to root_start)
//     Children: StringFileInfo, VarFileInfo...

fn dword_align_rel(base: usize, offset: usize) -> usize {
    let rel = offset - base;
    let rel_aligned = rel.div_ceil(4) * 4;
    base + rel_aligned
}

fn patch_version_info(binary: &mut [u8], patches: &[(&str, String)]) -> bool {
    try_patch(binary, patches).unwrap_or(false)
}

fn try_patch(binary: &mut [u8], patches: &[(&str, String)]) -> Option<bool> {
    const SIG: &[u8] = &[
        0x56, 0x00, 0x53, 0x00, 0x5F, 0x00, 0x56, 0x00, 0x45, 0x00, 0x52, 0x00, 0x53, 0x00, 0x49,
        0x00, 0x4F, 0x00, 0x4E, 0x00, 0x5F, 0x00, 0x49, 0x00, 0x4E, 0x00, 0x46, 0x00, 0x4F, 0x00,
        0x00, 0x00,
    ];
    let sig_pos = binary.windows(SIG.len()).position(|w| w == SIG)?;
    let root = sig_pos.checked_sub(6)?;
    let root_len = read_u16(binary, root) as usize;
    let root_end = root.checked_add(root_len)?;
    if root_end > binary.len() || root_len < 6 {
        return None;
    }

    let root_val_len = read_u16(binary, root + 2) as usize;
    let key_nul = sig_pos + SIG.len() - 2;
    let after_key = key_nul + 2;
    let after_key_aligned = dword_align_rel(root, after_key);
    let after_fixed = after_key_aligned + root_val_len;
    let children_start = dword_align_rel(root, after_fixed);

    Some(walk_sfi(binary, root, children_start, root_end, patches))
}

fn walk_sfi(
    binary: &mut [u8],
    root: usize,
    start: usize,
    end: usize,
    patches: &[(&str, String)],
) -> bool {
    let mut pos = start;
    let mut changed = false;
    while pos + 6 <= end {
        let block_len = read_u16(binary, pos) as usize;
        if block_len < 6 {
            break;
        }
        let block_end = pos + block_len;
        if block_end > end {
            break;
        }
        let key_nul = find_utf16_nul(binary, pos + 6, block_end).unwrap_or(block_end);
        let key = read_utf16le(binary, pos + 6, key_nul);
        if key == "StringFileInfo" {
            let after_key = dword_align_rel(pos, key_nul + 2);
            changed |= walk_string_tables(binary, pos, after_key, block_end, patches);
        }
        let next = dword_align_rel(root, block_end);
        if next <= pos {
            break;
        }
        pos = next;
    }
    changed
}

fn walk_string_tables(
    binary: &mut [u8],
    sfi_start: usize,
    start: usize,
    end: usize,
    patches: &[(&str, String)],
) -> bool {
    let mut pos = start;
    let mut changed = false;
    while pos + 6 <= end {
        let block_len = read_u16(binary, pos) as usize;
        if block_len < 6 {
            break;
        }
        let block_end = pos + block_len;
        if block_end > end {
            break;
        }
        let key_nul = find_utf16_nul(binary, pos + 6, block_end).unwrap_or(block_end);
        let entries_start = dword_align_rel(pos, key_nul + 2);
        changed |= walk_entries(binary, pos, entries_start, block_end, patches);
        let next = dword_align_rel(sfi_start, block_end);
        if next <= pos {
            break;
        }
        pos = next;
    }
    changed
}

fn walk_entries(
    binary: &mut [u8],
    table_start: usize,
    start: usize,
    end: usize,
    patches: &[(&str, String)],
) -> bool {
    let mut pos = start;
    let mut changed = false;
    while pos + 6 <= end {
        let entry_len = read_u16(binary, pos) as usize;
        if entry_len < 6 {
            break;
        }
        let entry_end = pos + entry_len;
        if entry_end > end {
            break;
        }
        let val_words = read_u16(binary, pos + 2) as usize;
        let key_nul = find_utf16_nul(binary, pos + 6, entry_end).unwrap_or(entry_end);
        let key = read_utf16le(binary, pos + 6, key_nul);
        let val_start = dword_align_rel(pos, key_nul + 2);
        let val_slot = val_words * 2;
        if let Some((_, new_val)) = patches.iter().find(|(k, _)| *k == key) {
            if val_slot >= 2 && val_start + val_slot <= entry_end {
                patch_value(binary, val_start, val_slot, new_val, pos + 2);
                changed = true;
            }
        }
        let next = dword_align_rel(table_start, entry_end);
        if next <= pos {
            break;
        }
        pos = next;
    }
    changed
}

fn patch_value(
    binary: &mut [u8],
    val_start: usize,
    slot_bytes: usize,
    new_val: &str,
    wvl_pos: usize,
) {
    let end = val_start + slot_bytes;
    if end > binary.len() {
        return;
    }
    binary[val_start..end].fill(0);
    let max_chars = slot_bytes / 2;
    let mut written = 0usize;
    for (i, ch) in new_val.encode_utf16().enumerate() {
        if i + 1 >= max_chars {
            break;
        }
        let off = val_start + i * 2;
        binary[off] = (ch & 0xFF) as u8;
        binary[off + 1] = (ch >> 8) as u8;
        written += 1;
    }
    let wvl = (written + 1) as u16;
    if wvl_pos + 2 <= binary.len() {
        let le = wvl.to_le_bytes();
        binary[wvl_pos] = le[0];
        binary[wvl_pos + 1] = le[1];
    }
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn find_utf16_nul(data: &[u8], start: usize, end: usize) -> Option<usize> {
    let start = (start + 1) & !1;
    let mut i = start;
    while i + 1 < end {
        if data[i] == 0 && data[i + 1] == 0 {
            return Some(i);
        }
        i += 2;
    }
    None
}

fn read_utf16le(data: &[u8], start: usize, end: usize) -> String {
    if start >= end || end > data.len() {
        return String::new();
    }
    let words: Vec<u16> = data[start..end]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&words).to_string()
}
