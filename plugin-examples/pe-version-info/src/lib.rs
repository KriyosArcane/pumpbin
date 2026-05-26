use pumpbin_plugin_sdk::*;

#[plugin_fn]
pub fn plugin_schema() -> FnResult<Json<PluginConfigSchema>> {
    Ok(Json(PluginConfigSchema::new(vec![
        PluginConfigField::new("company_name", "text")
            .description("CompanyName string in the PE Details tab."),
        PluginConfigField::new("file_description", "text")
            .description("FileDescription string in the PE Details tab."),
        PluginConfigField::new("file_version", "text")
            .description("FileVersion string, e.g. \"1.0.0.0\"."),
        PluginConfigField::new("internal_name", "text")
            .description("InternalName string in the PE Details tab."),
        PluginConfigField::new("legal_copyright", "text")
            .description("LegalCopyright string in the PE Details tab."),
        PluginConfigField::new("original_filename", "text")
            .description("OriginalFilename string in the PE Details tab."),
        PluginConfigField::new("product_name", "text")
            .description("ProductName string in the PE Details tab."),
        PluginConfigField::new("product_version", "text")
            .description("ProductVersion string, e.g. \"1.0\"."),
    ])))
}

#[plugin_fn]
pub fn post_binary(Json(input): Json<PostBinaryInput>) -> FnResult<Json<PostBinaryOutput>> {
    let patches: &[(&str, &str)] = &[
        ("CompanyName",      "company_name"),
        ("FileDescription",  "file_description"),
        ("FileVersion",      "file_version"),
        ("InternalName",     "internal_name"),
        ("LegalCopyright",   "legal_copyright"),
        ("OriginalFilename", "original_filename"),
        ("ProductName",      "product_name"),
        ("ProductVersion",   "product_version"),
    ];

    let resolved: Vec<(&str, String)> = patches
        .iter()
        .filter_map(|(key, cfg)| pumpbin_config!(cfg).map(|v| (*key, v)))
        .collect();

    if resolved.is_empty() {
        return Ok(Json(PostBinaryOutput {
            final_binary: input.final_binary,
            changed: false,
        }));
    }

    let mut binary = input.final_binary;
    let changed = patch_version_info(&mut binary, &resolved);

    Ok(Json(PostBinaryOutput {
        final_binary: binary,
        changed,
    }))
}

// ── VS_VERSION_INFO TLV walker ────────────────────────────────────────────────
//
// All wLength fields are in bytes, all DWORD alignment is RELATIVE to the
// start of the containing block (not the absolute file offset).
//
//   Root block  @ root_start:
//     [u16 wLength][u16 wValueLength][u16 wType=0]
//     UTF-16LE "VS_VERSION_INFO\0"
//     DWORD pad (rel to root_start)
//     VS_FIXEDFILEINFO (wValueLength bytes, always 52)
//     DWORD pad (rel to root_start)
//     Children: StringFileInfo, VarFileInfo...
//
//   StringFileInfo:
//     [u16 wLength][u16 wValueLength=0][u16 wType=1]
//     UTF-16LE "StringFileInfo\0"
//     DWORD pad (rel to StringFileInfo start)
//     Children: StringTable...
//
//   StringTable:
//     [u16 wLength][u16 wValueLength=0][u16 wType=1]
//     UTF-16LE "<lang_codepage>\0"
//     DWORD pad (rel to StringTable start)
//     Children: String entries...
//
//   String entry:
//     [u16 wLength][u16 wValueLength][u16 wType=1]
//     UTF-16LE key\0
//     DWORD pad (rel to entry start)
//     UTF-16LE value\0   (slot = wValueLength * 2 bytes)

/// Round `offset` up to DWORD alignment, measured relative to `base`.
fn dword_align_rel(base: usize, offset: usize) -> usize {
    let rel = offset - base;
    let rel_aligned = (rel + 3) & !3;
    base + rel_aligned
}

fn patch_version_info(binary: &mut Vec<u8>, patches: &[(&str, String)]) -> bool {
    try_patch(binary, patches).unwrap_or(false)
}

fn try_patch(binary: &mut Vec<u8>, patches: &[(&str, String)]) -> Option<bool> {
    // UTF-16LE "VS_VERSION_INFO\0"
    const SIG: &[u8] = &[
        0x56,0x00,0x53,0x00,0x5F,0x00,0x56,0x00,0x45,0x00,0x52,0x00,
        0x53,0x00,0x49,0x00,0x4F,0x00,0x4E,0x00,0x5F,0x00,0x49,0x00,
        0x4E,0x00,0x46,0x00,0x4F,0x00,0x00,0x00,
    ];

    let sig_pos = binary.windows(SIG.len()).position(|w| w == SIG)?;
    let root = sig_pos.checked_sub(6)?;
    let root_len = read_u16(binary, root) as usize;
    let root_end = root.checked_add(root_len)?;
    if root_end > binary.len() || root_len < 6 {
        return None;
    }

    // Skip past header (6) + key + DWORD-align + VS_FIXEDFILEINFO
    let root_val_len = read_u16(binary, root + 2) as usize; // bytes of FIXEDFILEINFO (52)
    let key_nul = sig_pos + SIG.len() - 2; // SIG already includes \0\0 at the end, nul is last 2 bytes
    let after_key = key_nul + 2;
    let after_key_aligned = dword_align_rel(root, after_key);
    let after_fixed = after_key_aligned + root_val_len;
    let children_start = dword_align_rel(root, after_fixed);

    Some(walk_sfi(binary, root, children_start, root_end, patches))
}

/// Walk the direct children of the root block looking for StringFileInfo.
fn walk_sfi(
    binary: &mut Vec<u8>,
    root: usize,
    start: usize,
    end: usize,
    patches: &[(&str, String)],
) -> bool {
    let mut pos = start;
    let mut changed = false;
    while pos + 6 <= end {
        let block_len = read_u16(binary, pos) as usize;
        if block_len < 6 { break; }
        let block_end = pos + block_len;
        if block_end > end { break; }

        let key_nul = find_utf16_nul(binary, pos + 6, block_end).unwrap_or(block_end);
        let key = read_utf16le(binary, pos + 6, key_nul);

        if key == "StringFileInfo" {
            // Children of StringFileInfo start after its header+key, DWORD-aligned rel to pos
            let after_key = dword_align_rel(pos, key_nul + 2);
            changed |= walk_string_tables(binary, pos, after_key, block_end, patches);
        }

        let next = dword_align_rel(root, block_end);
        if next <= pos { break; }
        pos = next;
    }
    changed
}

/// Walk StringTable children of a StringFileInfo block.
fn walk_string_tables(
    binary: &mut Vec<u8>,
    sfi_start: usize,
    start: usize,
    end: usize,
    patches: &[(&str, String)],
) -> bool {
    let mut pos = start;
    let mut changed = false;
    while pos + 6 <= end {
        let block_len = read_u16(binary, pos) as usize;
        if block_len < 6 { break; }
        let block_end = pos + block_len;
        if block_end > end { break; }

        let key_nul = find_utf16_nul(binary, pos + 6, block_end).unwrap_or(block_end);
        let entries_start = dword_align_rel(pos, key_nul + 2);
        changed |= walk_entries(binary, pos, entries_start, block_end, patches);

        let next = dword_align_rel(sfi_start, block_end);
        if next <= pos { break; }
        pos = next;
    }
    changed
}

/// Walk String entries inside a StringTable.
fn walk_entries(
    binary: &mut Vec<u8>,
    table_start: usize,
    start: usize,
    end: usize,
    patches: &[(&str, String)],
) -> bool {
    let mut pos = start;
    let mut changed = false;
    while pos + 6 <= end {
        let entry_len = read_u16(binary, pos) as usize;
        if entry_len < 6 { break; }
        let entry_end = pos + entry_len;
        if entry_end > end { break; }

        let val_words = read_u16(binary, pos + 2) as usize; // wValueLength in chars (incl NUL)
        let key_nul = find_utf16_nul(binary, pos + 6, entry_end).unwrap_or(entry_end);
        let key = read_utf16le(binary, pos + 6, key_nul);

        // Value starts after DWORD-align of key+NUL, relative to entry start
        let val_start = dword_align_rel(pos, key_nul + 2);
        let val_slot = val_words * 2; // bytes available for value

        if let Some((_, new_val)) = patches.iter().find(|(k, _)| *k == key) {
            if val_slot >= 2 && val_start + val_slot <= entry_end {
                patch_value(binary, val_start, val_slot, new_val, pos + 2);
                changed = true;
            }
        }

        let next = dword_align_rel(table_start, entry_end);
        if next <= pos { break; }
        pos = next;
    }
    changed
}

/// Write `new_val` as UTF-16LE into `binary[val_start..val_start+slot_bytes]`.
/// Truncates to fit the slot (preserves NUL terminator). Updates wValueLength at `wvl_pos`.
fn patch_value(binary: &mut Vec<u8>, val_start: usize, slot_bytes: usize, new_val: &str, wvl_pos: usize) {
    let end = val_start + slot_bytes;
    if end > binary.len() { return; }
    binary[val_start..end].fill(0);

    let max_chars = slot_bytes / 2; // chars including NUL
    let mut written = 0usize;
    for (i, ch) in new_val.encode_utf16().enumerate() {
        if i + 1 >= max_chars { break; }
        let off = val_start + i * 2;
        binary[off]     = (ch & 0xFF) as u8;
        binary[off + 1] = (ch >> 8)   as u8;
        written += 1;
    }

    // Update wValueLength (chars including NUL)
    let wvl = (written + 1) as u16;
    if wvl_pos + 2 <= binary.len() {
        let le = wvl.to_le_bytes();
        binary[wvl_pos]     = le[0];
        binary[wvl_pos + 1] = le[1];
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn read_u16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() { return 0; }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Find byte offset of UTF-16LE NUL terminator (\x00\x00) on 2-byte boundaries.
fn find_utf16_nul(data: &[u8], start: usize, end: usize) -> Option<usize> {
    let start = (start + 1) & !1; // align to even
    let mut i = start;
    while i + 1 < end {
        if data[i] == 0 && data[i + 1] == 0 { return Some(i); }
        i += 2;
    }
    None
}

/// Decode UTF-16LE bytes `data[start..end]` (NUL not included).
fn read_utf16le(data: &[u8], start: usize, end: usize) -> String {
    if start >= end || end > data.len() { return String::new(); }
    let words: Vec<u16> = data[start..end]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&words).to_string()
}
