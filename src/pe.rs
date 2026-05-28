//! PE patching primitives. Lifted out of the (now-deleted)
//! `host_helpers/pe.rs` so the native `pe-version-info` post-build
//! module can use them without any Extism dependency.
//!
//! Contents:
//! - [`patch_version_info`] — rewrite VS_VERSION_INFO StringFileInfo
//!   entries in place. Byte-for-byte equivalent to the v1.5.0 host
//!   helper (this is the same walker, just relocated).

/// All wLength fields are in bytes, all DWORD alignment is RELATIVE to
/// the start of the containing block (not the absolute file offset).
///
///   Root block @ root_start:
///     [u16 wLength][u16 wValueLength][u16 wType=0]
///     UTF-16LE "VS_VERSION_INFO\0"
///     DWORD pad (rel to root_start)
///     VS_FIXEDFILEINFO (wValueLength bytes, always 52)
///     DWORD pad (rel to root_start)
///     Children: StringFileInfo, VarFileInfo...
pub fn patch_version_info(binary: &mut [u8], patches: &[(&str, String)]) -> bool {
    try_patch(binary, patches).unwrap_or(false)
}

fn dword_align_rel(base: usize, offset: usize) -> usize {
    let rel = offset - base;
    let rel_aligned = rel.div_ceil(4) * 4;
    base + rel_aligned
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
