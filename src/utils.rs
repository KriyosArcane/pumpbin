use iced::{
    advanced::graphics::image::image_rs::ImageFormat,
    window::{self, Level, Position},
    Font, Pixels, Settings, Size, Task,
};
use memchr::memmem;
use rand::RngCore;
use rfd::{AsyncMessageDialog, MessageButtons, MessageDialog, MessageDialogResult, MessageLevel};
use std::iter;
use thiserror::Error;

pub const JETBRAINS_MONO_FONT: Font = Font::with_name("JetBrainsMono NF");

pub fn error_dialog(error: anyhow::Error) {
    MessageDialog::new()
        .set_buttons(MessageButtons::Ok)
        .set_description(error.to_string())
        .set_level(MessageLevel::Error)
        .set_title("PumpBin")
        .show();
}

pub fn message_dialog(message: String, level: MessageLevel) -> Task<MessageDialogResult> {
    let dialog = AsyncMessageDialog::new()
        .set_buttons(MessageButtons::Ok)
        .set_description(message)
        .set_level(level)
        .set_title("PumpBin")
        .show();
    Task::future(dialog)
}

pub fn confirm_dialog(message: String, title: String) -> Task<MessageDialogResult> {
    let dialog = AsyncMessageDialog::new()
        .set_buttons(MessageButtons::YesNo)
        .set_description(message)
        .set_level(MessageLevel::Warning)
        .set_title(title)
        .show();
    Task::future(dialog)
}

pub fn settings() -> Settings {
    Settings {
        fonts: vec![include_bytes!("../assets/JetBrainsMonoNerdFont-Regular.ttf").into()],
        default_font: JETBRAINS_MONO_FONT,
        default_text_size: Pixels(13.0),
        antialiasing: true,
        ..Default::default()
    }
}

pub fn window_settings() -> window::Settings {
    let size = Size::new(1200.0, 800.0);

    window::Settings {
        size,
        position: Position::Centered,
        min_size: Some(size),
        visible: true,
        resizable: true,
        decorations: true,
        transparent: false,
        level: Level::Normal,
        icon: window::icon::from_file_data(
            include_bytes!("../logo/icon.png"),
            Some(ImageFormat::Png),
        )
        .ok(),
        exit_on_close_request: true,
        ..Default::default()
    }
}

#[derive(Debug, Error)]
pub enum ReplaceError {
    #[error("Holder '{0}' not found in binary")]
    HolderNotFound(String),
    #[error("Replacement data too long: {0} bytes (max: {1} bytes)")]
    ReplacementTooLong(usize, usize),
}

pub fn replace(
    bin: &mut [u8],
    holder: &[u8],
    replace_by: &[u8],
    max_len: usize,
) -> Result<(), ReplaceError> {
    replace_with_rng(bin, holder, replace_by, max_len, &mut rand::thread_rng())
}

/// Same as [`replace`] but with an explicit RNG. Used by golden-output tests
/// (seed a `ChaCha20Rng`) to make padding deterministic.
pub fn replace_with_rng<R: RngCore>(
    bin: &mut [u8],
    holder: &[u8],
    replace_by: &[u8],
    max_len: usize,
    rng: &mut R,
) -> Result<(), ReplaceError> {
    if replace_by.len() > max_len {
        return Err(ReplaceError::ReplacementTooLong(replace_by.len(), max_len));
    }

    let mut replace_by = replace_by.to_owned();

    let position = memmem::find_iter(bin, holder)
        .next()
        .ok_or_else(|| ReplaceError::HolderNotFound(String::from_utf8_lossy(holder).to_string()))?;

    let mut random: Vec<u8> = iter::repeat_n(b'0', max_len - replace_by.len()).collect();
    rng.fill_bytes(&mut random);
    replace_by.extend_from_slice(random.as_slice());

    bin[position..(position + max_len)].copy_from_slice(replace_by.as_slice());

    Ok(())
}

/// Crash-safe file write. Writes `data` to a sibling temp file in the same
/// directory as `path` and atomically renames over `path` on success. On
/// crash or disk-full mid-write, `path` keeps its previous contents instead
/// of being truncated to a partial file (the pre-1.1.2 `fs::write` behavior).
///
/// The temp file must share `path`'s directory so the final rename is a
/// same-filesystem operation; otherwise atomicity is not guaranteed.
#[tracing::instrument(skip(data), fields(path = %path.display(), len = data.len()))]
pub fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    if !parent.as_os_str().is_empty() {
        std::fs::create_dir_all(parent)?;
    }

    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(data)?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist(path)
        .map_err(|e| std::io::Error::other(e.error))?;
    Ok(())
}

/// Recompute the PE `IMAGE_OPTIONAL_HEADER.CheckSum` field in `bin` if it
/// looks like a valid PE. Returns `true` on rewrite, `false` if the input
/// isn't a PE (silently a no-op on ELF/Mach-O/etc.) or is malformed.
///
/// Algorithm (matches the documented `CheckSumMappedFile` behavior):
///   1. Zero out the 4-byte CheckSum field.
///   2. Walk the file as `u16` little-endian words. Accumulate with
///      end-around carry: `acc = (acc + word) mod 0xFFFF`. The trailing
///      odd byte (if any) is included as a low byte / zero high byte.
///   3. Add the file size as a `u32`.
///   4. Store the resulting `u32` back into the CheckSum field.
///
/// The CheckSum field lives at `e_lfanew + 24 + 64` in both PE32 and
/// PE32+ — IMAGE_OPTIONAL_HEADER and IMAGE_OPTIONAL_HEADER64 share the
/// same layout up through `SizeOfHeaders` (the CheckSum offset).
///
/// Why this matters: PumpBin patches the loader template in-place
/// (writes shellcode + length into the placeholder region) without
/// recomputing CheckSum. Stock Windows tools (`signtool verify`,
/// Defender's static-analysis path, `CertVerifyFileSignature`) read
/// the field and treat any mismatch as tamper evidence — increasing
/// detection rate on otherwise-clean builds and breaking PumpBin's
/// own `verify` subcommand which reports `PE checksum mismatch`.
pub fn recompute_pe_checksum(bin: &mut [u8]) -> bool {
    // PE prerequisites: at least 64 bytes, "MZ" magic, valid e_lfanew
    // pointing at "PE\0\0" with room for the optional header.
    if bin.len() < 64 || &bin[0..2] != b"MZ" {
        return false;
    }
    let e_lfanew = u32::from_le_bytes(bin[0x3C..0x40].try_into().unwrap()) as usize;
    if e_lfanew + 24 + 64 + 4 > bin.len() {
        return false;
    }
    if &bin[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return false;
    }
    let checksum_off = e_lfanew + 24 + 64;

    // Zero the existing CheckSum field before summing.
    bin[checksum_off..checksum_off + 4].fill(0);

    // Sum u16 LE words with end-around carry. The standard idiom is
    //   sum = (sum + word) mod 0xFFFF
    // which is equivalent to "add with carry into bit-16 folded back."
    let mut sum: u32 = 0;
    let chunks = bin.chunks_exact(2);
    let remainder = chunks.remainder();
    for w in chunks {
        let word = u16::from_le_bytes([w[0], w[1]]) as u32;
        sum = sum.wrapping_add(word);
        // Fold any carry out of the low 16 bits back in. Doing this each
        // iteration matches the kernel32 CheckSumMappedFile reference.
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if let Some(&last) = remainder.first() {
        sum = sum.wrapping_add(last as u32);
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    let checksum = sum.wrapping_add(bin.len() as u32);

    bin[checksum_off..checksum_off + 4].copy_from_slice(&checksum.to_le_bytes());
    true
}

pub fn random_id_lowercase(len: usize) -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    (0..len)
        .map(|_| {
            let idx = (rng.next_u32() as usize) % chars.len();
            chars[idx]
        })
        .collect()
}
