//! Integration test for the `cert-graft` post-build module.
//!
//! Synthesizes two minimal PE64 binaries in memory — a "target" implant
//! and a "donor" with a fake WIN_CERTIFICATE blob — writes them to temp
//! files, runs the cert-graft module, and verifies the target PE now
//! carries the donor's certificate blob with a correct security
//! directory entry.

use pumpbin::modules::post_build::cert_graft::CertGraft;
use pumpbin::modules::PostBuildModule;

// ── PE64 construction helpers ──────────────────────────────────────

/// Standard e_lfanew offset (skip the 128-byte DOS stub area).
const E_LFANEW: usize = 0x80;

/// Build a minimal PE64 skeleton:
///   DOS header (128 bytes) + PE\0\0 (4) + COFF FileHeader (20)
///   + OptionalHeader64 (240 bytes: 112 fixed + 16 data dirs * 8)
///   + optional extra payload bytes.
///
/// The optional header's `NumberOfRvaAndSizes` is set to 16 so all
/// standard data directory slots exist. The security directory
/// (index 4) starts zeroed (no embedded signature).
fn minimal_pe64(extra_payload: usize) -> Vec<u8> {
    let opt_hdr_off = E_LFANEW + 4 + 20; // offset of optional header
    let opt_hdr_size: usize = 240; // 112 fixed + 128 data dirs
    let header_end = opt_hdr_off + opt_hdr_size;
    let mut pe = vec![0u8; header_end + extra_payload];

    // DOS header
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3C..0x40].copy_from_slice(&(E_LFANEW as u32).to_le_bytes());

    // PE signature
    pe[E_LFANEW..E_LFANEW + 4].copy_from_slice(b"PE\0\0");

    // COFF FileHeader: SizeOfOptionalHeader at offset 16 within the
    // file header (e_lfanew + 4 + 16).
    let size_opt_hdr_off = E_LFANEW + 4 + 16;
    pe[size_opt_hdr_off..size_opt_hdr_off + 2]
        .copy_from_slice(&(opt_hdr_size as u16).to_le_bytes());

    // Optional header — PE64 magic
    pe[opt_hdr_off] = 0x0b;
    pe[opt_hdr_off + 1] = 0x02; // 0x020b = PE32+ (PE64)

    // NumberOfRvaAndSizes at fixed offset 108 within the optional header
    let num_rva_off = opt_hdr_off + 108;
    pe[num_rva_off..num_rva_off + 4].copy_from_slice(&16u32.to_le_bytes());

    // Sprinkle identifiable junk in the payload area so we can detect
    // the original content after grafting.
    for (i, b) in pe[header_end..].iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x37).wrapping_add(0xAA);
    }

    pe
}

/// Build a donor PE64 with a fake Authenticode (WIN_CERTIFICATE)
/// blob appended after the headers. The security data directory
/// entry (index 4) points at the blob.
fn donor_pe64_with_cert(cert_blob: &[u8]) -> Vec<u8> {
    let mut pe = minimal_pe64(64); // some body bytes

    // 8-byte align before appending the cert blob
    while pe.len() % 8 != 0 {
        pe.push(0);
    }
    let blob_offset = pe.len() as u32;
    let blob_size = cert_blob.len() as u32;
    pe.extend_from_slice(cert_blob);

    // Patch the security data directory entry (index 4)
    let opt_hdr_off = E_LFANEW + 4 + 20;
    // For PE64 (0x20b): data directories start at opt_hdr_off + 112
    let data_dir_off = opt_hdr_off + 112;
    let sec_dir_off = data_dir_off + 4 * 8; // index 4, 8 bytes each
    pe[sec_dir_off..sec_dir_off + 4].copy_from_slice(&blob_offset.to_le_bytes());
    pe[sec_dir_off + 4..sec_dir_off + 8].copy_from_slice(&blob_size.to_le_bytes());

    pe
}

// ── Helpers ────────────────────────────────────────────────────────

fn make_valid_win_certificate(total_len: usize) -> Vec<u8> {
    let data_len = total_len.saturating_sub(8);
    let mut v = Vec::new();
    v.extend_from_slice(&(total_len as u32).to_le_bytes());
    v.extend_from_slice(&0x0200u16.to_le_bytes());
    v.extend_from_slice(&0x0002u16.to_le_bytes());
    v.extend(std::iter::repeat_n(0xCCu8, data_len));
    v
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn read_security_dir_entry(pe: &[u8]) -> (u32, u32) {
    let opt_hdr_off = E_LFANEW + 4 + 20;
    let data_dir_off = opt_hdr_off + 112;
    let sec_dir_off = data_dir_off + 4 * 8;
    (read_u32(pe, sec_dir_off), read_u32(pe, sec_dir_off + 4))
}

// ── Tests ──────────────────────────────────────────────────────────

#[test]
fn cert_graft_transfers_donor_blob_to_target() {
    // A recognizable fake WIN_CERTIFICATE blob.
    let fake_cert: Vec<u8> = {
        let mut v = Vec::new();
        // WIN_CERTIFICATE: dwLength(4) + wRevision(2) + wCertificateType(2) + bCertificate(...)
        let cert_data = b"FAKE_AUTHENTICODE_CERTIFICATE_BLOB_FOR_TESTING_1234567890";
        let total_len = 8 + cert_data.len();
        v.extend_from_slice(&(total_len as u32).to_le_bytes()); // dwLength
        v.extend_from_slice(&0x0200u16.to_le_bytes()); // wRevision = WIN_CERT_REVISION_2_0
        v.extend_from_slice(&0x0002u16.to_le_bytes()); // wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA
        v.extend_from_slice(cert_data);
        v
    };

    let donor = donor_pe64_with_cert(&fake_cert);
    let mut target = minimal_pe64(256);

    // Sanity: target starts with no security directory.
    let (va, sz) = read_security_dir_entry(&target);
    assert_eq!(va, 0, "target should start with zero security VA");
    assert_eq!(sz, 0, "target should start with zero security size");

    // Sanity: donor has the cert blob.
    let (d_va, d_sz) = read_security_dir_entry(&donor);
    assert_ne!(d_va, 0, "donor must have a nonzero security VA");
    assert_eq!(d_sz as usize, fake_cert.len());

    // Write donor to a temp file (cert-graft reads it from disk).
    let dir = tempfile::tempdir().unwrap();
    let donor_path = dir.path().join("donor.exe");
    std::fs::write(&donor_path, &donor).unwrap();

    let target_len_before = target.len();

    // Run cert-graft.
    let graft = CertGraft;
    let args = vec![format!("donor={}", donor_path.display())];
    graft.apply(&args, &mut target).expect("cert-graft failed");

    // Target should now be longer (cert blob appended).
    assert!(
        target.len() > target_len_before,
        "target size should increase after grafting"
    );

    // Security directory entry should point at the appended blob.
    let (new_va, new_sz) = read_security_dir_entry(&target);
    assert_ne!(new_va, 0, "security VA must be set after grafting");
    assert_eq!(
        new_sz as usize,
        fake_cert.len(),
        "security size must equal the donor blob length"
    );

    // The blob offset must be 8-byte aligned.
    assert_eq!(
        new_va % 8,
        0,
        "WIN_CERTIFICATE offset must be 8-byte aligned"
    );

    // Extract the grafted blob from the target and compare to the original.
    let start = new_va as usize;
    let end = start + new_sz as usize;
    assert!(end <= target.len(), "grafted blob past EOF");
    let grafted_blob = &target[start..end];
    assert_eq!(
        grafted_blob, &fake_cert,
        "grafted blob must match the donor's cert blob byte-for-byte"
    );
}

#[test]
fn cert_graft_rejects_unsigned_donor() {
    // Donor with no security directory (all zeros).
    let donor = minimal_pe64(64);
    let mut target = minimal_pe64(128);

    let dir = tempfile::tempdir().unwrap();
    let donor_path = dir.path().join("unsigned.exe");
    std::fs::write(&donor_path, &donor).unwrap();

    let graft = CertGraft;
    let args = vec![format!("donor={}", donor_path.display())];
    let err = graft.apply(&args, &mut target).unwrap_err();
    assert!(
        err.to_string().contains("no embedded Authenticode"),
        "expected 'no embedded Authenticode' error, got: {err}"
    );
}

#[test]
fn cert_graft_rejects_non_pe_target() {
    // Target is an ELF (not a PE).
    let mut target = vec![0x7F, b'E', b'L', b'F'];
    target.extend(std::iter::repeat_n(0u8, 256));

    let fake_cert = make_valid_win_certificate(64);
    let donor = donor_pe64_with_cert(&fake_cert);

    let dir = tempfile::tempdir().unwrap();
    let donor_path = dir.path().join("donor.exe");
    std::fs::write(&donor_path, &donor).unwrap();

    let graft = CertGraft;
    let args = vec![format!("donor={}", donor_path.display())];
    let err = graft.apply(&args, &mut target).unwrap_err();
    assert!(
        err.to_string().contains("not a PE"),
        "expected 'not a PE' error, got: {err}"
    );
}
