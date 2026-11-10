#![no_main]
//! Fuzz the 7z disk-side declared-size gate (bug-sweep H1+H2, 14 Aug
//! 2026). The gate reads a whole on-disk container's declarations
//! before sevenz-rust2 is allowed to allocate on them: start-header
//! geometry (including the zeroed shape that would otherwise reach the
//! library's end-header recovery scan), the packed-header caps, an
//! in-process decode of LZMA/LZMA2-packed headers, and the CONTENT
//! blocks' dictionary/PPMd declarations judged against the packed
//! bytes actually present. Everything here is attacker-chosen bytes,
//! and the gate itself must stay cheap: its own worst-case allocation
//! is a 2 MiB window plus a 2 MiB packed-header decode, so run this
//! with a low `-malloc_limit_mb` and any big allocation is a finding.
//!
//! The same two inputs also drive `sevenz_encrypted_header` (TODO 358
//! item 9), the in-stream password probe's locator for a `-mhe`
//! container's encrypted header: it reuses the gate's scanner, plus the
//! one field it added (the header AES coder's property bytes), so it is
//! held to the same bounds - one 32-byte read, one window, no decode.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Bound the input like the sibling probe target: the end header is
    // capped at SEVENZ_END_MAX before any buffering, so bigger inputs
    // exercise nothing real and only measure RAM.
    if data.is_empty() || data.len() > 1 << 20 {
        return;
    }
    // Raw bytes as a container: covers the magic/CRC gates and the
    // zeroed-start refusal.
    let mut f = std::io::Cursor::new(data);
    let _ = nzbkit::nameprobe::sevenz_disk_declared_bomb(&mut f);
    let _ = nzbkit::nameprobe::sevenz_encrypted_header(&mut f);
    // Sealed: the input as the end header of a well-formed container,
    // so the fuzzer reaches the header scan and the packed-header
    // decode instead of being stopped at the checksum door. The window
    // doubles as the pack area (header_off 0), so declared pack
    // streams resolve to real bytes.
    let mut file = Vec::with_capacity(64 + data.len());
    file.extend_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04]);
    file.extend_from_slice(&[0u8; 24]);
    file.extend_from_slice(data);
    file[12..20].copy_from_slice(&0u64.to_le_bytes()); // header_off
    file[20..28].copy_from_slice(&(data.len() as u64).to_le_bytes()); // header_size
    file[28..32].copy_from_slice(&crc32fast::hash(data).to_le_bytes());
    let crc = crc32fast::hash(&file[12..32]);
    file[8..12].copy_from_slice(&crc.to_le_bytes());
    let mut f = std::io::Cursor::new(file);
    let _ = nzbkit::nameprobe::sevenz_disk_declared_bomb(&mut f);
    if let Some(hc) = nzbkit::nameprobe::sevenz_encrypted_header(&mut f) {
        // What the probe then trusts: a pack range bounded like a header.
        assert!(hc.pack_len > 0 && hc.pack_len <= nzbkit::nameprobe::SEVENZ_END_MAX);
        assert!(hc.pack_off >= 32);
        assert!(!hc.aes_props.is_empty());
    }
});
