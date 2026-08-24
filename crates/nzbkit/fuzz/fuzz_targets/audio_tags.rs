#![no_main]
//! Fuzz the audio tag reader (issue #55). Every byte it parses is a
//! filename an anonymous poster chose, and the value it returns is put
//! on a file, so both the walk and the strings it yields are attacker
//! controlled. Two surfaces are driven:
//!
//! 1. The natural path: the input as a whole file. Almost everything
//!    rejects at the magic gate, which is kept because that gate IS the
//!    first piece of armor.
//! 2. The deep path: the input wearing each supported magic, so the
//!    fuzzer reaches the metadata walks - block lengths, frame sizes,
//!    box sizes and the comment grammar - instead of being turned away
//!    at the door.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // The reader caps its own head read at HEAD_MAX; bigger inputs
    // exercise nothing further and only measure RAM.
    if data.len() > nzbkit::audiotag::HEAD_MAX {
        return;
    }
    let _ = nzbkit::audiotag::sniff_ext(data);
    let _ = nzbkit::audiotag::probe(&mut Cursor::new(data.to_vec()));

    for magic in [
        &b"fLaC"[..],
        // An Ogg page header is not checked, so the comment marker is
        // what has to be worn.
        &b"OggS\0\x02OpusHead\0OpusTags"[..],
        &b"ID3\x03\0\0\0\0\0\0"[..],
        &b"\0\0\0\x08ftypM4A "[..],
    ] {
        let mut v = magic.to_vec();
        v.extend_from_slice(data);
        let _ = nzbkit::audiotag::sniff_ext(&v);
        let _ = nzbkit::audiotag::probe(&mut Cursor::new(v));
    }
});
