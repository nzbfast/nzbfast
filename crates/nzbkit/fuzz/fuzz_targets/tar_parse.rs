#![no_main]
//! Fuzz the tar container parser on arbitrary bytes. A posted `.tar` is
//! untrusted input, and `nzbkit::tar::Reader` is the ONLY entry point
//! that walks it - the in-stream chase (`extract/tar.rs`) and the disk
//! post-pass arm (`rarfix/tar.rs`) both drive it directly with no second
//! copy of the grammar, so this target's coverage is theirs too.
//!
//! Two things are exercised, on the zip target's shape
//! (`zip_parse.rs`): the classification sniff (`looks_like_tar`, which a
//! `.tar`-or-extensionless posted file is routed through before this
//! reader ever sees it), and the header/data walk itself - checksums in
//! both the signed and unsigned form, octal and GNU base-256 sizes, the
//! typeflag table, the `prefix` join, GNU `L`/`K` long-name members and
//! pax `x`/`g` extended headers (including the sparse refusal hidden
//! behind an ordinary file header, `parse_pax`'s byte-vs-char slicing
//! trap noted in its own doc comment).
//!
//! No capped sink is needed the way zip's target needs one: a tar member
//! is stored uncompressed, so its declared size can never exceed the
//! container `Reader` was built with (`total = data.len()`), and
//! `read_meta`'s own `MAX_NAME_BYTES` bounds the one allocation off an
//! attacker-declared length. The read loop below only has to prove it
//! ends, which the forward-only cursor already guarantees by
//! construction (every branch through `next_entry` consumes at least one
//! 512-byte block before it can loop again).
use libfuzzer_sys::fuzz_target;
use std::io;

use nzbkit::tar::{Reader, SNIFF_MIN, looks_like_tar};

fuzz_target!(|data: &[u8]| {
    // Cheap reject: below the sniff's own weak threshold there is no
    // magic to find and nothing downstream would route this input to
    // the reader at all.
    if data.len() < SNIFF_MIN {
        return;
    }
    let _ = looks_like_tar(data);

    let mut r = Reader::new(io::Cursor::new(data), data.len() as u64);
    let mut buf = [0u8; 8192];
    loop {
        match r.next_entry() {
            Ok(Some(_)) => loop {
                match r.read_data(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => return,
                }
            },
            Ok(None) => break,
            Err(_) => return,
        }
    }
    let _ = r.saw_end_marker();
});
