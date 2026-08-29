#![no_main]
//! Fuzz the RAR volume-head naming probe (TODO 131 rung 5). Sibling of
//! `sevenz_name_probe`, and the same threat model: the bytes are one
//! decoded article fetched off usenet from an anonymous poster, so the
//! signature, every header field, and every inner filename are
//! attacker-chosen.
//!
//! `rar_map` already hammers `VolumeMapper`'s offset arithmetic - the
//! parser where a bad bound becomes a `pwrite`. What is new here is the
//! layer ABOVE it, which that target never reaches:
//!
//! 1. `rar_head`'s blocker/version mapping. An `EncryptedHeader` verdict
//!    now writes a TERMINAL classification (index/encrypted.rs), so a
//!    volume that can talk this function into that answer retires the
//!    release from byte probing. Panicking here would be bad; answering
//!    "encrypted" for bytes that are not is worse, and the assertion
//!    below pins the one direction that cannot be argued after the fact.
//! 2. `pick_rar_media_name`'s sanitising of an inner filename into a
//!    title and a content key - path components, control characters,
//!    the length cap, and the rule that a placeholder size never
//!    becomes a key.
//!
//! Two feed shapes, because a probe holds ONE article: the whole input
//! as a head (the live shape), and a truncated prefix (the short-article
//! and torn-header shapes, where the parser must decline rather than
//! read past what it holds).
use libfuzzer_sys::fuzz_target;

use nzbkit::nameprobe::{pick_rar_media_name, rar_head, ProbeError};

fuzz_target!(|data: &[u8]| {
    // One article's worth is the live bound; bigger inputs exercise
    // nothing real and only measure RAM.
    if data.is_empty() || data.len() > 1 << 20 {
        return;
    }
    for head in [data, &data[..data.len() / 2]] {
        if head.is_empty() {
            continue;
        }
        // Both volume-size configurations: the declared length switches
        // the mapper's EOF rule on, and 0 ("unknown") switches it off,
        // which is the weaker of the two.
        for declared in [head.len() as u64, 0] {
            match rar_head(head, declared) {
                Ok(h) => {
                    // A parsed head must not ALSO be the encrypted
                    // verdict - the terminal classification keys off
                    // that error alone, and a head that both names a
                    // file and claims to be locked would let one
                    // hostile volume retire a nameable release.
                    if let Some((name, key)) = pick_rar_media_name(&h) {
                        assert!(!name.is_empty(), "an empty title escaped the gate");
                        assert!(name.chars().count() <= 255, "title over the cap");
                        assert!(
                            !name.contains('/') && !name.contains('\\'),
                            "a path component reached the title: {name:?}"
                        );
                        assert!(
                            !name.chars().any(char::is_control),
                            "a control character reached the title"
                        );
                        // The key is a corroborating content key. A
                        // constant one would make every keyless RAR in
                        // the index confirm every other, so the only
                        // legal answers are a real size (with or
                        // without a CRC) or nothing at all.
                        if let Some(k) = key {
                            assert!(
                                !k.starts_with('0'),
                                "a placeholder size became a key: {k:?}"
                            );
                        }
                    }
                }
                // Every error is a legal answer; the point is that the
                // canary stays distinguishable from parse noise, which
                // is what the caller branches on.
                Err(ProbeError::EncryptedHeader) => {}
                Err(_) => {}
            }
        }
    }
});
