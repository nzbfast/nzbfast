#![no_main]
//! Fuzz the RAR volume HEADER MAPPER on arbitrary bytes.
//!
//! `VolumeMapper` is the first thing every downloaded RAR volume touches,
//! and it is fed article spans in ARBITRARY ORDER while the download is
//! still in flight. Every offset it produces - a piece's `data_off`, its
//! `data_len`, the parse cursor's next stop - is arithmetic over
//! attacker-declared header fields, and the extractor turns those straight
//! into `pwrite` destinations. So this is the parser where a bad bound
//! becomes a write, not just a bad read.
//!
//! It is also where the anti-DoS bounds live, and those are the ones a
//! unit test cannot really pin: the cursor MUST strictly advance (a block
//! declaring `data_len = 2^64 - 40` once wrapped it back onto itself and
//! spun forever, growing the entry list at line rate), a declared data
//! area must not run past the volume, and the RAR4 name decoder must not
//! amplify a 38-byte field into kilobytes of `String`. We hunt panics,
//! non-termination and unbounded growth.
//!
//! Read the volume bound in that list as the MAPPER's, because it is one:
//! `VolumeMapper::advance_to` owns it and half 1 below is the only half
//! that can ask for it. Halves 2 and 3 sit one layer under the mapper, on
//! the block parser, which deliberately bounds a header's own frame and
//! nothing else - half 2 asserted otherwise until 11 Sep 2026, and the
//! long note at that assertion is where the split is written out.
//!
//! Two halves, because their costs differ by five orders of magnitude:
//!
//! 1. The mapper itself, fed in shuffled chunks with no password. Full
//!    speed - no key schedule runs on this path by construction (see
//!    `entry_blocker`, which deliberately refuses to derive for RAR4).
//! 2. The RAR4 `-hp` header framing, driven through
//!    `fuzz_v4_encrypted_header` with one throwaway key. Going through the
//!    mapper instead would run 0x40000 SHA-1 rounds per input (~20
//!    execs/s) and fuzz the KDF, which is fixed-size arithmetic already
//!    pinned by known-answer tests. The interesting bytes are the
//!    DECRYPTED length fields, and this reaches them at full speed.
//! 3. The RAR4 PLAINTEXT header framing, through `fuzz_v4_plain_header`.
//!    Since the M5 fix (review sweep 10 Aug) the mapper refuses a
//!    plaintext block whose CRC16 misses, which random bytes clear one
//!    time in 65,536 - so half 1 alone would leave the arithmetic BEHIND
//!    that gate essentially unfuzzed. Same split, same reason, as half 2:
//!    the check is cheap fixed-size work, the fields it guards are the
//!    ones that become `pwrite` destinations.
use libfuzzer_sys::fuzz_target;

use nzbkit::rar::{ArchiveMap, VolumeMapper};

/// Entries retained per volume, as bounded by the mapper's own cap. A
/// volume that produces more than this has defeated `MAX_ENTRIES`.
const ENTRY_CEILING: usize = 100_000;

fuzz_target!(|data: &[u8]| {
    // The mapper is linear in the input; the point is malformed structure,
    // not size.
    if data.len() < 2 || data.len() > 1 << 20 {
        return;
    }
    // Byte 0 picks the feed shape, so one corpus exercises both the
    // all-at-once parse and the incremental one where headers straddle
    // span boundaries (the case that made the window and the hold list
    // necessary in the first place).
    let mode = data[0];
    let body = &data[1..];

    // Chunk sizes that are NOT header-aligned: a header split across two
    // spans has to survive being stashed and re-parsed.
    let chunk = match mode & 0x03 {
        0 => body.len().max(1),
        1 => 7,
        2 => 61,
        _ => 1024,
    };
    // Sometimes lie about the volume size: 0 means "unknown" (a yEnc span
    // with no `size=`), which switches OFF the volume-bounds check and is
    // the weaker of the two configurations.
    let declared = if mode & 0x04 != 0 {
        0
    } else {
        body.len() as u64
    };
    let password = (mode & 0x08 != 0).then_some("testpw123");

    let mut m = VolumeMapper::with_password(declared, password.map(std::sync::Arc::from));
    let mut offsets: Vec<usize> = (0..body.len()).step_by(chunk).collect();
    if mode & 0x10 != 0 {
        offsets.reverse(); // out-of-order arrival, the normal case in flight
    }
    for off in offsets {
        let end = (off + chunk).min(body.len());
        m.feed(off as u64, &body[off..end]);
    }

    // Whatever it decided, the results have to be self-consistent: the
    // extractor allocates and pwrites from exactly these numbers.
    assert!(m.entries.len() <= ENTRY_CEILING, "entry cap defeated");
    let mut prev_end = 0u64;
    for e in &m.entries {
        // Data areas come off a forward-only cursor, so they are ordered
        // and disjoint - `map_span_into` relies on it to binary-search
        // instead of scanning, and overlapping areas would route one
        // article's bytes to two destinations.
        assert!(e.data_off >= prev_end, "data areas overlap or go backwards");
        prev_end = e.data_off.checked_add(e.data_len).expect("data area wraps");
        // A mapped volume promises its pieces are really in the volume.
        // (An UNMAPPED one may hold a diagnostic entry recorded alongside
        // the blocker, which nothing reads offsets from.)
        if m.blocker.is_none() && declared > 0 {
            assert!(prev_end <= declared, "piece runs past the volume");
        }
        // An encrypted entry that stayed mappable is one the extractor
        // will assemble ciphertext for and decrypt at finish, so it MUST
        // carry parameters to decrypt with.
        if m.blocker.is_none() && e.encrypted {
            assert!(
                e.crypt.is_some(),
                "mappable encrypted entry with no key material"
            );
        }
    }
    // `mapped_through` gates the hold list: bytes past it are retained in
    // memory, so it must never sit below a piece the mapper claims to have
    // parsed or those bytes are dropped on the floor.
    if !m.entries.is_empty() && m.blocker.is_none() {
        assert!(m.mapped_through() >= prev_end || m.mapped_through() == u64::MAX);
    }
    // A password must never CHANGE a volume that needs none. Holding a key
    // for some other archive in the job is the normal case - most sets in
    // a passworded NZB are plain - so a plaintext volume has to parse
    // identically either way. Only worth asking when the passwordless read
    // succeeded outright; a blocked one legitimately parses further once a
    // key unlocks it, which is the whole point.
    if password.is_some() {
        let mut plain = VolumeMapper::new(declared);
        plain.feed(0, body);
        if plain.blocker.is_none() && plain.complete {
            let mut keyed =
                VolumeMapper::with_password(declared, password.map(std::sync::Arc::from));
            keyed.feed(0, body);
            assert!(
                keyed.blocker.is_none(),
                "a password blocked a plaintext volume"
            );
            assert_eq!(
                keyed.entries.len(),
                plain.entries.len(),
                "a password changed a plaintext volume's entry count"
            );
            for (a, b) in keyed.entries.iter().zip(&plain.entries) {
                assert_eq!((a.data_off, a.data_len), (b.data_off, b.data_len));
                assert_eq!(a.name, b.name);
            }
        }
    }

    // Base resolution across a multi-volume set: the same volume repeated
    // is a degenerate but legal set, and it exercises the propagation that
    // derives a continuation's inner-file offset from its neighbour.
    let map = ArchiveMap::resolve(&[&m, &m]);
    for (&(vol, ei), &base) in &map.bases {
        assert!(vol < 2);
        let e = &m.entries[ei];
        // A base plus its piece length is where the extractor writes; it
        // must not wrap into a low offset.
        assert!(
            base.checked_add(e.data_len).is_some(),
            "inner-file offset wraps"
        );
    }

    // Half 2: the RAR4 `-hp` framing, past the key schedule. The key is a
    // throwaway - what is under test is the length arithmetic over the
    // bytes it decrypts to, not the schedule that produced it.
    let enc_base = u64::from(mode) * 16;
    let (next, blocked) =
        nzbkit::rar::fuzz_v4_encrypted_header(body, enc_base, [0x5a; 16], [0xa5; 16], declared);
    if let Some(next) = next {
        // The mapper refuses any block that does not strictly advance, and
        // this is the value it checks. A header claiming to end at or
        // before its own start is the shape that spun the parse loop.
        assert!(next > enc_base, "encrypted header does not advance");
        // NO volume bound is asserted here, and that is a CORRECTION
        // rather than an omission: this half used to assert
        // `next <= declared` and it was WRONG, in the way a fuzz
        // assertion is worst - it described a layer that is not on this
        // path. CI found it on 11 Sep 2026 (fuzz-smoke run 34564492152,
        // sha a6ed0da5, artifact
        // `crash-f23952f19b3ae77b1b576164f2d99592f840188a`, reduced to 25
        // bytes in `seeds/rar_map/`): a 0x7a block with LONG_BLOCK set,
        // whose HEADER fits the volume and whose declared data area is
        // 16 MiB past the end of it.
        //
        // Which is a shape the library handles correctly, one layer up.
        // `parse_block_v4_enc_with` takes `volume_size` for ONE purpose -
        // its plausibility gate bounds the header FRAME (salt + AES
        // padding) so a wrong password's random `hsize` cannot park the
        // parser in `NeedMore` for bytes the volume does not contain. The
        // DATA-AREA bound is `VolumeMapper::advance_to`'s, deliberately:
        // every `next` in the mapper's block loop goes through it, and it
        // refuses this exact shape with `Corrupt("data area exceeds
        // volume")` through `fail_volume_bound`, which names both terms
        // for TODO 118 item 2. That rule cannot move down here - the
        // encrypted parse's only two refusals are `Corrupt` and
        // `BadPassword`, so it would either call a CORRECT password wrong
        // or lose the diagnostic, and it would be a second copy of a rule
        // that has one home. Half 1 above is where the volume bound is
        // asked, and note how it is GATED: `m.blocker.is_none()`, i.e.
        // "only when the mapper ACCEPTED the volume". This half has no
        // such gate available, because the thing that accepts or refuses
        // is not on its path - which is the whole reason the assertion
        // was unanswerable here. The plaintext twin in half 3 never made
        // the claim. The mapper's side is pinned by an ordinary test,
        // `an_understated_volume_declaration_refuses_every_volume_of_a_healthy_set`.
        //
        // What IS this layer's to promise, and is asserted instead:
        // `volume_size` is a GATE and never arithmetic. A sized parse may
        // REFUSE what an unsized one accepts (its gate is strictly
        // stronger - the third conjunct of `plausible` is vacuous at 0),
        // but when it accepts it must land on the SAME cursor. That
        // catches the tempting wrong fix for this very crash - clamping
        // `next` to `volume_size`, which would silently shorten a
        // declared data area and hand the extractor a piece whose length
        // no header ever declared - and it catches a `volume_size` that
        // ever starts widening what the parser will take.
        if declared > 0 {
            let (unsized_next, _) =
                nzbkit::rar::fuzz_v4_encrypted_header(body, enc_base, [0x5a; 16], [0xa5; 16], 0);
            assert_eq!(
                unsized_next,
                Some(next),
                "a volume size changed the cursor instead of only gating it"
            );
        }
    } else {
        let _ = blocked;
    }

    // Half 3: the PLAINTEXT v4 framing, past the header CRC gate. Same
    // cursor contract - a block that does not strictly advance is the
    // shape that spun the parse loop, and `next` is the value the
    // mapper's own bounds are all derived from.
    let base = u64::from(mode) * 16;
    let (next, blocked) = nzbkit::rar::fuzz_v4_plain_header(body, base);
    if let Some(next) = next {
        assert!(next > base, "plaintext header does not advance");
    } else {
        let _ = blocked;
    }
});
