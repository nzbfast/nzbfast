//! Tests for the encrypted-stream extraction path, moved out of crypto.rs
//! bodily (TODO 106).
//!
//! Attached with `#[path]` from crypto.rs so `super::*` still names the
//! crypto module's private internals - the same shape serve/ uses for its
//! `*_tests.rs` siblings.

use super::*;
use crate::rar::fixtures;

use crate::extract::testutil::*;

#[test]
fn encrypted_single_volume_decrypts_in_stream() {
    let dir = tmpdir("enc-single");
    // Non-16-aligned length exercises the end-padding truncate.
    let plain = payload(200_003, 41);
    let f = fixtures::encrypt_file("hunter2", &plain, 5);
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
    assert_eq!(rep.extracted, vec![("movie.mkv".to_string(), 200_003)]);
    let out = std::fs::read(dir.join("movie.mkv")).unwrap();
    assert_eq!(out.len(), plain.len(), "padding must be truncated");
    assert_eq!(out, plain);
    assert!(!dir.join("v.rar").exists(), "one-pass: no volume on disk");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Codex sweep 13 Aug C1, half one: an encrypted span routed WITHOUT
/// CryptoState commits its output to the ciphertext route AT ENQUEUE,
/// under the routing lock. The physical pwrites run after the lock
/// drops, so `written()` lags the commitment - the latch is what a
/// concurrent router consults in that window.
///
/// The `rar a -htb` shape takes that route: a BLAKE2sp digest with no
/// CRC32 beside it, which nothing in this build can adjudicate, so the
/// gate refuses to decrypt it in-stream and the group demotes at finish
/// to the disk path that can. A check-less RAR5 entry stood here until
/// TODO 27 phase 3 - it now decrypts in-stream like any other.
#[test]
fn a_ciphertext_route_is_latched_at_enqueue_not_at_write_time() {
    let plain = payload(120_000, 75);
    let mut f = fixtures::encrypt_file("right", &plain, 47);
    f.with_hash = true;
    f.with_crc = false;
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let dir = tmpdir("c1-latch");
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("right");
    feed(&ex, 0, "v.rar", &vol, 7000, 75);
    {
        let inner = ex.inner.lock_ok();
        assert!(
            inner.ciphertext_files.contains("movie.mkv"),
            "the route was committed at enqueue and must be latched there"
        );
        // A zero-written view of the same output name: what a concurrent
        // router sees while the first span's pwrite is still in flight.
        // The counter half of rule 2 is blind here; the latch refuses.
        let scratch = dir.join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        let w = crate::disk::FileWriter::create(&scratch.join("movie.mkv"), 4096).unwrap();
        assert_eq!(w.written(), 0);
        assert!(
            !Extractor::instream_decrypt_allowed(&inner, 0, 0, &w),
            "an output owed ciphertext must never latch plaintext-once"
        );
    }
    // One route for the whole file, and it ends in a demote: the volume
    // materializes byte-exact for the disk path, and no unadjudicated
    // plaintext is ever published.
    let rep = ex.finish().unwrap();
    assert!(!rep.fallbacks.is_empty(), "the digest set must demote");
    assert!(rep.decrypted.is_empty(), "{:?}", rep.decrypted);
    assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Codex sweep 13 Aug C1, half two: the gate CONSULTS the latch. This
/// set satisfies every plaintext-once condition (stored check, right
/// password, zero bytes written) - the exact state a second span sees
/// mid-window - and the pre-latched route must still refuse it, or the
/// output mixes raw ciphertext with decrypted plaintext. Refusing costs
/// the set its one-pass ending since TODO 27 phase 3 (nothing decrypts
/// ciphertext at finish any more), which is the conservative half of
/// the trade and the reason the latch is only ever set deliberately.
#[test]
fn a_latched_ciphertext_output_refuses_plaintext_once() {
    let plain = payload(120_000, 76);
    let mut f = fixtures::encrypt_file("right", &plain, 48);
    f.with_crc = true;
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let dir = tmpdir("c1-consult");
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("right");
    // The committed-but-unwritten ciphertext span, as the routing lock
    // records it: only the latch, no bytes on disk yet.
    ex.inner
        .lock_ok()
        .ciphertext_files
        .insert("movie.mkv".to_string());
    feed(&ex, 0, "v.rar", &vol, 7000, 76);
    {
        let inner = ex.inner.lock_ok();
        assert!(
            !inner.crypto_files.contains_key("movie.mkv"),
            "plaintext-once latched over an output owed ciphertext"
        );
    }
    // The whole file stays ciphertext, so finish demotes it - one
    // route, and a volume the disk path can still unpack byte-exactly.
    let rep = ex.finish().unwrap();
    assert!(
        !rep.fallbacks.is_empty(),
        "a latched ciphertext set demotes"
    );
    assert!(rep.decrypted.is_empty(), "{:?}", rep.decrypted);
    assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Finding 8: an encrypted RAR5 STORE entry with a plain (non-tweaked)
/// stored CRC must have its DECRYPTED plaintext verified. The password
/// check proves the key, not that every ciphertext block survived the
/// wire, so damaged ciphertext (the outer PAR2 vouches for the archive
/// as-posted) would otherwise decrypt to corrupt plaintext and report
/// success. With the CRC present, pristine ciphertext succeeds and a
/// single flipped ciphertext byte fails the extraction loudly.
#[test]
fn encrypted_store_verifies_plaintext_crc() {
    let plain = payload(200_003, 47);
    // Pristine: with_crc set, tweaked clear -> plaintext CRC is checked
    // and matches, so extraction succeeds.
    let mut f = fixtures::encrypt_file("hunter2", &plain, 6);
    f.with_crc = true;
    f.tweaked = false;
    let dir = tmpdir("enc-crc-ok");
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 7);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();

    // Damaged ciphertext, correct password: decryption yields corrupt
    // plaintext whose CRC no longer matches -> hard failure, no clean
    // output. (Before finding 8's fix this returned Ok with corrupt
    // movie.mkv.)
    let mut fbad = fixtures::encrypt_file("hunter2", &plain, 6);
    fbad.with_crc = true;
    fbad.tweaked = false;
    fbad.cipher[80_000] ^= 0x5A;
    let dir = tmpdir("enc-crc-bad");
    let vol = fixtures::rar5_volume_enc(
        &[("movie.mkv", &fbad, 0..fbad.cipher.len(), false, false)],
        None,
    );
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 8);
    let res = ex.finish();
    assert!(res.is_err(), "damaged encrypted plaintext must not succeed");
    let out = dir.join("movie.mkv");
    assert!(
        !out.exists() || std::fs::read(&out).unwrap() != plain,
        "corrupt plaintext must not masquerade as the clean file"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Increment B: a TWEAKED-checksum entry stores the keyed fold of the
/// plaintext CRC32, which used to make it un-verifiable - `expect_crc`
/// was filtered to None and the decrypted output shipped with no
/// integrity check at all. The gate now folds the computed CRC the
/// same way before comparing, so a tweaked entry gets exactly the
/// protection an untweaked one has: clean bytes verify, damaged
/// ciphertext fails hard instead of masquerading as output.
#[test]
fn tweaked_checksum_entry_is_verified_through_the_keyed_fold() {
    let plain = payload(140_003, 44);

    // Clean, tweaked: must extract byte-exact.
    let mut f = fixtures::encrypt_file("hunter2", &plain, 21);
    f.with_crc = true;
    f.tweaked = true;
    let dir = tmpdir("enc-tweaked-ok");
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 21);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();

    // Damaged ciphertext under the same tweaked entry: the folded
    // comparison must catch it. Before this gate the mismatch was
    // invisible and the corrupt file shipped as success.
    let mut fbad = fixtures::encrypt_file("hunter2", &plain, 22);
    fbad.with_crc = true;
    fbad.tweaked = true;
    fbad.cipher[70_000] ^= 0x5A;
    let dir = tmpdir("enc-tweaked-bad");
    let vol = fixtures::rar5_volume_enc(
        &[("movie.mkv", &fbad, 0..fbad.cipher.len(), false, false)],
        None,
    );
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 22);
    let res = ex.finish();
    assert!(res.is_err(), "damaged tweaked plaintext must not succeed");
    let out = dir.join("movie.mkv");
    assert!(
        !out.exists() || std::fs::read(&out).unwrap() != plain,
        "corrupt plaintext must not masquerade as the clean file"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Increment B2: a CHECK-LESS encrypted RAR5 store set - the crypt
/// record carries no password check, so nothing can verify the
/// password before data is decrypted - used to demote to disk on
/// sight. It now maps one-pass and is adjudicated at finish against
/// the whole-file checksum, which lives on the set's LAST piece (the
/// head's value describes only its own volume). Split across three
/// volumes so the tail lookup is what makes it work.
#[test]
fn checkless_encrypted_store_set_maps_and_verifies_at_finish() {
    let plain = payload(300_007, 51);
    let mut f = fixtures::encrypt_file("n0check", &plain, 31);
    f.with_crc = true;
    f.no_check = true;
    let n = f.cipher.len();
    let (a, b) = (100_016, 200_016);
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..a, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, a..b, true, true)], Some(1)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, b..n, true, false)], Some(2)),
    ];
    let dir = tmpdir("enc-checkless-ok");
    let ex = Extractor::new(&dir, 3, true);
    ex.set_password("n0check");
    for (i, v) in vols.iter().enumerate() {
        feed(&ex, i, &format!("v{i}.rar"), v, 7000, 31 + i as u64);
    }
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks.is_empty(),
        "must not demote: {:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    for i in 0..vols.len() {
        assert!(
            !dir.join(format!("v{i}.rar")).exists(),
            "volume {i} must not touch disk (one-pass)"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The other half of B2's contract: the SAME check-less set with the
/// WRONG password must not publish garbage. Nothing could veto the
/// password up front, so the whole-file checksum is the verdict - it
/// misses, and the group demotes (volumes materialize byte-exact for
/// the disk path, which validates the password itself) instead of
/// either shipping noise or failing the whole download.
#[test]
fn checkless_encrypted_store_set_wrong_password_demotes_not_publishes() {
    let plain = payload(300_007, 52);
    let mut f = fixtures::encrypt_file("rightpw", &plain, 33);
    f.with_crc = true;
    f.no_check = true;
    let n = f.cipher.len();
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..n / 2, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, n / 2..n, true, false)], Some(1)),
    ];
    let dir = tmpdir("enc-checkless-wrongpw");
    let ex = Extractor::new(&dir, 2, true);
    ex.set_password("wrongpw");
    for (i, v) in vols.iter().enumerate() {
        feed(&ex, i, &format!("v{i}.rar"), v, 7000, 41 + i as u64);
    }
    let rep = ex.finish().expect("a wrong password must not fail the job");
    assert!(!rep.fallbacks.is_empty(), "the group must demote");
    let out = dir.join("movie.mkv");
    assert!(
        !out.exists() || std::fs::read(&out).unwrap() != plain,
        "wrong-password output must never masquerade as the payload"
    );
    // The volumes are the deliverable now, and must be byte-exact -
    // this is the property that assembling CIPHERTEXT (rather than
    // decrypting in place) buys.
    for (i, v) in vols.iter().enumerate() {
        let got = std::fs::read(dir.join(format!("v{i}.rar")))
            .unwrap_or_else(|e| panic!("volume {i} must materialize: {e}"));
        assert!(got == *v, "volume {i} must materialize byte-exact");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `rar a -htb` writes a BLAKE2sp digest INSTEAD of a CRC32, and nzbkit
/// has no BLAKE2sp of its own - so nothing in the one-pass path can
/// adjudicate such an output. `instream_decrypt_allowed` diverts the
/// shape away from write-time decryption explicitly so the disk path
/// (where rars checks the keyed digest) takes it, but nothing demoted
/// it: the finish pass built a job with `expect_crc = None`, the RAR5
/// password check set `verified = true`, and the demotion filter let it
/// through. Result: plaintext published with no integrity verdict at
/// all, on an archive whose ciphertext may have been damaged before the
/// yEnc/PAR2 pass ever saw it (Codex sweep 12 Aug F2).
///
/// A CORRECT password, deliberately: the point is that a verified key is
/// not a verified payload.
///
/// Both split shapes, and in both feed orders. The SPLIT case is the one
/// that mattered most and the one the report missed: only the tail
/// fragment carries the whole-file checks, so the write-time veto reads
/// `hash: None, file_crc: None` off the head, answers "allowed", and
/// latches the plaintext-once route for the whole file - which made
/// whether anything was checked depend on which volume arrived first.
#[test]
fn a_hash_only_encrypted_set_demotes_rather_than_publishing_unchecked() {
    let plain = payload(300_007, 53);
    let mut f = fixtures::encrypt_file("hunter2", &plain, 37);
    // The shape: a digest, and NO CRC32.
    f.with_hash = true;
    f.with_crc = false;
    let n = f.cipher.len();
    let unsplit = vec![fixtures::rar5_volume_enc(
        &[("movie.mkv", &f, 0..n, false, false)],
        None,
    )];
    let split = vec![
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..150_016, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 150_016..n, true, false)], Some(1)),
    ];
    for (label, vols, tail_first) in [
        ("unsplit", unsplit, false),
        ("split-head-first", split.clone(), false),
        ("split-tail-first", split, true),
    ] {
        let dir = tmpdir(&format!("enc-hash-only-{label}"));
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_password("hunter2");
        let order: Vec<usize> = if tail_first {
            (0..vols.len()).rev().collect()
        } else {
            (0..vols.len()).collect()
        };
        for i in order {
            feed(&ex, i, &format!("v{i}.rar"), &vols[i], 7000, 51 + i as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(
            !rep.fallbacks.is_empty(),
            "{label}: a set nothing here can check must demote to the verifying disk path"
        );
        assert!(
            rep.decrypted.is_empty(),
            "{label}: nothing may be reported as decrypted: {:?}",
            rep.decrypted
        );
        assert!(
            !dir.join("movie.mkv").exists(),
            "{label}: no unverified plaintext may be published"
        );
        // And the volumes are byte-exact, so the disk path gets the
        // posted bytes to verify the digest against.
        for (i, v) in vols.iter().enumerate() {
            let got = std::fs::read(dir.join(format!("v{i}.rar")))
                .unwrap_or_else(|e| panic!("{label}: volume {i} must materialize: {e}"));
            assert!(got == *v, "{label}: volume {i} must materialize byte-exact");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The twin: a digest AND a CRC32 is fully adjudicable here, so it must
/// still take the one-pass route. Without this the fix above would be
/// indistinguishable from "demote anything with a hash record".
#[test]
fn a_hash_plus_crc_encrypted_set_still_maps_one_pass() {
    let plain = payload(300_007, 54);
    let mut f = fixtures::encrypt_file("hunter2", &plain, 39);
    f.with_hash = true;
    f.with_crc = true;
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let dir = tmpdir("enc-hash-and-crc");
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 61);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks.is_empty(),
        "must not demote: {:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 158 item 2: a head and a tail that DISAGREE about a check field
/// must not route half an output each way.
///
/// `crypto_files` latches the plaintext-once route by output name on
/// whichever fragment asks first, and the write-time decision used to read
/// its check fields off the fragment in front of the writer. Only the tail
/// carries the whole-file checks, so the two could answer differently for
/// one file - and a half-plaintext output cannot be turned back into
/// byte-exact volumes by the fallback shim, which is what a demoted group
/// needs from it.
///
/// The fixture is synthetic on purpose: no real writer states a whole-file
/// digest on a head piece, which is why this shape is unreachable in the
/// field today and why it stops being unreachable the moment another
/// per-file check field is added. Here the HEAD states a BLAKE2sp digest
/// and no CRC32 (nothing this build can adjudicate) and the tail states a
/// CRC32 (which adjudicates the whole file).
///
/// The head is the piece that makes the disagreement bite: its base is
/// offset 0, so its spans WRITE while a tail's would still be holding for
/// an unresolved base. Feeding part of the head, then the tail, then the
/// rest of the head is therefore the order that used to write ciphertext
/// under a veto and then latch plaintext-once when the tail's CRC32 lifted
/// it - one output, both routes. Every order below must leave the file on
/// one route and publish the same correct bytes.
#[test]
fn head_and_tail_disagreeing_about_the_digest_never_mix_routes() {
    let plain = payload(300_007, 71);
    let mut head = fixtures::encrypt_file("hunter2", &plain, 43);
    // Head: a digest where no real archive puts one, and no CRC32.
    head.with_hash = true;
    head.checks_on_head = true;
    let mut tail = fixtures::encrypt_file("hunter2", &plain, 43);
    tail.with_crc = true;
    let n = head.cipher.len();
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &head, 0..150_016, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &tail, 150_016..n, true, false)], Some(1)),
    ];
    // Sequential so the interleaved order is exactly the one described.
    let put = |ex: &Extractor, slot: usize, vol: &[u8], r: std::ops::Range<usize>| {
        let mut at = r.start;
        while at < r.end {
            let to = (at + 7000).min(r.end);
            ex.write(
                slot,
                &format!("v{slot}.rar"),
                vol.len() as u64,
                at as u64,
                &vol[at..to],
            )
            .unwrap();
            at = to;
        }
    };
    let cut = 70_000;
    for label in ["head-split-around-tail", "head-first", "tail-first"] {
        let dir = tmpdir(&format!("enc-disagree-digest-{label}"));
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_password("hunter2");
        match label {
            "head-split-around-tail" => {
                put(&ex, 0, &vols[0], 0..cut);
                put(&ex, 1, &vols[1], 0..vols[1].len());
                put(&ex, 0, &vols[0], cut..vols[0].len());
            }
            "head-first" => {
                put(&ex, 0, &vols[0], 0..vols[0].len());
                put(&ex, 1, &vols[1], 0..vols[1].len());
            }
            _ => {
                put(&ex, 1, &vols[1], 0..vols[1].len());
                put(&ex, 0, &vols[0], 0..vols[0].len());
            }
        }
        let rep = ex.finish().unwrap();
        // The tail's CRC32 covers the whole plaintext, so this set IS
        // adjudicable and must publish - on whichever route it took.
        assert!(
            rep.fallbacks.is_empty(),
            "{label}: the tail's CRC32 adjudicates this set: {:?}",
            rep.fallbacks
        );
        assert_eq!(
            std::fs::read(dir.join("movie.mkv")).unwrap(),
            plain,
            "{label}: the published plaintext must be whole and correct"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The same disagreement one field over: the head omits the stored
/// password check (crypt flag 0x01 clear) and the tail carries one.
///
/// Reading the check off the fragment in front answered "no proof, assemble
/// ciphertext" for the head and "verified, decrypt in place" for the tail -
/// two routes, one output. Resolved over the whole file it is one answer in
/// both feed orders: the head's record is what keys the stream, an
/// unproven key never decrypts at write time, and the finish pass
/// adjudicates the assembled ciphertext against the tail's whole-file
/// CRC32 - so the file publishes, correct, either way.
#[test]
fn head_and_tail_disagreeing_about_the_password_check_never_mix_routes() {
    let plain = payload(300_007, 73);
    let mut head = fixtures::encrypt_file("hunter2", &plain, 45);
    head.no_check = true;
    head.with_crc = true;
    let mut tail = fixtures::encrypt_file("hunter2", &plain, 45);
    tail.with_crc = true;
    let n = head.cipher.len();
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &head, 0..150_016, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &tail, 150_016..n, true, false)], Some(1)),
    ];
    for (label, tail_first) in [("head-first", false), ("tail-first", true)] {
        let dir = tmpdir(&format!("enc-disagree-check-{label}"));
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_password("hunter2");
        let order: Vec<usize> = if tail_first {
            (0..vols.len()).rev().collect()
        } else {
            (0..vols.len()).collect()
        };
        for i in order {
            feed(&ex, i, &format!("v{i}.rar"), &vols[i], 7000, 73 + i as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.is_empty(),
            "{label}: the tail's CRC32 adjudicates this set, nothing to demote: {:?}",
            rep.fallbacks
        );
        assert_eq!(
            std::fs::read(dir.join("movie.mkv")).unwrap(),
            plain,
            "{label}: the published plaintext must be whole and correct"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The real multi-volume shape: ONE CBC stream carved at arbitrary
/// (non-16-aligned) offsets, same crypt record in every volume, fed
/// interleaved and out of order.
#[test]
fn encrypted_split_volumes_decrypt() {
    let dir = tmpdir("enc-split");
    let plain = payload(500_007, 42);
    let f = fixtures::encrypt_file("s3cret", &plain, 11);
    let n = f.cipher.len();
    let (a, b) = (170_003, 340_006); // deliberately odd split points
    let vols = [
        fixtures::rar5_volume_enc(&[("film.mkv", &f, 0..a, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("film.mkv", &f, a..b, true, true)], Some(1)),
        fixtures::rar5_volume_enc(&[("film.mkv", &f, b..n, true, false)], Some(2)),
    ];
    let ex = Extractor::new(&dir, 3, true);
    ex.set_password("s3cret");
    feed(&ex, 2, "x.part3.rar", &vols[2], 9000, 11);
    feed(&ex, 0, "x.part1.rar", &vols[0], 9000, 12);
    feed(&ex, 1, "x.part2.rar", &vols[1], 9000, 13);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.decrypted, vec!["film.mkv".to_string()]);
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), plain);
    assert!(!dir.join("x.part1.rar").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Plaintext-once across every arrival order and article size -
/// including pathological articles smaller than two cipher blocks,
/// where every span is nothing BUT seams.
///
/// This compared the in-stream route against the legacy
/// ciphertext+finish-decrypt one until TODO 27 phase 3 deleted the
/// second route; the orders and sizes it swept are what the test was
/// really for, so they stay.
#[test]
fn instream_decrypt_holds_across_orders_and_sizes() {
    let plain = payload(120_003, 77);
    let mut f = fixtures::encrypt_file("hunter2", &plain, 21);
    f.with_crc = true; // engage the composed-CRC verify too
    f.tweaked = false;
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    for art in [17usize, 33, 4096, 7000] {
        for seed in [1u64, 2, 3] {
            let dir = tmpdir(&format!("eqv-{art}-{seed}"));
            let ex = Extractor::new(&dir, 1, true);
            ex.set_password("hunter2");
            feed(&ex, 0, "v.rar", &vol, art, seed);
            let rep = ex.finish().unwrap();
            assert!(
                rep.fallbacks.is_empty(),
                "art={art} seed={seed}: {:?}",
                rep.fallbacks
            );
            assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
            assert_eq!(
                std::fs::read(dir.join("movie.mkv")).unwrap(),
                plain,
                "output wrong at art={art} seed={seed}"
            );
            assert!(!dir.join("v.rar").exists(), "no volume on disk");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}

/// Split encrypted file, in-stream: one CBC stream across three
/// volumes, volumes fed out of order, seams crossing volume
/// boundaries.
#[test]
fn instream_split_volumes_decrypt() {
    let dir = tmpdir("instream-split");
    let plain = payload(500_007, 42);
    let f = fixtures::encrypt_file("s3cret", &plain, 11);
    let n = f.cipher.len();
    let (a, b) = (170_003, 340_006);
    let vols = [
        fixtures::rar5_volume_enc(&[("film.mkv", &f, 0..a, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("film.mkv", &f, a..b, true, true)], Some(1)),
        fixtures::rar5_volume_enc(&[("film.mkv", &f, b..n, true, false)], Some(2)),
    ];
    let ex = Extractor::new(&dir, 3, true);
    ex.set_password("s3cret");
    feed(&ex, 2, "x.part3.rar", &vols[2], 4099, 31);
    feed(&ex, 0, "x.part1.rar", &vols[0], 4099, 32);
    feed(&ex, 1, "x.part2.rar", &vols[1], 4099, 33);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.decrypted, vec!["film.mkv".to_string()]);
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The posted-bytes shim: after an in-stream decrypt, read_at over
/// the whole volume view must reproduce the POSTED volume
/// byte-exactly - headers from the stash, data areas re-encrypted
/// from the plaintext on disk, seam/tail slivers from retained
/// cipher. This is what PAR2 settle read-back, mapped repair and
/// fallback all consume.
#[test]
fn instream_read_at_reproduces_posted_volume_bytes() {
    let dir = tmpdir("instream-shim");
    // Big enough to cross a checkpoint stride with the small chunk.
    let plain = payload(300_005, 55);
    let f = fixtures::encrypt_file("pw", &plain, 9);
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("pw");
    feed(&ex, 0, "v.rar", &vol, 7001, 5);
    // Whole-volume round trip.
    let mut got = vec![0u8; vol.len()];
    ex.read_at(0, 0, &mut got).unwrap();
    assert_eq!(got, vol, "shim must reproduce the posted volume");
    // Unaligned interior windows, crossing data-area edges.
    for (off, len) in [(1u64, 31usize), (999, 4097), (150_001, 50_003)] {
        let mut w = vec![0u8; len];
        ex.read_at(0, off, &mut w).unwrap();
        assert_eq!(
            w,
            vol[off as usize..off as usize + len],
            "window {off}+{len}"
        );
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A file spanning several checkpoint strides: the shim must chain
/// from the nearest checkpoint (not the file head), deep windows
/// must reproduce posted bytes, and a repair landing past the first
/// stride must refresh the checkpoints it crosses.
#[test]
fn instream_checkpoints_serve_deep_windows_and_repairs() {
    let dir = tmpdir("instream-ckpt");
    let plain = payload(3_500_003, 91);
    let mut f = fixtures::encrypt_file("hunter2", &plain, 66);
    f.with_crc = true;
    f.tweaked = false;
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let mut damaged = vol.clone();
    for i in 2_500_000..2_500_048 {
        damaged[i] ^= 0xA7;
    }
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &damaged, 65_536, 14);
    // Deep windows chain from checkpoints, not a multi-MB walk.
    for (off, len) in [(3_200_001u64, 8_192usize), (1_048_570, 64), (2_097_140, 40)] {
        let mut w = vec![0u8; len];
        ex.read_at(0, off, &mut w).unwrap();
        assert_eq!(w, damaged[off as usize..off as usize + len], "window {off}");
    }
    // Repair the damage (crosses nothing aligned on purpose).
    ex.patch_volume_span(0, 2_499_997, &vol[2_499_997..2_500_051])
        .unwrap();
    let mut got = vec![0u8; vol.len()];
    ex.read_at(0, 0, &mut got).unwrap();
    assert_eq!(got, vol, "healed volume view across strides");
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Mapped repair on a plaintext-once file: damaged cipher decrypts
/// to garbage plaintext locally, the patch rewrites the repaired
/// blocks AND the CBC-adjacent following block, and the stored-CRC
/// gate passes on the healed plaintext.
#[test]
fn instream_patch_heals_damaged_cipher_and_adjacency() {
    let dir = tmpdir("instream-patch");
    let plain = payload(200_003, 61);
    let mut f = fixtures::encrypt_file("hunter2", &plain, 33);
    f.with_crc = true;
    f.tweaked = false;
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    // Damage a mid-data range of the POSTED bytes before feeding -
    // the wire delivered corrupt cipher, exactly what PAR2 repairs.
    let mut damaged = vol.clone();
    for i in 45_000..45_040 {
        damaged[i] ^= 0x5A;
    }
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &damaged, 7000, 8);
    // Repair the damaged span with the true posted bytes (unaligned
    // edges on purpose - the patch window logic must round out).
    ex.patch_volume_span(0, 44_997, &vol[44_997..45_043])
        .unwrap();
    // The healed volume view must be the pristine posted bytes...
    let mut got = vec![0u8; vol.len()];
    ex.read_at(0, 0, &mut got).unwrap();
    assert_eq!(got, vol, "healed volume view");
    // ...and the plaintext (incl. the adjacency block) must verify.
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An incomplete in-stream set falls back to materialized volumes,
/// and every byte the fallback writes must be the POSTED byte (the
/// shim rebuilding cipher from plaintext), never plaintext leaking
/// into a volume file.
#[test]
fn instream_incomplete_set_materializes_posted_bytes() {
    let dir = tmpdir("instream-fallback");
    let plain = payload(200_003, 71);
    let f = fixtures::encrypt_file("hunter2", &plain, 44);
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    // Feed everything except one mid-file article.
    let art = 7000usize;
    let skip = 91_000usize;
    let mut i = 0;
    while i < vol.len() {
        let e = (i + art).min(vol.len());
        if i != skip {
            ex.write(0, "v.rar", vol.len() as u64, i as u64, &vol[i..e])
                .unwrap();
        }
        i = e;
    }
    let rep = ex.finish().unwrap();
    assert!(!rep.fallbacks.is_empty(), "incomplete set must fall back");
    let disk = std::fs::read(dir.join("v.rar")).unwrap();
    // Every fed byte materialized must equal the posted byte.
    let mut i = 0;
    while i < vol.len().min(disk.len()) {
        let e = (i + art).min(vol.len()).min(disk.len());
        if i != skip {
            assert_eq!(
                &disk[i..e],
                &vol[i..e],
                "materialized volume must hold posted bytes at {i}"
            );
        }
        i = e;
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Plaintext-once bookkeeping: spans that fed an in-stream-decrypted
/// file are never journaled (a resume must refetch them - the disk
/// holds plaintext, not the posted bytes a restore would copy into
/// volume files), and /stream serves the output as a plain file.
#[test]
fn instream_spans_never_journal() {
    let dir = tmpdir("instream-journal");
    let plain = payload(150_001, 81);
    let f = fixtures::encrypt_file("hunter2", &plain, 55);
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    let mut any_placed = false;
    let art = 7000usize;
    let mut i = 0;
    while i < vol.len() {
        let e = (i + art).min(vol.len());
        let p = ex
            .write(0, "v.rar", vol.len() as u64, i as u64, &vol[i..e])
            .unwrap();
        if let Persist::Placed(_) = p {
            any_placed = true;
        }
        i = e;
    }
    assert!(
        !any_placed,
        "no article of an in-stream-decrypted file may be journaled"
    );
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Phase 2 of plaintext-once: a journaled run's D/E/K/T records let a
/// resume RE-ENCRYPT the on-disk plaintext back into posted volume
/// bytes. Simulates a kill (drop without finish), then restores and
/// compares every restored span byte-for-byte against the posted
/// volume - including the final article, whose last block needs the
/// journaled tail padding.
#[test]
fn instream_journal_restores_posted_bytes_for_resume() {
    let dir = tmpdir("instream-resume");
    let plain = payload(2_300_005, 87); // > 2 checkpoint strides
    let f = fixtures::encrypt_file("hunter2", &plain, 77);
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let art = 50_000usize;
    let n_arts = vol.len().div_ceil(art);

    // Run 1: journal exactly like main.rs does, "crash" before the
    // last two articles and before finish.
    let (journal, _) = crate::journal::Journal::open(&dir, b"nzb-x").unwrap();
    let mut d_ids: Vec<String> = Vec::new();
    {
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        // Mirror main.rs: D records park until their span's seam
        // bytes are physically on disk (usually one article later).
        let mut pending: Vec<(String, Vec<Frag>)> = Vec::new();
        for i in 0..n_arts - 2 {
            let s = i * art;
            let e = (s + art).min(vol.len());
            let id = format!("<a{i}@t>");
            let p = ex
                .write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
            match p {
                Persist::PlacedCrypto(frags) => pending.push((id, frags)),
                Persist::Placed(_) => panic!("crypto span must journal as D, not R"),
                Persist::No | Persist::Held(_) => {}
            }
            pending.retain(|(id, frags)| {
                if ex.crypto_span_on_disk(frags) {
                    let ev = ex.drain_crypto_events();
                    journal.record_crypto_events(&ev);
                    journal.record_placed_crypto(
                        0,
                        id,
                        ex.slot_file_info(0),
                        "v.rar",
                        vol.len() as u64,
                        frags,
                        &ex.crypto_frag_mask(frags),
                    );
                    d_ids.push(id.clone());
                    false
                } else {
                    true
                }
            });
        }
        // Killed: dropped without finish. The frontier article's
        // seam never settled, so it must still be parked.
        assert!(!pending.is_empty(), "the frontier span must be unjournaled");
    }
    drop(journal);
    // The plaintext output must exist from run 1.
    assert!(dir.join("movie.mkv").exists());
    assert!(!d_ids.is_empty(), "run 1 recorded D articles");

    // Resume: parse + restore with the password.
    let (_j2, resume) = crate::journal::Journal::open(&dir, b"nzb-x").unwrap();
    assert!(
        resume.crypto_files.contains_key("movie.mkv"),
        "E record parsed"
    );
    let restored = crate::journal::restore(&dir, &resume, Some("hunter2"));
    // Every D article restores (its plaintext fully on disk - the
    // skipped articles' seams only affect themselves).
    for id in &d_ids {
        assert!(restored.ids.contains(id), "{id} must restore");
    }
    // And the rebuilt volume bytes are the POSTED bytes.
    let rebuilt = std::fs::read(dir.join("v.rar")).unwrap();
    for seed in &restored.seeds {
        for &(off, len) in &seed.spans {
            assert_eq!(
                &rebuilt[off as usize..(off + len) as usize],
                &vol[off as usize..(off + len) as usize],
                "restored span {off}+{len} must be posted bytes"
            );
        }
    }
    // No password: nothing restores, articles refetch.
    let none = crate::journal::restore(&dir, &resume, None);
    assert!(none.ids.is_empty(), "no password must mean no restores");
    // Wrong password: KDF succeeds but produces the wrong keystream;
    // the checkpoint cross-verify rejects the walk, so nothing is
    // restored (rather than poisoned volumes).
    let wrong = crate::journal::restore(&dir, &resume, Some("wrong"));
    assert!(
        wrong.ids.is_empty(),
        "wrong password must not restore: {:?}",
        wrong.ids.len()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A D record without its E facts (torn journal tail, or a file
/// whose params line was lost) must refetch, never guess.
#[test]
fn journal_d_without_e_refetches() {
    let dir = tmpdir("d-without-e");
    std::fs::write(dir.join("movie.mkv"), payload(64_000, 3)).unwrap();
    let text = "nzbfast-journal v1 d41d8cd98f00b204e9800998ecf8427e\n\
                S 0 100000 v.rar\n\
                F 0 movie.mkv\n\
                D 0 0:0:5000:32768 <a1@t>\n";
    std::fs::write(dir.join(".nzbfast.journal"), text).unwrap();
    // Reparse through the real reader (fingerprint of b"" matches).
    let (_j, resume) = crate::journal::Journal::open(&dir, b"").unwrap();
    let restored = crate::journal::restore(&dir, &resume, Some("pw"));
    assert!(restored.ids.is_empty(), "D without E must refetch");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `-hp` shape: encrypted headers AND encrypted data.
#[test]
fn encrypted_headers_volume_decrypts() {
    let dir = tmpdir("enc-hdrs");
    let plain = payload(150_001, 43);
    let f = fixtures::encrypt_file("pw", &plain, 21);
    let vol = fixtures::rar5_volume_enc_headers(
        &[("obf.bin", &f, 0..f.cipher.len(), false, false)],
        None,
        "pw",
        22,
    );
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("pw");
    feed(&ex, 0, "0abc123.rar", &vol, 6000, 9);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.decrypted, vec!["obf.bin".to_string()]);
    assert_eq!(std::fs::read(dir.join("obf.bin")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Wrong password: the check value rejects it BEFORE any garbage is
/// written; the volume materializes byte-identical (unrar / retry
/// with the right password still possible).
#[test]
fn encrypted_wrong_password_materializes_volume() {
    let dir = tmpdir("enc-wrongpw");
    let plain = payload(90_000, 44);
    let f = fixtures::encrypt_file("right", &plain, 31);
    let vol = fixtures::rar5_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("wrong");
    feed(&ex, 0, "v.rar", &vol, 7000, 5);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks.iter().any(|(_, w)| w.contains("password")),
        "{:?}",
        rep.fallbacks
    );
    assert!(rep.decrypted.is_empty());
    assert_eq!(
        std::fs::read(dir.join("v.rar")).unwrap(),
        vol,
        "byte-exact volume"
    );
    assert!(!dir.join("a.bin").exists(), "no half-written decoy output");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// No password at all: today's behavior - volumes on disk, reason
/// names encryption.
#[test]
fn encrypted_without_password_materializes_volume() {
    let dir = tmpdir("enc-nopw");
    let plain = payload(60_000, 45);
    let f = fixtures::encrypt_file("x", &plain, 33);
    let vol = fixtures::rar5_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 7000, 6);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks.iter().any(|(_, w)| w.contains("encrypted")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The committed REAL `rar 7.23` fixtures, driven through the full
/// extractor: single encrypted volume, encrypted headers, and the
/// 3-volume split - each must produce the exact payload with no
/// volume files left behind.
#[test]
fn real_rar_fixtures_extract_and_decrypt() {
    let secret = include_bytes!("../../testdata/rar5/secret.bin").to_vec();
    let cases: Vec<(&str, Vec<(&str, &[u8])>)> = vec![
        (
            "store",
            vec![(
                "enc-store.rar",
                include_bytes!("../../testdata/rar5/enc-store.rar"),
            )],
        ),
        (
            "hdrs",
            vec![(
                "enc-hdrs.rar",
                include_bytes!("../../testdata/rar5/enc-hdrs.rar"),
            )],
        ),
        (
            "vols",
            vec![
                (
                    "enc-vols.part1.rar",
                    include_bytes!("../../testdata/rar5/enc-vols.part1.rar"),
                ),
                (
                    "enc-vols.part2.rar",
                    include_bytes!("../../testdata/rar5/enc-vols.part2.rar"),
                ),
                (
                    "enc-vols.part3.rar",
                    include_bytes!("../../testdata/rar5/enc-vols.part3.rar"),
                ),
            ],
        ),
    ];
    for (tag, vols) in cases {
        let dir = tmpdir(&format!("enc-real-{tag}"));
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_password("testpw123");
        for (si, (name, bytes)) in vols.iter().enumerate() {
            feed(&ex, si, name, bytes, 1400, 60 + si as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
        assert_eq!(rep.decrypted, vec!["secret.bin".to_string()], "{tag}");
        assert_eq!(
            std::fs::read(dir.join("secret.bin")).unwrap(),
            secret,
            "{tag}"
        );
        for (name, _) in &vols {
            assert!(
                !dir.join(name).exists(),
                "{tag}: volume {name} materialized"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The committed REAL RAR4 fixtures (`unrar t`-validated; see
/// testdata/rar4/README.md), driven through the full extractor.
/// RAR4 has no password check, so every one of these takes the
/// UNVERIFIED route - ciphertext assembled at store offsets, decrypted
/// at finish, and published only once the header's plaintext CRC32
/// accepts it - yet the outcome must be the same one-pass extraction
/// RAR5 gets: exact payload, no volume left on disk.
#[test]
fn real_rar4_fixtures_extract_and_decrypt() {
    let secret = include_bytes!("../../testdata/rar4/secret.bin").to_vec();
    let cases: Vec<(&str, Vec<(&str, &[u8])>)> = vec![
        (
            "store",
            vec![(
                "enc-store.rar",
                include_bytes!("../../testdata/rar4/enc-store.rar"),
            )],
        ),
        (
            "hdrs",
            vec![(
                "enc-hdrs.rar",
                include_bytes!("../../testdata/rar4/enc-hdrs.rar"),
            )],
        ),
        (
            "vols",
            vec![
                (
                    "enc-vols.part1.rar",
                    include_bytes!("../../testdata/rar4/enc-vols.part1.rar"),
                ),
                (
                    "enc-vols.part2.rar",
                    include_bytes!("../../testdata/rar4/enc-vols.part2.rar"),
                ),
                (
                    "enc-vols.part3.rar",
                    include_bytes!("../../testdata/rar4/enc-vols.part3.rar"),
                ),
            ],
        ),
        (
            "hdrvols",
            vec![
                (
                    "enc-hdr-vols.part1.rar",
                    include_bytes!("../../testdata/rar4/enc-hdr-vols.part1.rar"),
                ),
                (
                    "enc-hdr-vols.part2.rar",
                    include_bytes!("../../testdata/rar4/enc-hdr-vols.part2.rar"),
                ),
                (
                    "enc-hdr-vols.part3.rar",
                    include_bytes!("../../testdata/rar4/enc-hdr-vols.part3.rar"),
                ),
            ],
        ),
    ];
    for (tag, vols) in cases {
        let dir = tmpdir(&format!("enc-real4-{tag}"));
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_password("testpw123");
        for (si, (name, bytes)) in vols.iter().enumerate() {
            feed(&ex, si, name, bytes, 137, 60 + si as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
        assert_eq!(rep.decrypted, vec!["inner.bin".to_string()], "{tag}");
        assert_eq!(
            std::fs::read(dir.join("inner.bin")).unwrap(),
            secret,
            "{tag}"
        );
        for (name, _) in &vols {
            assert!(
                !dir.join(name).exists(),
                "{tag}: volume {name} materialized"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// A RAR4 volume holding TWO inner files. RAR4 salts each file
/// separately (the writer draws a fresh one per entry), so each needs
/// its OWN derived key and its own IV - a single archive-wide key,
/// which is what a RAR5-shaped assumption would give, decrypts the
/// second file to noise. Both must come out, and the finish pass must
/// pair each output with the right head entry.
#[test]
fn rar4_multi_file_volume_derives_a_key_per_inner_file() {
    let dir = tmpdir("enc4-multi");
    let a_plain = payload(40_000, 51);
    let b_plain = payload(25_003, 52); // odd: exercises the tail pad too
    let fa = fixtures::encrypt_file_v4("pw", &a_plain, 41);
    let fb = fixtures::encrypt_file_v4("pw", &b_plain, 42);
    assert_ne!(
        fa.salt, fb.salt,
        "the fixture must give each file its own salt"
    );
    let vol = fixtures::rar4_volume_enc(&[
        ("a.bin", &fa, 0..fa.cipher.len(), false, false),
        ("b.bin", &fb, 0..fb.cipher.len(), false, false),
    ]);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("pw");
    feed(&ex, 0, "v.rar", &vol, 4096, 8);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(
        rep.decrypted,
        vec!["a.bin".to_string(), "b.bin".to_string()]
    );
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a_plain);
    assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b_plain);
    assert!(!dir.join("v.rar").exists(), "volume must not materialize");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The wrong password on a RAR4 `-p` set. Nothing can catch it before
/// the decrypt pass, so this is the case the unverified route exists
/// for: the CRC gate must reject, the group must DEMOTE rather than
/// fail the job, and the assembled bytes must come back out as the
/// byte-exact posted volume for unrar or a corrected retry.
#[test]
fn rar4_wrong_password_demotes_to_a_byte_exact_volume() {
    let dir = tmpdir("enc4-wrongpw");
    let plain = payload(60_000, 46);
    let f = fixtures::encrypt_file_v4("rightpw", &plain, 31);
    let vol = fixtures::rar4_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)]);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("wrongpw");
    feed(&ex, 0, "v.rar", &vol, 7000, 6);
    let rep = ex.finish().unwrap();
    assert!(
        rep.decrypted.is_empty(),
        "nothing may publish: {:?}",
        rep.decrypted
    );
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.contains("wrong password")),
        "the demote must name the real cause: {:?}",
        rep.fallbacks
    );
    assert_eq!(
        std::fs::read(dir.join("v.rar")).unwrap(),
        vol,
        "the demoted volume must be byte-exact for a retry"
    );
    assert!(
        !dir.join("a.bin").exists(),
        "no wrong-key garbage published"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 27 phase 3: a RAR4 `-p` set decrypts in-stream like every other
/// encrypted store shape, and its volume never touches disk.
///
/// It could not before. The gate demanded a stored check that PROVES the
/// password first, because a wrong one writes plaintext-shaped garbage
/// into the file the group has to be able to hand back as byte-exact
/// volumes - and RAR4 stores no check at all, so the set assembled
/// ciphertext for the finish pass instead. Phase 2's re-encrypt shim
/// retired that requirement: CBC inverts under ANY key, so E_k(D_k(c))
/// = c and the garbage rebuilds the same volumes real plaintext does
/// (`rar4_wrong_password_demotes_to_a_byte_exact_volume` is that half),
/// leaving the proof to decide only what a checksum MISS means.
///
/// Three things are asserted here that were all false before: the file
/// is PLAINTEXT on disk mid-download, the whole-file CRC32 in the RAR4
/// header adjudicates it at finish, and the shim still reproduces the
/// posted volume from it byte for byte.
#[test]
fn rar4_encrypted_store_decrypts_in_stream() {
    let dir = tmpdir("enc4-instream");
    let plain = payload(300_005, 47);
    let f = fixtures::encrypt_file_v4("hunter2", &plain, 32);
    let vol = fixtures::rar4_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)]);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 6);
    // Mid-download, before finish has adjudicated anything: the output
    // already holds the payload, not the ciphertext that was posted.
    assert_eq!(
        &std::fs::read(dir.join("movie.mkv")).unwrap()[..4096],
        &plain[..4096],
        "a RAR4 encrypted output must hold plaintext while it downloads"
    );
    // ...and the posted bytes are still reachable through the shim, so
    // a demote from here would materialize an exact volume.
    let mut got = vec![0u8; vol.len()];
    ex.read_at(0, 0, &mut got).unwrap();
    assert_eq!(got, vol, "the shim must reproduce the posted volume");
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    assert!(!dir.join("v.rar").exists(), "volume must not materialize");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A file whose password no stored check can PROVE journals no resume
/// facts, and that is deliberate rather than an omission.
///
/// The `E` grammar is RAR5-shaped (RAR4's 8-byte salt and SHA-1
/// schedule do not fit it), and a resume that re-encrypted local
/// plaintext under a key it could not prove would post bytes nobody
/// vouched for. So `crypto_for` emits `E` only for a wellformed-check
/// RAR5 record; a `D` record whose `E` is missing simply refetches its
/// article (`journal_d_without_e_refetches`), which is exactly what
/// these files did before they took this route at all.
///
/// Both unprovable shapes, against the provable one beside them.
#[test]
fn an_unprovable_password_journals_no_resume_facts() {
    let plain = payload(120_007, 48);
    // RAR4: no check field exists in the format.
    let f4 = fixtures::encrypt_file_v4("hunter2", &plain, 33);
    let v4 = fixtures::rar4_volume_enc(&[("movie.mkv", &f4, 0..f4.cipher.len(), false, false)]);
    // RAR5 with the check omitted: the record has the field and the
    // poster left it out.
    let mut f5 = fixtures::encrypt_file("hunter2", &plain, 34);
    f5.no_check = true;
    f5.with_crc = true;
    let v5 = fixtures::rar5_volume_enc(
        &[("movie.mkv", &f5, 0..f5.cipher.len(), false, false)],
        None,
    );
    // ...and the ordinary provable set, which must still journal.
    let mut ok = fixtures::encrypt_file("hunter2", &plain, 35);
    ok.with_crc = true;
    let vok = fixtures::rar5_volume_enc(
        &[("movie.mkv", &ok, 0..ok.cipher.len(), false, false)],
        None,
    );

    for (label, vol, want_params) in [
        ("rar4", &v4, false),
        ("checkless-rar5", &v5, false),
        ("checked-rar5", &vok, true),
    ] {
        let dir = tmpdir(&format!("enc-facts-{label}"));
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        feed(&ex, 0, "v.rar", vol, 7000, 7);
        let params = ex
            .drain_crypto_events()
            .iter()
            .any(|e| matches!(e, CryptoJournalEvent::Params { .. }));
        assert_eq!(
            params, want_params,
            "{label}: an `E` record may exist only where a resume could prove the password"
        );
        // Either way the set still decrypts and publishes: the facts
        // buy a cheaper RESUME, never correctness of this run.
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{label}: {:?}", rep.fallbacks);
        assert_eq!(
            std::fs::read(dir.join("movie.mkv")).unwrap(),
            plain,
            "{label}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// A RAR4 encrypted entry whose header carries no CRC (a zero field,
/// which the parser reads as "not computed") has NOTHING to adjudicate
/// an unverifiable password against, so it must demote before
/// decrypting rather than publish bytes no one vouched for.
#[test]
fn rar4_encrypted_without_a_checksum_demotes() {
    let dir = tmpdir("enc4-nocrc");
    let plain = payload(50_000, 47);
    let f = fixtures::encrypt_file_v4("pw", &plain, 32);
    let mut vol = fixtures::rar4_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)]);
    // Blank the file header's CRC field (file header at 20, CRC at +16)
    // and repair the header CRC16 so the block still parses.
    let hdr = 20usize;
    let hsize = u16::from_le_bytes(vol[hdr + 5..hdr + 7].try_into().unwrap()) as usize;
    vol[hdr + 16..hdr + 20].fill(0);
    let hc = (crc32fast::hash(&vol[hdr + 2..hdr + hsize]) & 0xffff) as u16;
    vol[hdr..hdr + 2].copy_from_slice(&hc.to_le_bytes());
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("pw"); // the RIGHT password, but unverifiable
    feed(&ex, 0, "v.rar", &vol, 7000, 5);
    let rep = ex.finish().unwrap();
    assert!(rep.decrypted.is_empty());
    assert!(
        rep.fallbacks.iter().any(|(_, w)| w.contains("encrypted")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A check-less encrypted archive can't have its password verified
/// natively (the stored CRC is keyed), so it must fall back to unrar
/// rather than risk a silent wrong-password decrypt.
#[test]
fn encrypted_without_check_falls_back() {
    let dir = tmpdir("enc-nocheck");
    let plain = payload(80_000, 61);
    let mut f = fixtures::encrypt_file("pw", &plain, 7);
    f.no_check = true;
    let vol = fixtures::rar5_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("pw"); // correct password, but unverifiable
    feed(&ex, 0, "v.rar", &vol, 7000, 5);
    let rep = ex.finish().unwrap();
    assert!(rep.decrypted.is_empty());
    assert!(
        rep.fallbacks.iter().any(|(_, w)| w.contains("encrypted")),
        "{:?}",
        rep.fallbacks
    );
    // Byte-exact volume kept for unrar / a corrected retry.
    assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A header-encrypted set whose password never turns up (the bench
/// release1 shape) must NOT park its payload in RAM up to the holds
/// cap: parked spans page to scratch beyond the pw-await window, so
/// peak held bytes stay at the window while the finish demote still
/// materializes byte-exact volumes with the password reason. Before
/// the pager, a 1.6 GB set sat fully resident on a big-RAM box - the
/// highest peak RSS of all five clients in the 2026-08-10 re-cut.
#[test]
fn pw_await_parked_spans_page_to_scratch() {
    let dir = tmpdir("pw-await-page");
    let plain = payload(24_000_000, 51);
    let f = fixtures::encrypt_file("no-candidate-knows-this", &plain, 9);
    let vol = fixtures::rar5_volume_enc_headers(
        &[("obf.bin", &f, 0..f.cipher.len(), false, false)],
        None,
        "no-candidate-knows-this",
        13,
    );
    let ex = Extractor::new(&dir, 1, true);
    // Window = (cap/4).clamp(4 MB, 64 MB) = 8 MB; the 24 MB payload
    // must overflow it to scratch, staying far under the 32 MB cap so
    // nothing demotes on "held-bytes cap".
    ex.set_holds_cap(32 << 20);
    ex.set_password_probe(std::sync::Arc::new(|_probe| None));
    // Offset 0 first so the slot classifies Rar (and parks on the
    // password blocker) before the data piles - a shuffle that lands
    // it late would route the early spans through the unclassified
    // path instead, which is not this test's subject.
    ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..7000])
        .unwrap();
    feed(&ex, 0, "v.rar", &vol, 7000, 11);
    assert!(
        ex.holds_peak() < 12 << 20,
        "parked spans stayed resident: peak {} for a {} B payload",
        ex.holds_peak(),
        vol.len()
    );
    assert!(
        ex.holds_paged_total() > 10 << 20,
        "paging never engaged: {}",
        ex.holds_paged_total()
    );
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.contains("password") && !w.contains("held-bytes cap")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(
        std::fs::read(dir.join("v.rar")).unwrap(),
        vol,
        "materialized volume must be byte-exact"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The rescue survives paging: a probe that produces the password only
/// at the finish force-probe must still re-key and extract one-pass,
/// re-feeding the parked spans from scratch (`reclaim_span` preads).
#[test]
fn pw_await_probe_hit_refeeds_paged_spans() {
    let dir = tmpdir("pw-await-page-hit");
    let plain = payload(24_000_000, 52);
    let f = fixtures::encrypt_file("late-sidecar-pw", &plain, 10);
    let vol = fixtures::rar5_volume_enc_headers(
        &[("obf.bin", &f, 0..f.cipher.len(), false, false)],
        None,
        "late-sidecar-pw",
        14,
    );
    let ex = Extractor::new(&dir, 1, true);
    ex.set_holds_cap(32 << 20);
    let landed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let l = landed.clone();
    ex.set_password_probe(std::sync::Arc::new(move |probe| {
        // Every mid-feed probe misses (the sidecar has not "landed"
        // yet); the finish force-probe hits, when the parked spans are
        // on scratch.
        if !l.load(std::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        (probe.verify("late-sidecar-pw") == crate::rar::PwVerdict::Verified)
            .then(|| "late-sidecar-pw".to_string())
    }));
    // Offset 0 first for the same deterministic classification as the
    // paging test above.
    ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..7000])
        .unwrap();
    feed(&ex, 0, "v.rar", &vol, 7000, 12);
    landed.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        ex.holds_paged_total() > 10 << 20,
        "paging never engaged: {}",
        ex.holds_paged_total()
    );
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.decrypted, vec!["obf.bin".to_string()]);
    assert_eq!(std::fs::read(dir.join("obf.bin")).unwrap(), plain);
    assert!(!dir.join("v.rar").exists(), "one-pass: no volume on disk");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Sweep 2 L8, the re-key half. `apply_probed_password` takes the
/// slot's whole header stash out before re-feeding it through the newly
/// keyed mapper, so a reclaim that fails partway is the last chance to
/// uncharge the spans it never reached. Dropping the vector frees the
/// memory and leaves the budget - and the scratch live count - charged
/// for them, which demotes later sets on a ceiling nothing is using and
/// stops the scratch file ever truncating.
///
/// The parked slot is real (a genuinely password-awaiting encrypted-
/// headers set); the failure is injected deterministically - a paged
/// span at the head of the stash and a scratch whose file handle is
/// gone, so the very first reclaim of the re-key fails with spans still
/// behind it.
#[test]
fn a_failed_rekey_refeed_leaves_no_stashed_span_charged() {
    let dir = tmpdir("pw-await-rekey-err");
    let plain = payload(2_000_000, 52);
    let f = fixtures::encrypt_file("late-sidecar-pw", &plain, 10);
    let vol = fixtures::rar5_volume_enc_headers(
        &[("obf.bin", &f, 0..f.cipher.len(), false, false)],
        None,
        "late-sidecar-pw",
        14,
    );
    let ex = Extractor::new(&dir, 1, true);
    // A probe hook that never hits: the await arm needs one to exist,
    // and the slot then simply parks with a mapper that will verify the
    // real password below.
    ex.set_password_probe(std::sync::Arc::new(|_| None));
    ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..7000])
        .unwrap();
    feed(&ex, 0, "v.rar", &vol, 7000, 12);

    let (a, b, c) = (vec![0xA1u8; 4096], vec![0xB2u8; 4096], vec![0xC3u8; 4096]);
    {
        let mut g = ex.inner.lock_ok();
        let inner = &mut *g;
        assert!(
            inner.slots[0].pw_await.is_some(),
            "the slot must be parked awaiting a password"
        );
        // Paged FIRST, so the failing reclaim is holding a scratch
        // charge and leaving the whole rest of the stash behind it.
        let off = inner.scratch.append(&a, u64::MAX).unwrap();
        inner.slots[0]
            .header_spans
            .insert(0, (0, HoldSpan::Paged { off, len: a.len() }));
        inner.budget.add(b.len());
        inner.slots[0]
            .header_spans
            .push((1 << 20, HoldSpan::Ram(b)));
        inner.budget.add(c.len());
        inner.slots[0]
            .header_spans
            .push((2 << 20, HoldSpan::Ram(c)));
        // The re-key is about to pread that span back.
        inner.scratch.st().file = None;
    }
    let err = ex
        .apply_probed_password("late-sidecar-pw")
        .expect_err("a dead scratch must fail the re-key");

    // Whatever the failure left IN the slots is legitimately charged;
    // nothing else may be. Walk the survivors and demand the two
    // counters agree with them exactly.
    let g = ex.inner.lock_ok();
    let (mut ram, mut paged) = (0usize, 0u64);
    for s in &g.slots {
        for (_, sp) in s.holds.iter().chain(s.header_spans.iter()) {
            match sp {
                HoldSpan::Ram(b) => ram += b.len(),
                HoldSpan::Paged { len, .. } => paged += *len as u64,
            }
        }
    }
    assert_eq!(
        g.budget.len(),
        ram,
        "RAM budget overstated after a failed re-key ({err})"
    );
    assert_eq!(
        g.scratch.st().live,
        paged,
        "scratch live count overstated after a failed re-key ({err})"
    );
    drop(g);
    drop(ex);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The real 3-volume split fixture, whose whole-file CRC lives on the
/// TAIL piece with real `rar`'s tweaked-checksum flag set there alone:
/// the tail stores the keyed FOLD of the whole-file CRC while the
/// head's record says "plain". A gate built from the head's record
/// compared the bare CRC against the fold and false-failed every
/// intact split set - this is the regression test for that.
///
/// It rode the legacy ciphertext route until TODO 27 phase 3 retired
/// it; the fixture and the gate it exercises are unchanged.
#[test]
fn real_rar_split_fixture_verifies() {
    let secret = include_bytes!("../../testdata/rar5/secret.bin").to_vec();
    let vols: Vec<(&str, &[u8])> = vec![
        (
            "enc-vols.part1.rar",
            include_bytes!("../../testdata/rar5/enc-vols.part1.rar"),
        ),
        (
            "enc-vols.part2.rar",
            include_bytes!("../../testdata/rar5/enc-vols.part2.rar"),
        ),
        (
            "enc-vols.part3.rar",
            include_bytes!("../../testdata/rar5/enc-vols.part3.rar"),
        ),
    ];
    let dir = tmpdir("enc-split-fixture");
    let ex = Extractor::new(&dir, vols.len(), true);
    ex.set_password("testpw123");
    for (si, (name, bytes)) in vols.iter().enumerate() {
        feed(&ex, si, name, bytes, 1400, 60 + si as u64);
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.decrypted, vec!["secret.bin".to_string()]);
    assert_eq!(std::fs::read(dir.join("secret.bin")).unwrap(), secret);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Damaged SPLIT ciphertext must fail its whole-file CRC. One flipped
/// byte in the middle volume's data area survives every other check
/// (the stored password check proves only the key), so this gate is
/// the only thing standing between wire damage and a silently corrupt
/// published file - and before the tail-piece CRC was wired into the
/// in-stream route, that route published this exact input on
/// completeness alone.
///
/// A hard error rather than a demote because the password IS proven
/// here: the key is right, so the plaintext under it is damage. The
/// unprovable twin of this shape demotes instead - see
/// `checkless_encrypted_store_set_wrong_password_demotes_not_publishes`.
#[test]
fn real_rar_split_damaged_ciphertext_fails() {
    let mut part2 = include_bytes!("../../testdata/rar5/enc-vols.part2.rar").to_vec();
    // Inside part2's data area (data_off 119, data_len 1790) - headers
    // and the stored check stay intact, only ciphertext is damaged.
    part2[119 + 800] ^= 0xff;
    {
        let vols: Vec<(&str, &[u8])> = vec![
            (
                "enc-vols.part1.rar",
                include_bytes!("../../testdata/rar5/enc-vols.part1.rar"),
            ),
            ("enc-vols.part2.rar", &part2),
            (
                "enc-vols.part3.rar",
                include_bytes!("../../testdata/rar5/enc-vols.part3.rar"),
            ),
        ];
        let dir = tmpdir("enc-split-damaged");
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_password("testpw123");
        for (si, (name, bytes)) in vols.iter().enumerate() {
            feed(&ex, si, name, bytes, 1400, 60 + si as u64);
        }
        let err = match ex.finish() {
            Err(e) => e,
            Ok(rep) => panic!("damaged split ciphertext published: {:?}", rep.decrypted),
        };
        assert!(err.to_string().contains("stored CRC"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// One article-by-article run that journals exactly like workers.rs,
/// over `arts` (index, start, end) of `vol`: an `R` for every plain
/// placement, a parked `D` flushed once its seam bytes settle. Returns
/// the ids recorded. Shared by the TODO 158 item 2 restart tests.
fn run_journaled(
    ex: &Extractor,
    journal: &crate::journal::Journal,
    vol: &[u8],
    arts: impl Iterator<Item = (usize, usize, usize)>,
) -> Vec<String> {
    let mut ids = Vec::new();
    let mut pending: Vec<(String, Vec<Frag>)> = Vec::new();
    for (i, s, e) in arts {
        let id = format!("<a{i}@t>");
        match ex
            .write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
            .unwrap()
        {
            Persist::Placed(frags) => {
                journal.record_placed(
                    0,
                    &id,
                    ex.slot_file_info(0),
                    "v.rar",
                    vol.len() as u64,
                    &frags,
                );
                ids.push(id);
            }
            Persist::PlacedCrypto(frags) => pending.push((id, frags)),
            Persist::No | Persist::Held(_) => {}
        }
        pending.retain(|(id, frags)| {
            if ex.crypto_span_on_disk(frags) {
                journal.record_crypto_events(&ex.drain_crypto_events());
                journal.record_placed_crypto(
                    0,
                    id,
                    ex.slot_file_info(0),
                    "v.rar",
                    vol.len() as u64,
                    frags,
                    &ex.crypto_frag_mask(frags),
                );
                ids.push(id.clone());
                false
            } else {
                true
            }
        });
    }
    ids
}

/// Replay a restore the way `get/rig.rs` does for a mapped resume: the
/// head article first (it was never journaled - the mapper consumed
/// it), then every restored span read from wherever the restore says
/// its bytes are and fed straight back through `write`. Exactly the
/// shape that never re-journals.
fn replay_restored(
    ex: &Extractor,
    dir: &std::path::Path,
    restored: &crate::journal::Restored,
    vol: &[u8],
    art: usize,
) {
    ex.seed_resumed_routes(&restored.wire_outputs, &restored.plaintext_outputs);
    for seed in &restored.seeds {
        ex.preclaim_name(seed.slot, &seed.name);
        for (file, _) in &seed.sources {
            if **file != *seed.name {
                ex.preclaim_name(seed.slot, file);
            }
        }
    }
    ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..art.min(vol.len())])
        .unwrap();
    for seed in &restored.seeds {
        let mut spans: Vec<(u64, u64, std::sync::Arc<str>, u64)> = seed
            .spans
            .iter()
            .enumerate()
            .map(|(i, &(off, len))| match seed.sources.get(i) {
                Some((f, fo)) => (off, len, f.clone(), *fo),
                None => (off, len, std::sync::Arc::from(seed.name.as_str()), off),
            })
            .collect();
        spans.sort_unstable();
        for (off, len, file, file_off) in spans {
            let src = std::fs::File::open(dir.join(&*file)).unwrap();
            let mut buf = vec![0u8; len as usize];
            crate::disk::read_exact_at(&src, &mut buf, file_off).unwrap();
            ex.write(0, "v.rar", vol.len() as u64, off, &buf).unwrap();
        }
    }
}

/// TODO 158 item 2 (closed 22 Aug 2026): the CIPHERTEXT route survives
/// a restart. The set here is `rar a -htb` shaped - a BLAKE2sp digest
/// and no CRC32 - which is the one shape `instream_decrypt_allowed`
/// still vetoes, so its output assembles posted ciphertext and journals
/// `R` records exactly as every encrypted set did before plaintext-once.
/// Run 1 is killed mid-write, run 2 resumes and is killed too, run 3
/// resumes and finishes: nothing may decrypt it in-stream on the way,
/// and the group demotes at finish to the disk path that CAN check a
/// digest this build cannot compute.
///
/// Before the fix run 2 latched plaintext-once over the resumed output
/// (both halves of rule 2 were empty on a fresh process), decrypted the
/// replayed spans in place, and re-recorded nothing: the `R` lines then
/// described plaintext as wire bytes, and run 3 restored them as such -
/// a mixed output that looked complete. The fix seeds the latch and the
/// counter from the journal before the first span, so a resumed wire
/// output can never take the other route, and the demoted volume is the
/// cold run's byte for byte. Run 1 used to force the route with
/// `NZBFAST_NO_INSTREAM_DECRYPT`; the digest shape stands in for it now
/// that the switch is gone, and it is the shape a resumed OLD journal
/// presents too.
#[test]
fn a_ciphertext_output_keeps_its_route_across_a_restart() {
    let plain = payload(1_200_003, 91);
    let mut f = fixtures::encrypt_file("hunter2", &plain, 93);
    f.with_hash = true;
    f.with_crc = false;
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let art = 50_000usize;
    let n = vol.len().div_ceil(art);
    let vlen = vol.len();
    let arts =
        move |lo: usize, hi: usize| (lo..hi).map(move |i| (i, i * art, ((i + 1) * art).min(vlen)));

    // The cold run: password from the start, never interrupted. It
    // demotes at finish (nothing here can adjudicate a BLAKE2sp digest)
    // and the volume it materializes is what the resumed runs must
    // reproduce byte for byte.
    let cold_dir = tmpdir("158-2-cold");
    let cold = {
        let ex = Extractor::new(&cold_dir, 1, true);
        ex.set_password("hunter2");
        feed(&ex, 0, "v.rar", &vol, art, 91);
        let rep = ex.finish().unwrap();
        assert!(!rep.fallbacks.is_empty(), "the digest set must demote");
        std::fs::read(cold_dir.join("v.rar")).unwrap()
    };
    assert_eq!(cold, vol);
    std::fs::remove_dir_all(&cold_dir).unwrap();

    let dir = tmpdir("158-2-cipher");
    // Run 1: the ciphertext route, killed after 60% of the articles.
    let cut1 = n * 6 / 10;
    let run1_ids = {
        let (journal, _) = crate::journal::Journal::open(&dir, b"nzb-158").unwrap();
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        let ids = run_journaled(&ex, &journal, &vol, arts(0, cut1));
        assert!(
            ex.inner.lock_ok().ciphertext_files.contains("movie.mkv"),
            "run 1 committed the output to the ciphertext route"
        );
        ids
    };
    assert!(
        run1_ids.len() > 3,
        "run 1 journaled R records: {}",
        run1_ids.len()
    );
    let on_disk = std::fs::read(dir.join("movie.mkv")).unwrap();
    assert_ne!(&on_disk[..art], &plain[..art], "run 1 left ciphertext");

    // Run 2: resume, replay, write 20% more, killed again without
    // finish.
    let cut2 = n * 8 / 10;
    {
        let (journal, resume) = crate::journal::Journal::open(&dir, b"nzb-158").unwrap();
        let restored = crate::journal::restore_for(&dir, &resume, Some("hunter2"), false);
        for id in &run1_ids {
            assert!(restored.ids.contains(id), "{id} restores");
        }
        assert!(
            restored.wire_outputs.contains_key("movie.mkv"),
            "the journal derives the wire route: {:?}",
            restored.wire_outputs
        );
        assert!(restored.plaintext_outputs.is_empty());
        let ex = Extractor::with_resume(&dir, 1, true, true);
        ex.set_password("hunter2");
        replay_restored(&ex, &dir, &restored, &vol, art);
        {
            let inner = ex.inner.lock_ok();
            assert!(
                inner.ciphertext_files.contains("movie.mkv"),
                "the resumed output is latched ciphertext before its first span"
            );
            assert!(
                !inner.crypto_files.contains_key("movie.mkv"),
                "plaintext-once must never latch over a resumed wire output"
            );
            let w = inner
                .inner_writers
                .get("movie.mkv")
                .expect("resumed inner writer");
            assert!(w.written() > 0, "the write counter is non-empty on resume");
        }
        run_journaled(&ex, &journal, &vol, arts(cut1, cut2));
    }

    // Run 3: resume and finish.
    {
        let (journal, resume) = crate::journal::Journal::open(&dir, b"nzb-158").unwrap();
        let restored = crate::journal::restore_for(&dir, &resume, Some("hunter2"), false);
        let ex = Extractor::with_resume(&dir, 1, true, true);
        ex.set_password("hunter2");
        replay_restored(&ex, &dir, &restored, &vol, art);
        run_journaled(&ex, &journal, &vol, arts(cut2, n));
        let rep = ex.finish().unwrap();
        assert!(!rep.fallbacks.is_empty(), "the digest set must demote");
        assert!(rep.decrypted.is_empty(), "{:?}", rep.decrypted);
    }
    assert_eq!(
        std::fs::read(dir.join("v.rar")).unwrap(),
        cold,
        "the resumed volume must be byte-identical to the cold run"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The other direction of TODO 158 item 2: a PLAINTEXT-ONCE output
/// survives a restart. Run 1 decrypts in-stream and journals `D`
/// records; run 2 resumes and must re-latch plaintext-once on the same
/// head record - and when it cannot, it must REFUSE the write rather
/// than put ciphertext under records that say plaintext. The refusal
/// arm below seeds a head record the journal's `E` fact does not name
/// (a different salt and IV), which is the gate's own disqualifier and
/// stands in for any answer that differs; it used to switch in-stream
/// decrypt off, and that switch is gone.
#[test]
fn a_plaintext_once_output_keeps_its_route_across_a_restart() {
    let plain = payload(1_100_007, 94);
    let f = fixtures::encrypt_file("hunter2", &plain, 95);
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let art = 50_000usize;
    let n = vol.len().div_ceil(art);
    let vlen = vol.len();
    let arts =
        move |lo: usize, hi: usize| (lo..hi).map(move |i| (i, i * art, ((i + 1) * art).min(vlen)));
    let dir = tmpdir("158-2-plain");
    let cut = n * 6 / 10;
    let run1_ids = {
        let (journal, _) = crate::journal::Journal::open(&dir, b"nzb-158p").unwrap();
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        let ids = run_journaled(&ex, &journal, &vol, arts(0, cut));
        assert!(ex.inner.lock_ok().crypto_files.contains_key("movie.mkv"));
        ids
    };
    assert!(run1_ids.len() > 3, "run 1 journaled D records");
    assert_eq!(
        &std::fs::read(dir.join("movie.mkv")).unwrap()[..art],
        &plain[..art]
    );

    // Derivation: a wrong password admits nothing and pins nothing.
    {
        let (_j, resume) = crate::journal::Journal::open(&dir, b"nzb-158p").unwrap();
        let wrong = crate::journal::restore_for(&dir, &resume, Some("wrong"), false);
        assert!(wrong.ids.is_empty());
        assert!(
            wrong.plaintext_outputs.is_empty(),
            "an unadmitted D pins no route"
        );
        assert!(!wrong.wire_outputs.contains_key("movie.mkv"));
    }

    // Refusal arm: the resumed run cannot re-establish the route - the
    // seeded `(salt, iv)` is not this archive's, so the gate refuses to
    // confirm the recorded route. The first span routed into the output
    // (the head article carries data past its headers) must be refused,
    // the plaintext on disk untouched, nothing latched either way.
    {
        let (_j, resume) = crate::journal::Journal::open(&dir, b"nzb-158p").unwrap();
        let restored = crate::journal::restore_for(&dir, &resume, Some("hunter2"), false);
        assert_eq!(
            restored.plaintext_outputs.get("movie.mkv"),
            Some(&(f.salt, f.iv)),
            "an admitted D pins plaintext-once under the E record's keys"
        );
        let ex = Extractor::with_resume(&dir, 1, true, true);
        ex.set_password("hunter2");
        let elsewhere = HashMap::from([("movie.mkv".to_string(), ([0xAAu8; 16], [0xBBu8; 16]))]);
        ex.seed_resumed_routes(&restored.wire_outputs, &elsewhere);
        let err = match ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..art]) {
            Err(e) => e,
            Ok(_) => panic!("ciphertext over a resumed plaintext-once output must be refused"),
        };
        assert!(
            err.to_string().contains("refusing to write ciphertext"),
            "{err}"
        );
        let inner = ex.inner.lock_ok();
        assert!(!inner.ciphertext_files.contains("movie.mkv"));
        assert!(!inner.crypto_files.contains_key("movie.mkv"));
    }
    assert_eq!(
        &std::fs::read(dir.join("movie.mkv")).unwrap()[..art],
        &plain[..art],
        "a refused write lands nothing"
    );

    // The real resume: re-latches plaintext-once on the journaled head
    // record, replays, finishes byte-exact.
    {
        let (journal, resume) = crate::journal::Journal::open(&dir, b"nzb-158p").unwrap();
        let restored = crate::journal::restore_for(&dir, &resume, Some("hunter2"), false);
        for id in &run1_ids {
            assert!(restored.ids.contains(id), "{id} restores");
        }
        let ex = Extractor::with_resume(&dir, 1, true, true);
        ex.set_password("hunter2");
        replay_restored(&ex, &dir, &restored, &vol, art);
        {
            let inner = ex.inner.lock_ok();
            assert!(
                inner.crypto_files.contains_key("movie.mkv"),
                "re-latched plaintext-once"
            );
            assert!(!inner.ciphertext_files.contains("movie.mkv"));
        }
        // The frontier articles whose D never settled in run 1 are not
        // in `completed`, so the pool refetches them; then the rest.
        let refetch = arts(1, cut).filter(|(i, _, _)| !run1_ids.contains(&format!("<a{i}@t>")));
        run_journaled(&ex, &journal, &vol, refetch.chain(arts(cut, n)));
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    }
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A journal that claims one file under BOTH routes - an `E`+`D` and an
/// `R` naming it - can only come from a binary without the fix (a run
/// that wrote ciphertext over plaintext and recorded neither change).
/// Its bytes may be either domain, so the `D` articles must refuse
/// admission: re-encrypting ciphertext poisons a volume exactly as
/// copying plaintext would. The file is then a wire output, never a
/// plaintext-once one.
#[test]
fn a_file_the_journal_claims_under_both_routes_refetches_its_d_articles() {
    let dir = tmpdir("158-2-contradiction");
    std::fs::write(dir.join("movie.mkv"), payload(200_000, 5)).unwrap();
    std::fs::write(dir.join("v.rar"), payload(200_000, 6)).unwrap();
    let salt = "00".repeat(16);
    let text = format!(
        "nzbfast-journal v1 d41d8cd98f00b204e9800998ecf8427e\n\
         S 0 200000 v.rar\n\
         F 0 movie.mkv\n\
         E {salt} 12 {salt} 150000 - movie.mkv\n\
         D 0 0:0:5000:32768 <a1@t>\n\
         R 0 0:40000:45000:32768 <a2@t>\n"
    );
    std::fs::write(dir.join(".nzbfast.journal"), text).unwrap();
    let (_j, resume) = crate::journal::Journal::open(&dir, b"").unwrap();
    assert!(resume.crypto_files.contains_key("movie.mkv"), "E parsed");
    let restored = crate::journal::restore_for(&dir, &resume, Some("pw"), false);
    assert!(
        !restored.ids.contains("<a1@t>"),
        "the D article must refetch"
    );
    assert!(
        restored.ids.contains("<a2@t>"),
        "the R article restores as before"
    );
    assert!(restored.plaintext_outputs.is_empty());
    assert_eq!(restored.wire_outputs.get("movie.mkv"), Some(&32768));
    std::fs::remove_dir_all(&dir).unwrap();
}
