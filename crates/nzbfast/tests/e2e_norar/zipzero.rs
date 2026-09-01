//! Wave-4 matrix-read, THIRD extreme pass: rows M4-39 and M4-40.
//!
//! The archive that IS the deliverable, and the junk file the sliding
//! scan's virtual zero padding turned into a donor. Both rows were
//! PREDICTIONS and both were measured on the 30 Aug 2026 baseline before
//! an assertion was written: M4-39 came back GREEN and lands as a pass
//! pin with the measurement that falsifies it, M4-40 came back RED and
//! lands with its fix (`nzbkit::par2repair::adopt::scan_candidate`).
//!
//! A CHILD of `e2e_norar` rather than a sibling of it, for `pins.rs`'s
//! reason word for word: a child sees the parent's builders through
//! `use super::*` where a sibling directory would need every one of them
//! made `pub(crate)` on lines other M4 lanes are also editing.

use super::*;

/// M4-39 - a FileDesc names a zip we then extract. The row predicted
/// "extract and spend, then a missing-file warning or a false green":
/// settle verifies `photos.zip` under its FileDesc, `finish` unpacks it,
/// and the closed world is left with the zip gone, the inners extra and
/// the descriptor unsatisfied.
///
/// MEASURED GREEN, 30 Aug 2026, and the reason is an ordering the row
/// could not see from outside: the FileDesc is satisfied ON THE WIRE,
/// not on disk. The set goes live while the articles are still
/// arriving, every block of the archive is checked in-stream against
/// the IFSC as it passes through the mapper, and only then do those
/// same bytes become inner members. So there is no unsatisfied
/// descriptor at the end to warn about and no false green to give: the
/// archive was proven byte-exact, and what the job publishes is its
/// contents, which is the deliberate one-pass container contract
/// (`e2e::top_level_zip_extracts_one_pass` pins the same architecture
/// from the extraction side).
///
/// Landed anyway, and not as a duplicate of that pin: this asks the
/// PAR2 question that one does not - was the container's own descriptor
/// honoured before its bytes were consumed - and it asks it of a
/// two-member STORE zip, the shape the row named. The load-bearing
/// assertion is the in-stream verify line: an engine that started
/// unpacking BEFORE the set could check the archive would still land
/// both members and still exit 0, and only that line would move.
#[tokio::test(flavor = "multi_thread")]
async fn a_filedesc_named_zip_is_verified_before_its_bytes_are_unpacked() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarzipdeliv");
    let a = b"alpha text file, the first member\n".repeat(40);
    let b = b"beta text file, the second member\n".repeat(40);
    let arch = nzbkit::zip::fixtures::zip_of(&[
        nzbkit::zip::fixtures::Spec::stored("alpha.txt", &a),
        nzbkit::zip::fixtures::Spec::stored("beta.txt", &b),
    ]);
    fx.add_file("photos.zip", &arch, 40_000);
    assert!(fx.add_par2(20, &["photos.zip"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "zip-as-deliverable post failed:\n{log}");
    // The descriptor was HONOURED, in-stream, before extraction spent
    // the bytes - this is the whole row.
    assert!(
        log.contains("verified 1 file(s)") && log.contains("blocks in-stream"),
        "the archive's own FileDesc was never checked against the wire \
         bytes - the unpack ran ahead of the recovery set\n{log}"
    );
    assert!(
        log.contains("clean download"),
        "no clean verdict for a post whose only FileDesc verified\n{log}"
    );
    // ...and the members are the payload, byte-exact. "Neither the zip
    // nor matching inners" was the predicted harm; the inners match.
    for (name, want) in [("alpha.txt", &a), ("beta.txt", &b)] {
        let got = std::fs::read(out.join(name))
            .unwrap_or_else(|e| panic!("{name} missing from the unpacked zip: {e}\n{log}"));
        assert!(got == *want, "{name} is not byte-exact\n{log}");
    }
    // The container itself never touching disk is the one-pass contract,
    // pinned here so a "fix" that keeps the archive to satisfy a census
    // has to argue with this row rather than land quietly.
    assert!(
        !out.join("photos.zip").exists(),
        "the mapped container was materialized after all\n{log}"
    );
}

/// M4-39's sharper half, and the shape the row's "or REMAINING FileDesc"
/// clause is really about: the same mapped zip, but a SIBLING payload in
/// the same recovery set arrives damaged, so a real repair pass runs
/// while the archive is not on disk.
///
/// This is where a container excused from the census could plausibly go
/// wrong - the repair walks the directory, finds no `photos.zip`, and
/// could price it wholly missing and take the job down with it. MEASURED
/// GREEN: the sibling repairs from parity, the archive stays mapped, and
/// the members still land. Nothing in the existing zip pins covers a
/// repair running against a set that includes a mapped container.
#[tokio::test(flavor = "multi_thread")]
async fn a_mapped_zip_survives_a_repair_of_its_sibling_in_the_same_set() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarzipsib");
    let a = b"alpha text file, the first member\n".repeat(40);
    let b = b"beta text file, the second member\n".repeat(40);
    let arch = nzbkit::zip::fixtures::zip_of(&[
        nzbkit::zip::fixtures::Spec::stored("alpha.txt", &a),
        nzbkit::zip::fixtures::Spec::stored("beta.txt", &b),
    ]);
    let movie = payload(120_000, 93);
    fx.add_file("photos.zip", &arch, 40_000);
    fx.add_file("movie.bin", &movie, 40_000);
    // An explicit block size: left to par2cmdline the two-file set picks
    // a 64-byte block, one corrupt article is then 625 bad blocks, and
    // the row measures nothing but a recovery shortfall.
    assert!(fx.add_par2_opts(30, Some(20_000), &["photos.zip", "movie.bin"], 40_000));
    let chaos = Chaos {
        corrupt: HashSet::from([String::from("<movie_bin-1-2@mock>")]),
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(
        ok,
        "a repair of one member took the whole set down while the other \
         member was a mapped container:\n{log}"
    );
    let got = std::fs::read(out.join("movie.bin"))
        .unwrap_or_else(|e| panic!("the damaged sibling never landed: {e}\n{log}"));
    assert!(
        got == movie,
        "the repaired sibling is not byte-exact\n{log}"
    );
    for (name, want) in [("alpha.txt", &a), ("beta.txt", &b)] {
        let got = std::fs::read(out.join(name))
            .unwrap_or_else(|e| panic!("{name} missing after the repair pass: {e}\n{log}"));
        assert!(got == *want, "{name} is not byte-exact\n{log}");
    }
    assert!(
        !log.contains("materializing volumes for repair"),
        "the mapped container was written to disk to satisfy a repair \
         that never needed its blocks\n{log}"
    );
}

/// M4-40 - the virtual zero padding as a source of arbitrary zero
/// slices. `sliding_scan` runs `bs - 1` virtual zeros past a candidate's
/// EOF so a PAR2 tail slice, whose checksum covers zero padding, is
/// findable at end-of-file. A one-byte `0x00` file therefore yields
/// exactly one window - all zeros - and could donate any all-zero block
/// of any target.
///
/// RED on origin/main, and the harm is destructive rather than cosmetic.
/// `Zero.Tail.bin` is covered by the set and never posted, so both its
/// blocks are wanted; the payload block needs the one recovery block and
/// the all-zero tail block was taken from the decoy, which the log named
/// outright - `1 block(s) adopted from Zq4zeroDecoyX`. `proven_spent`'s
/// fully-donated arm is then satisfied by definition, because one
/// adoption covers every byte of a one-byte file, and the run ended
/// `removed 1 spent source file(s)`: a junk file the poster put in the
/// NZB, deleted, on the strength of a block the scan invented.
///
/// The fix bounds the padding rather than removing it (see
/// `nzbkit::par2repair::adopt::scan_candidate`): a window carrying
/// virtual bytes may only claim a slice whose OWN zero padding is at
/// least that long, so every manufactured byte lands where the slice has
/// padding anyway and stands in for nothing. Afterwards the tail block
/// is no longer adoptable from the decoy, one recovery block cannot
/// cover two missing ones, and the job says so - which is the outcome
/// the row asks for over a green built on fabricated bytes.
///
/// A `.par2`-covered-but-unposted file rather than a damaged one, and
/// that is the whole reason the fixture is shaped this way: an ARTICLE
/// that fails leaves a hole, a hole reads as zeros, and an all-zero
/// block then verifies PRESENT off the target's own file - so the slice
/// never enters the want set and the decoy is never consulted. The only
/// way an all-zero block is genuinely missing is a file that is not
/// there at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_one_byte_zero_decoy_never_donates_a_full_all_zero_block() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarzerodecoy");
    let mut data = vec![0u8; 40_000];
    data[..20_000].copy_from_slice(&payload(20_000, 91));
    std::fs::write(fx.dir.join("Zero.Tail.bin"), &data).unwrap();
    fx.add_file_obfuscated("Zq4zeroDecoyX", "Zq4zeroDecoyX", &[0u8], 40_000);
    // Two blocks, one recovery block: the repair can only finish if
    // something donates the other, and the decoy is the only candidate.
    assert!(fx.add_par2_opts(50, Some(20_000), &["Zero.Tail.bin"], 40_000));
    let (log, _ok, out) = run_norar(&fx).await;
    assert!(
        !log.contains("adopted from Zq4zeroDecoyX"),
        "a full all-zero block was taken from a one-byte file - the \
         padding manufactured 19,999 bytes of it\n{log}"
    );
    assert!(
        out.join("Zq4zeroDecoyX").exists(),
        "the one-byte decoy was swept as a fully-donated source\n{log}"
    );
    assert!(
        !log.contains("repair complete"),
        "the repair reported success on a file whose second block only \
         ever existed as scan padding\n{log}"
    );
}

/// The control the row above needs: the bound must not make an all-zero
/// block unadoptable, only unadoptable from a candidate that does not
/// hold it. Same fixture, with the decoy grown from one byte to a full
/// block of REAL zeros - bytes the file actually has - and the repair
/// completes off it.
///
/// Without this arm, "never adopt zeros" would pass the row above and be
/// a strictly worse engine.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_block_of_zeros_still_donates_an_all_zero_block() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarzerodonor");
    let mut data = vec![0u8; 40_000];
    data[..20_000].copy_from_slice(&payload(20_000, 91));
    std::fs::write(fx.dir.join("Zero.Tail.bin"), &data).unwrap();
    fx.add_file_obfuscated("Wm7zeroDonorY", "Wm7zeroDonorY", &vec![0u8; 20_000], 40_000);
    assert!(fx.add_par2_opts(50, Some(20_000), &["Zero.Tail.bin"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(
        ok,
        "a candidate holding the all-zero block in real bytes could not \
         donate it:\n{log}"
    );
    let got = std::fs::read(out.join("Zero.Tail.bin"))
        .unwrap_or_else(|e| panic!("the rebuilt file is missing: {e}\n{log}"));
    assert!(got == data, "the rebuilt file is not byte-exact\n{log}");
}
