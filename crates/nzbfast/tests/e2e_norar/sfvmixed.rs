//! Matrix row M4-05: the zero-byte placeholder tier on the WITH-SET
//! path, and the veto that makes it safe there.
//!
//! `get::sfvempty` materializes the file behind a checksum-sidecar entry
//! that declares the checksum of the empty input, because that value is
//! a constant of the hash function and so proves itself. It shipped
//! (M4-07) gated to the NO-SET path by a per-JOB test in its caller,
//! standing in for a real hazard: `00000000` is a legal 8-hex CRC field
//! that a lazy or hostile generator emits for a file it never
//! checksummed, and with a set present that lets a sidecar manufacture a
//! 0-byte file over a descriptor declaring gigabytes - at the very end
//! of settle, after the repair decision, where nothing downstream
//! contradicts it.
//!
//! M4-05 is the shape that gate refuses along with the hazard: a MIXED
//! post, PAR2 over some files and the sidecar over the rest, with the
//! sidecar-only ones legitimately empty. There the set present has
//! nothing to do with the placeholder. Measured RED on origin/main at
//! 10cb0ad77 before a line was changed - the job completes at rc 0, the
//! placeholder is simply absent, and NOTHING in the log mentions it,
//! which is the silent miss the row forbids.
//!
//! So the gate is now a per-ENTRY veto on the question the hazard
//! actually asks: decline any name a descriptor in this post declares at
//! a NONZERO length. The two tests here are the two halves of that and
//! are a PAIR, verified by mutation against the real tree to separate
//! all three states the caller can be in: with the per-job gate restored
//! BOTH go red, with the veto deleted only the second does, and only the
//! shipped answer is green on both. The second is not satisfiable by "the
//! tier never fires", which is what its log assertion buys - a decline
//! has to be SAID, so a tier that is simply switched off fails it too.
//!
//! `the_sfv_zero_byte_tier_does_not_fire_when_a_set_is_present` used to
//! live in the parent and is GONE rather than moved: its fixture is
//! M4-05's own shape (a healthy set, and a placeholder no descriptor
//! mentions), so it asserted the absence this row exists to fix. What it
//! was really guarding is kept and sharpened by the veto test below,
//! which puts a descriptor ON the contested name instead of merely
//! putting a set in the post.
//!
//! A CHILD of `e2e_norar` rather than a sibling directory, for `pins.rs`'s
//! reason word for word: a child sees the parent's builders through
//! `use super::*` where a sibling would need every one of them made
//! `pub(crate)` on lines other M4 lanes are also editing.

use super::*;

/// M4-05, the capability. PAR2 over the feature, a `.sfv` over both it
/// and a disc placeholder no descriptor mentions, and the placeholder is
/// materialized.
///
/// The set here is HEALTHY and covers the payload, so the only thing
/// standing between this post and its placeholder was the per-job gate.
/// The payload assertions are not decoration: they are what says the run
/// reached the tier at all rather than failing somewhere earlier for an
/// unrelated reason, which a bare `.exists()` on the placeholder cannot
/// distinguish.
#[tokio::test(flavor = "multi_thread")]
async fn m4_05_a_mixed_post_materializes_its_sidecar_only_placeholder() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarsfvmixed");
    let data = payload(60_000, 95);
    fx.add_file_renamed_by_par2("Real.Feature.mkv", "Ld3pQv66JcM", &data, 40_000);
    assert!(add_par2_named(
        &mut fx,
        "withset",
        &["Real.Feature.mkv"],
        40_000,
        false
    ));
    let sfv = format!(
        "Real.Feature.mkv {:08X}\r\nVIDEO_TS/VTS_02_0.VOB 00000000\r\n",
        crc32fast::hash(&data)
    );
    fx.add_file("release.sfv", sfv.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "mixed sfv post failed outright:\n{log}");
    let got = std::fs::read(out.join("Real.Feature.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its set name: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
    let made = out.join("VIDEO_TS").join("VTS_02_0.VOB");
    let meta = std::fs::metadata(&made).unwrap_or_else(|e| {
        panic!(
            "the sidecar-only placeholder was not materialized on the with-set path \
             ({e}) - M4-05's mixed shape is still refused; tree: {:?}\n{log}",
            out_tree(&out)
                .into_iter()
                .map(|(n, b)| (n, b.len()))
                .collect::<Vec<_>>()
        )
    });
    assert_eq!(meta.len(), 0, "the placeholder is not empty\n{log}");
}

/// The veto, from the side that costs the user if it is missing: a
/// descriptor declares `Missing.Feature.mkv` with bytes in it, the post
/// never delivers it and no parity can rebuild it, and a sidecar claims
/// it is empty. Nothing may be created at that name.
///
/// This is the hazard the per-job gate stood in for, asked as the
/// question it actually is - and the fixture is deliberately the WORST
/// case rather than the mildest: the file is genuinely gone, so the tier
/// is not merely wrong about a file that happens to exist, it is the
/// only thing that would put anything at that path. Creating it turns a
/// job that correctly failed into a directory holding a 0-byte "movie".
///
/// The verdict is red either way - `sfvempty` runs after it - so the
/// assertion is about the FILE and about the post-mortem being HONEST:
/// the log has to say the post contradicts itself, because the row is
/// explicit that this tier's wrong answer is an honest miss and never a
/// silent one.
#[tokio::test(flavor = "multi_thread")]
async fn a_placeholder_a_descriptor_declares_with_bytes_is_never_created() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarsfvveto");
    let kept = payload(60_000, 95);
    let gone = payload(400_000, 41);
    fx.add_file_renamed_by_par2("Real.Feature.mkv", "Ld3pQv66JcM", &kept, 40_000);
    // On disk for `par2 create` to describe, and never posted - so the
    // set declares it at 400 kB and no article in the job carries a byte
    // of it. At -r20 over 460 kB there is nowhere near the parity to
    // rebuild a whole 400 kB member, which is what makes this the
    // "repair could not rebuild it" case rather than a repairable one.
    std::fs::write(fx.dir.join("Missing.Feature.mkv"), &gone).unwrap();
    assert!(add_par2_named(
        &mut fx,
        "withset",
        &["Real.Feature.mkv", "Missing.Feature.mkv"],
        40_000,
        false
    ));
    let sfv = format!(
        "Real.Feature.mkv {:08X}\r\nMissing.Feature.mkv 00000000\r\n",
        crc32fast::hash(&kept)
    );
    fx.add_file("release.sfv", sfv.as_bytes(), 40_000);
    let (log, _ok, out) = run_norar(&fx).await;
    assert!(
        !out.join("Missing.Feature.mkv").exists(),
        "a sidecar manufactured a 0-byte file over a descriptor that declares it at \
         400 kB and that no parity in the post can rebuild - a failed job now holds a \
         truncated file under the name of the thing it failed to deliver; tree: {:?}\n{log}",
        out_tree(&out)
            .into_iter()
            .map(|(n, b)| (n, b.len()))
            .collect::<Vec<_>>()
    );
    assert!(
        log.contains("this post contradicts itself, so no placeholder was created"),
        "the decline was silent - the row requires this tier's wrong answer to be an \
         honest miss, and a miss nobody is told about is the defect it was written \
         against\n{log}"
    );
}
