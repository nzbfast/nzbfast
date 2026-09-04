//! The repost table's round trip (W7-04): poison a content fingerprint
//! with a name, then arrive with the SAME bytes and see what you are
//! told.
//!
//! `par_hashes` is the only naming tier in this product with MEMORY -
//! it maps a content fingerprint to a name, persistently, across jobs -
//! and it is the only one that never declined ambiguity. Every in-job
//! tier treats a contested answer as a refusal (the rule stated in
//! `live.rs`, `sfvname.rs` and `emptydesc.rs` alike); this one answered,
//! from whichever job happened to write first, forever.
//!
//! These drive the whole trip through [`Daemon::resolve_identity`]
//! rather than through the table's own API, because the interesting
//! half is what a REPOST is told: the teach and the lookup are two
//! different call sites and only the round trip holds them together.

use super::super::*;

/// The par2cmdline output nzbkit's own parser tests use, so the two
/// cannot drift. One member, `beta.bin`, declared past
/// `member_hash16k`'s 16 KiB floor - so one fingerprint, which is all
/// a twin needs.
const TESTSET: &[u8] = include_bytes!("../../../nzbkit-base/tests/fixtures/par2/testset.par2");

pub fn with_daemon(name: &str, f: impl FnOnce(&Arc<Daemon>, &std::path::Path)) {
    let dir = std::env::temp_dir().join(format!("nzbfast-repost-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = super::super::testutil::test_daemon(&dir);
    // The table lives in the index database, so the lane has to be on
    // for any of this to happen at all.
    d.index_enabled.store(true, Ordering::Relaxed);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).expect("create out root");
    *d.out_root.write_ok() = out.clone();
    f(&d, &out);
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A finished job's output directory carrying the shared sidecar: the
/// same fingerprint every time, which is exactly the identical-head
/// twin family the corpus already knows `hash16k` cannot separate.
fn finished(out_root: &std::path::Path, name: &str) -> std::path::PathBuf {
    let dir = out_root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("testset.par2"), TESTSET).unwrap();
    dir
}

/// What the repost table would tell an obfuscated arrival of these
/// bytes: the identity resolve, driven end to end.
fn arrive(d: &Arc<Daemon>, out: &std::path::Path, posted: &str) -> crate::identity::Identity {
    let dir = finished(out, posted);
    crate::naming::resolve_identity(d, &format!("nzo_{posted}"), &dir, posted, 0)
}

/// An obfuscated stem, so the arrival ASKS the table rather than
/// answering out of its own name.
const OBFUSCATED: &str = "8a7f2c1b9d0e4f11";

/// Two jobs name one fingerprint two different things. Neither has
/// better evidence than the other, so the fingerprint is not an answer
/// and the repost must be told nothing - the same refusal every in-job
/// tier makes on the same ambiguity.
#[test]
fn a_fingerprint_two_jobs_named_differently_answers_a_repost_nothing() {
    with_daemon("contested", |d, out| {
        assert!(
            arrive(d, out, "Alpha.Movie.2019.1080p").name.is_empty(),
            "a job that can name itself takes no name from the table"
        );
        arrive(d, out, "Beta.Show.2021.1080p");
        let repost = arrive(d, out, OBFUSCATED);
        assert_eq!(
            repost.name, "",
            "one fingerprint claimed by two names is not an answer, \
             yet the repost was handed {:?} via {}",
            repost.name, repost.src
        );
    });
}

/// The uncontested case still works: one job names a fingerprint, the
/// repost of the same bytes is told. Guards the fix above from being
/// "decline everything".
#[test]
fn an_uncontested_fingerprint_still_names_its_repost() {
    with_daemon("plain", |d, out| {
        arrive(d, out, "Alpha.Movie.2019.1080p");
        let repost = arrive(d, out, OBFUSCATED);
        assert_eq!(repost.name, "Alpha.Movie.2019.1080p");
        assert_eq!(repost.src, "par-hash");
    });
}

/// W7-01: the correction round trip. A weak lane names a fingerprint
/// wrongly; the payload's own bytes later say otherwise; the repost is
/// told the CORRECTED name. The table used to be first-writer-wins
/// forever, so the repost was handed the wrong name for good - and
/// nothing anywhere reported the disagreement.
///
/// The proof is written straight through the index rather than by
/// driving `pesto_confirm`: what matters here is that a repost READS
/// the corrected row, and the lane that produced the proof is that
/// function's own end-to-end test (`index::pesto::tests`).
#[test]
fn a_later_proof_corrects_what_the_repost_is_told() {
    with_daemon("corrected", |d, out| {
        arrive(d, out, "Wrong.Movie.2019.1080p");
        assert_eq!(
            arrive(d, out, OBFUSCATED).name,
            "Wrong.Movie.2019.1080p",
            "the poisoned row is what a repost is told before the proof"
        );

        // The bytes' own answer, at the tier `pesto_confirm` writes.
        let prints = crate::identity::par_sidecar(&out.join(OBFUSCATED))
            .expect("the sidecar the arrivals fingerprinted")
            .pairs;
        let wrote = d
            .with_index_for_tail("nzo_proof", |ix| {
                ix.par_hash_remember(
                    &prints,
                    "Real.Movie.2019.1080p",
                    "m:real movie:2019",
                    9_000,
                    nzbkit::index::NameEvidence::Par2SetId,
                )
                .ok()
            })
            .expect("the index lane must be open");
        assert_eq!(wrote, prints.len(), "a proof must correct every member");

        let repost = arrive(d, out, "1c0ffee2deadbeef");
        assert_eq!(repost.name, "Real.Movie.2019.1080p");
        assert_eq!(repost.src, "par-hash");
    });
}

/// A finished directory carrying a synthetic set whose members'
/// fingerprints are chosen here, so two sets can be made to share
/// EXACTLY ONE of them - one collision, nothing to disagree with, which
/// is the only shape in which the echo fires at all.
fn finished_set(out_root: &std::path::Path, name: &str, set: u8, h: &[u8]) -> std::path::PathBuf {
    let dir = out_root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let members: Vec<(String, u8)> = h
        .iter()
        .enumerate()
        .map(|(i, b)| (format!("m{i}.rar"), *b))
        .collect();
    let refs: Vec<(&str, u8)> = members.iter().map(|(n, b)| (n.as_str(), *b)).collect();
    let bytes = crate::identity::testkit::par2_index_hashed(set, &refs, 4096);
    std::fs::write(dir.join("release.par2"), bytes).unwrap();
    dir
}

/// The storage form of a fingerprint built from one repeated byte.
fn fp(b: u8) -> String {
    format!("{b:02x}").repeat(16)
}

/// What the table now holds against one fingerprint, by name. `None`
/// is "nobody claimed it" - and also "the index lane was shut", which
/// is why every use of it below is paired with a probe that must answer.
fn probe(d: &Arc<Daemon>, b: u8) -> Option<String> {
    d.with_index_for_tail("nzo_probe", |ix| {
        ix.par_hash_lookup(&[(fp(b), "m.rar".into())])
            .ok()
            .flatten()
    })
    .map(|(_, n, _)| n)
}

/// W7-14: the table may not teach its OWN answer back onto fingerprints
/// that never corroborated it.
///
/// Release X is named and files three fingerprints. Release Z then
/// arrives obfuscated sharing exactly ONE of them - a 16 KiB head
/// collision, not a repost - so the lookup answers "X" with nothing to
/// disagree with. The teach then ran over the SAME `prints` vector the
/// lookup was given, and filed Z's other two fingerprints, which no
/// bytes of X have ever been near, under X's name.
///
/// W7-01..04 bounded that and did not close it: those rows land at
/// `Hash16kLen`, so an honest weak naming of Z later is EQUAL rank and
/// can only CONTEST them, never correct them - a release nothing ever
/// proves ends up with refused fingerprints rather than right ones.
#[test]
fn the_table_does_not_teach_its_own_answer_onto_uncorroborated_prints() {
    with_daemon("echo", |d, out| {
        // X names three fingerprints of its own.
        let x = finished_set(out, "Alpha.Movie.2019.1080p", 0x22, &[0xa0, 0xa1, 0xa2]);
        crate::naming::resolve_identity(d, "nzo_x", &x, "Alpha.Movie.2019.1080p", 0);

        // Z shares only a0. The lookup must still ANSWER - one hit, no
        // disagreement - or this test proves nothing about the teach.
        let z = finished_set(out, OBFUSCATED, 0x33, &[0xa0, 0xb1, 0xb2]);
        let told = crate::naming::resolve_identity(d, "nzo_z", &z, OBFUSCATED, 0);
        assert_eq!(told.src, "par-hash", "the echo path must be reached");
        assert_eq!(told.name, "Alpha.Movie.2019.1080p");

        // The lane has to be OPEN for the next assertion to mean
        // anything: `with_index_for_tail` answers `None` for a wedged
        // index exactly as it does for a fingerprint nobody claimed, so
        // without this the whole test passes on a closed lane.
        assert_eq!(
            probe(d, 0xa0).as_deref(),
            Some("Alpha.Movie.2019.1080p"),
            "the shared fingerprint is what the lookup answered off"
        );
        // Z's OWN fingerprints must still be unclaimed.
        for b in [0xb1u8, 0xb2] {
            let got = probe(d, b);
            assert!(
                got.is_none(),
                "one collision spread {got:?} onto {}, a fingerprint of a release \
                 nothing has ever named",
                fp(b)
            );
        }
    });
}

/// The half that must NOT be given up. A job named from its own .nzb -
/// `id.src` empty, the common good case the 2026-07-28 gap analysis
/// argues this table exists for - still teaches every one of its
/// fingerprints, so its later obfuscated repost is told.
#[test]
fn a_job_that_named_itself_still_teaches_every_fingerprint() {
    with_daemon("selfnamed", |d, out| {
        let x = finished_set(out, "Alpha.Movie.2019.1080p", 0x22, &[0xa0, 0xa1, 0xa2]);
        let own = crate::naming::resolve_identity(d, "nzo_x", &x, "Alpha.Movie.2019.1080p", 0);
        assert_eq!(own.src, "", "a readable stem takes no name from anywhere");
        for b in [0xa0u8, 0xa1, 0xa2] {
            assert_eq!(
                probe(d, b).as_deref(),
                Some("Alpha.Movie.2019.1080p"),
                "the teach must still cover every member of a job it could name"
            );
        }
    });
}
