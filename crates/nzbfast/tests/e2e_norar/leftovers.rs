//! Wave-4 rows M4-52, M4-53 and M4-82: what may be treated as
//! disposable, or as already claimed, on the strength of a NAME.
//!
//! Two ends of one question, which is why they are one lane. M4-52 is
//! the `has_unclaimed` door in `get::latesets` declining to look at a
//! leftover because its name ends `.par2` - so the late-set pass that
//! would have given it a real name never runs. M4-53 is the sniffed
//! leftover sweep in `get::tail` deleting a hash-named file because no
//! FileDesc names it - the same weak evidence, the strongest possible
//! action.
//!
//! M4-82 (31 Aug 2026) is the same door one predicate over - it also
//! skips a leaf beginning `.` - and it lands here rather than in a file
//! of its own because it reuses M4-52's fixture builder wholesale. Its
//! answer is different: the engine is GREEN, because no name this job
//! publishes reaches disk with a leading dot on it. See the test at the
//! foot of this file, and the mechanism half it names.
//!
//! A CHILD module of `e2e_norar`, so the builders above are reachable
//! through `use super::*` without any of them becoming `pub(crate)`,
//! and so `mod.rs` stays inside its size-gate ceiling.

use super::*;

// Both fixtures below hold their `Fixture` binding to the end of the
// test body. `out` lives INSIDE it and its `ScratchDir` guard deletes
// the tree on drop, so an assertion made after the fixture has gone is
// graded against a directory something else already emptied - a red
// that says nothing about the engine.

/// The par2-of-par2 chain of `a_par2_of_par2_chain_names_the_payload`,
/// with the payload's yEnc `name=` chosen by the caller. The NZB
/// SUBJECT stays a bare hash, so `nzb::File::kind` still calls the slot
/// Data - a subject ending `.par2` would classify it `Par2Main` and
/// test something else entirely.
///
/// Nothing is written into the fixture directory for the payload: the
/// two `par2 create` passes below glob `*.par2` out of that directory,
/// so a payload file wearing that extension would be posted as if it
/// were part of the inner set.
fn chain_with_payload_named(tag: &str, data: &[u8], yenc_name: &str, art: usize) -> Fixture {
    let mut fx = Fixture::new(tag);
    {
        let idtag = format!("payslot-{}", fx.nzb_files.len());
        let segs = make_file_articles(yenc_name, data, art, &idtag, &mut fx.articles);
        fx.nzb_files.push(("Bq3fJm77ZsK".to_string(), segs));
    }
    // Inner set over the payload's TRUTH bytes, posted under hashes.
    std::fs::write(fx.dir.join("Chained.Payload.mkv"), data).unwrap();
    let st = Command::new("par2")
        .args(["create", "-r10", "-q", "inner", "Chained.Payload.mkv"])
        .current_dir(&fx.dir)
        .status();
    assert!(st.is_ok_and(|s| s.success()), "inner par2 create failed");
    std::fs::remove_file(fx.dir.join("Chained.Payload.mkv")).unwrap();
    let mut inner: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    inner.sort();
    let inner_names: Vec<String> = inner
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    for (i, p) in inner.iter().enumerate() {
        let bytes = std::fs::read(p).unwrap();
        let hash = format!("Gx7tPz4{i:02}Qe");
        let idtag = format!("chain-inner-{i}");
        let segs = make_file_articles(&hash, &bytes, art, &idtag, &mut fx.articles);
        fx.nzb_files.push((hash, segs));
    }
    // Outer set over the inner packet FILES, announced under real names.
    let inner_refs: Vec<&str> = inner_names.iter().map(String::as_str).collect();
    let st = Command::new("par2")
        .args(["create", "-r10", "-q", "outer"])
        .args(&inner_refs)
        .current_dir(&fx.dir)
        .status();
    assert!(st.is_ok_and(|s| s.success()), "outer par2 create failed");
    for e in std::fs::read_dir(&fx.dir).unwrap().flatten() {
        let p = e.path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("outer") && name.ends_with(".par2") {
            let bytes = std::fs::read(&p).unwrap();
            let idtag = format!("chain-outer-{}", fx.nzb_files.len());
            let segs = make_file_articles(&name, &bytes, art, &idtag, &mut fx.articles);
            fx.nzb_files.push((name, segs));
        }
        std::fs::remove_file(&p).ok();
    }
    fx
}

/// M4-52 (wave-4 fourth pass, 30 Aug 2026). The payload lands under a
/// yEnc name that ends `.par2` and is not recovery data at all; the
/// only set that names it is the inner one, which never activated. The
/// late-set pass must still be asked.
#[tokio::test(flavor = "multi_thread")]
async fn a_par2_named_leftover_is_still_named_by_a_late_inner_set() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let data = payload(220_000, 95);
    let fx = chain_with_payload_named("norarlate52", &data, "Bq3fJm77ZsK.par2", 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the chain failed outright:\n{log}");
    let got = std::fs::read(out.join("Chained.Payload.mkv"))
        .unwrap_or_else(|e| panic!("payload never got its chained name: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join("Bq3fJm77ZsK.par2").exists(),
        "the payload was COPIED under its chained name, not renamed - the \
         posted spelling is still there:\n{log}"
    );
}

/// M4-53 (wave-4 fourth pass, 30 Aug 2026). A payload whose first eight
/// bytes are the PAR2 packet magic, covered by nothing, beside a normal
/// post with an announced recovery set. Both the in-stream sniff and
/// the disk-side `sniffed_packet_files` scan call it a recovery volume
/// on those eight bytes; the sweep then deletes it because no FileDesc
/// names it. One article, so the deferral has nothing left to cancel
/// and the bytes land whole - the question here is the SWEEP, not the
/// fetch.
///
/// The head is bare magic and not a VALID first packet on purpose: that
/// stronger polyglot is row M4-18's fixture, and this lane must not
/// build a second copy of it. It is pinned against the same predicate
/// one level down, by
/// `nzbkit::par2repair::unit_tests::only_packets_and_holes_read_as_a_recovery_volume`,
/// whose `poly` arm is exactly that shape.
#[tokio::test(flavor = "multi_thread")]
async fn a_par2_magic_payload_is_not_swept_as_a_spent_volume() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarsweep53");
    let movie = payload(400_000, 61);
    fx.add_file_obfuscated("Mm4kTq7wYz9", "Movie.Real.mkv", &movie, 40_000);
    assert!(fx.add_par2(10, &["Movie.Real.mkv"], 40_000));
    // The polyglot: PAR2 magic then ordinary bytes. Posted whole in one
    // article under a hash nothing covers.
    let mut poly: Vec<u8> = nzbkit::par2::MAGIC.to_vec();
    poly.extend_from_slice(&payload(30_000, 62));
    {
        let idtag = "polyslot".to_string();
        let segs = make_file_articles("Bb2xNr8vTc", &poly, 1 << 20, &idtag, &mut fx.articles);
        fx.nzb_files.push(("Bb2xNr8vTc".to_string(), segs));
    }
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "a fully fetchable post failed:\n{log}");
    let got = std::fs::read(out.join("Bb2xNr8vTc"))
        .unwrap_or_else(|e| panic!("the magic-headed payload was swept: {e}\n{log}"));
    assert!(
        got == poly,
        "the magic-headed payload is not byte-exact\n{log}"
    );
    let got_movie = std::fs::read(out.join("Movie.Real.mkv"))
        .unwrap_or_else(|e| panic!("movie payload missing: {e}\n{log}"));
    assert!(got_movie == movie, "movie payload not byte-exact\n{log}");
}

/// M4-82 (wave-4 sixth pass, 31 Aug 2026). The LEADING-DOT half of the
/// name test M4-52 opened one predicate over: `has_unclaimed` skips any
/// leftover whose leaf begins `.`, so a payload that landed under such
/// a name would never arm the late-set pass at all.
///
/// The row predicted a FAIL and the engine is GREEN, for a reason the
/// row did not have: the dot cannot reach the disk. Every name this job
/// writes goes through `nzbkit::disk::sanitize_out_name`, which never
/// lets a leading dot through - so this fixture, whose payload is posted
/// with the yEnc name `.Bq3fJm77ZsK`, lands under an UNDOTTED spelling,
/// the door sees it, and the inner set names it exactly as the M4-52
/// fixture above.
///
/// So this is the wire half of a pass pin. The mechanism half - the
/// skip itself, and the sanitize property that is the only thing making
/// it sound - is
/// `crate::get::latesets::tests::the_dot_skip_is_sound_only_while_nothing_we_publish_can_be_dotted`
/// in the binary, which goes RED the day any lane lets a published name
/// keep a leading dot. Neither test is the other: this one says the
/// chain works today, that one says why, and only that one can see the
/// change that would break it.
#[tokio::test(flavor = "multi_thread")]
async fn a_dotted_posted_name_lands_undotted_and_still_reaches_the_late_set() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let data = payload(220_000, 97);
    let fx = chain_with_payload_named("norarlate82", &data, ".Bq3fJm77ZsK", 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the chain failed outright:\n{log}");
    let got = std::fs::read(out.join("Chained.Payload.mkv"))
        .unwrap_or_else(|e| panic!("payload never got its chained name: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
    // The dot is gone at every depth, so nothing on disk is invisible to
    // the door. A leftover under the posted spelling - dotted or not -
    // would mean the rename never happened.
    let dotted: Vec<String> = tree_names(&out)
        .into_iter()
        .filter(|n| n.rsplit('/').next().is_some_and(|l| l.starts_with('.')))
        .collect();
    assert!(
        dotted.is_empty(),
        "a dotted name reached the output tree, which is what M4-82's skip \
         would then hide from the late-set pass: {dotted:?}\n{log}"
    );
    assert!(
        !out.join("Bq3fJm77ZsK").exists(),
        "the payload was COPIED under its chained name, not renamed - the \
         posted spelling is still there:\n{log}"
    );
}
