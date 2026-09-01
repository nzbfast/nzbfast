//! Wave-4 row M4-102: the LEFTOVER in a subdirectory - the composition
//! half of `has_unclaimed`'s tree walk.
//!
//! The late-set pass is gated on there being a file here that no ACTIVE
//! set speaks for, and that gate was a single top-level `read_dir`
//! until W4-06 (`b3664a93b`, 30 Aug 2026) rewrote it as a bounded tree
//! walk. Every chain pin written before that rewrite keeps the
//! unclaimed hash at the job ROOT - F12's `a_par2_of_par2_chain_names_
//! the_payload` and both W4-06 pins do, and M4-06A's own doc comment
//! says so in as many words ("the unclaimed hash is still at the root
//! when the scan runs"). So the one arrangement the gate's rewrite was
//! FOR had no e2e reaching it: the leftover itself below the root, with
//! nothing unclaimed at the root at all.
//!
//! That is a real publication shape and not a contrivance. A poster who
//! obfuscates the BASENAME and keeps the directory honest posts
//! `payload/<hash>`, `sanitize_out_name` rules that a safe relative
//! path and preserves it, and the file lands a directory down. Under
//! the root-only gate the root then holds nothing but recovery volumes,
//! `payload` is a DIRECTORY rather than a file, the pass returns before
//! discovery, and the job finishes rc=0 with the payload still wearing
//! its hash - the row's own prediction.
//!
//! MEASURED 31 Aug 2026 on `03d6c4345`, and the row's own prediction
//! was half right in the way that mattered. The PREDICATE half is
//! closed: W4-06's walk arms the door and discovery reaches the vouched
//! inner set, so `rc=0, no second set fetched` is falsified. What is
//! behind the door was not widened with it. `par2repair::adopt`'s
//! candidate scan was still a flat `read_dir`, so the vouched set
//! priced its only member WHOLLY MISSING with the bytes sitting intact
//! one directory down (`1965 block(s) of damage ... 0 adopted`) - and
//! since W4-01 a vouched set's denial FAILS the job.
//!
//! So the outcome went the wrong way across W4-06, which is the part
//! worth carrying: replaying the pre-W4-06 root-only predicate against
//! this very fixture gives rc=0 with the payload still at
//! `payload/Bq3fJm77ZsK`, exactly as the row predicted, while the tree
//! walk alone gives `verification failed and PAR2 repair could not
//! complete`. A job that used to finish - imperfectly, hash-named -
//! stopped finishing at all. The door was widened and the reach behind
//! it was not, and `has_unclaimed`'s own comment said widening `can
//! only make the door OPEN more often, never fail a job`, which W4-01
//! had already falsified on the day both landed.
//!
//! Landed here WITH the fix rather than as a pass pin: the late-set
//! call now offers this tree's own directories to the adoption scan as
//! donors (`par2repair::nested_subdirs`, DERIVED from the same walk, so
//! the two cannot drift apart about how far `here` reaches). The
//! sweepability line needed nothing - `par2repair.rs`'s donor sweep
//! already refuses to spend a candidate outside the repair directory,
//! so a subdirectory of this job's own output is spendable and another
//! job's donated directory is still not.
//!
//! The unit half of the predicate is `latesets.rs`'s
//! `a_tree_published_file_the_active_sets_name_is_not_unclaimed`; the
//! unit half of the reach is `par2repair::nested`'s
//! `nested_subdirs_are_the_directories_the_walk_actually_reached`. This
//! is the composition neither can see.
//!
//! The two cases below are ONE fixture with ONE thing changed, which is
//! the only way a probe's red is attributable: `Root` is F12's
//! arrangement and is the control, `Subdir` is the row. A failure in
//! `Subdir` alone is the row; a failure in both is something else.
//!
//! A CHILD of `e2e_norar` for that file's stated reason - it was 2,891
//! of its 3,000 size-gate lines when this was written, with wave-4
//! lanes appending to it.

use super::super::*;
use super::{run_norar, tree_names};

/// Where the obfuscated payload is published: at the job root (F12's
/// arrangement, the control) or a directory down (the row).
#[derive(Clone, Copy, PartialEq)]
enum Where {
    Root,
    Subdir,
}

/// F12's par2-of-par2 chain with the payload's publication directory as
/// the only variable.
///
/// The inner set - the one that names the payload - is posted under
/// hash names and never activates, so it is on disk unactivated at
/// settle time, which is what the late-set pass exists for. The outer
/// set NAMES those inner packet files, which is what vouches for the
/// inner set's verdict (W4-01) and what lands them at the root under
/// `inner*.par2`, where they read as recovery data rather than as
/// unclaimed payload. So in the `Subdir` arm the ONLY thing here that
/// no active set speaks for is one file, one directory down.
async fn chain_case(tag: &str, place: Where) {
    let mut fx = Fixture::new(tag);
    let data = payload(220_000, 97);
    let posted = match place {
        Where::Root => "Bq3fJm77ZsK".to_string(),
        Where::Subdir => {
            std::fs::create_dir_all(fx.dir.join("payload")).unwrap();
            "payload/Bq3fJm77ZsK".to_string()
        }
    };
    fx.add_file_obfuscated("Bq3fJm77ZsK", &posted, &data, 40_000);
    // Inner set over the payload's REAL name, at the root. Removed from
    // the staging tree after creation: it is never posted, and the
    // whole point is that these bytes reach the job only under the hash.
    std::fs::write(fx.dir.join("Chained.Payload.mkv"), &data).unwrap();
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
        let hash = format!("Kd8vRn5{i:02}Tj");
        let art_tag = format!("{tag}-inner-{i}");
        let segs = make_file_articles(&hash, &bytes, 40_000, &art_tag, &mut fx.articles);
        fx.nzb_files.push((hash, segs));
    }
    // Outer set over the inner par2 FILES, announced under real names.
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
            let art_tag = format!("{tag}-outer-{}", fx.nzb_files.len());
            let segs = make_file_articles(&name, &bytes, 40_000, &art_tag, &mut fx.articles);
            fx.nzb_files.push((name, segs));
        }
        std::fs::remove_file(&p).ok();
    }
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the {tag} chain failed outright:\n{log}");
    // The row's arrangement is only tested if it was actually BUILT:
    // if the leftover published flat after all, this is the control run
    // twice and its green says nothing about a subdirectory.
    if place == Where::Subdir {
        assert!(
            !out.join("Bq3fJm77ZsK").exists(),
            "the leftover published FLAT, so nothing here was below the \
             root and this run is not the row; tree: {:?}\n{log}",
            tree_names(&out)
        );
    }
    let got = std::fs::read(out.join("Chained.Payload.mkv")).unwrap_or_else(|e| {
        panic!(
            "the late set never named the payload: {e}; if the run also \
             failed outright the door armed and the repair could not reach \
             the leftover, which is the M4-102 regression - tree: {:?}\n{log}",
            tree_names(&out)
        )
    });
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join(&posted).exists(),
        "the obfuscated payload name survived the chain at {posted}:\n{log}"
    );
}

/// The CONTROL: F12's arrangement, leftover at the root, which the
/// root-only gate already reached. Green before W4-06 and after it.
#[tokio::test(flavor = "multi_thread")]
async fn a_chain_whose_leftover_sits_at_the_root_names_the_payload() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    chain_case("norarlateroot", Where::Root).await;
}

/// M4-102: the same chain with the ONE thing changed - the leftover is
/// published a directory down, so the root holds nothing but recovery
/// volumes and a root-only gate sees a directory where the unclaimed
/// file is.
#[tokio::test(flavor = "multi_thread")]
async fn a_chain_whose_leftover_sits_below_the_root_names_the_payload() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    chain_case("norarlatesub", Where::Subdir).await;
}
