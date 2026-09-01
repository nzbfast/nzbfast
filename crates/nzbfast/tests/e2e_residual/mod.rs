//! X5-24: residual assignment after a TOTAL loss, under global
//! uniqueness.
//!
//! The shape: a FULLY obfuscated post carrying one recovery set per
//! file. Two
//! payloads arrive and claim their sets. The third payload's every
//! article is refused, so it delivers ZERO bytes, and with zero bytes
//! there is no content claim to make: the md5-16k tier has no head to
//! hash and adoption wants `len > 0` on both sides. Its set therefore
//! matches nothing, a sibling set did match, and the post names
//! nothing usefully, so the stray-release guard in
//! `get::settle::settle_with_set` reads the job's OWN set as a
//! different release's and never spends its parity - on a set carrying
//! 100% redundancy over a file it could rebuild whole.
//!
//! It was decided (30 Aug 2026) that the rebuild is allowed ONLY under
//! GLOBAL UNIQUENESS, and that whenever uniqueness fails the decline
//! stands but the DIAGNOSIS must be honest. Both halves are pinned
//! here: the capability under every set and NZB order, and two
//! red-team controls that must keep declining - an INCOMPATIBLE
//! leftover set (unique, but describing a file of quite another size)
//! and an AMBIGUOUS pair (two files lost whole, two leftover sets, one
//! declared length between them).
//!
//! A sibling-dir child of e2e.rs (the `e2e_multiset` pattern) so the
//! parent stays inside its size-gate baseline; helpers via `super::*`.

use super::*;
use crate::payloads;

/// One INDEPENDENT recovery set over ONE file, base-named `base` - the
/// per-file-set shape of GH #63, which is what puts a whole set's fate
/// on a single payload. `add_par2_per_file` in `e2e_multiset` is the
/// same idea; this one takes the base explicitly because these fixtures
/// need the set name decoupled from the payload's stem.
fn add_set_over(fx: &mut Fixture, redundancy: u32, base: &str, file: &str, art: usize) -> bool {
    let st = Command::new("par2")
        .arg("create")
        .arg(format!("-r{redundancy}"))
        .arg("-q")
        .arg(format!("{base}.par2"))
        .arg(file)
        .current_dir(&fx.dir)
        .status();
    match st {
        Ok(s) if s.success() => {}
        _ => return false,
    }
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    for p in par2s {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let data = std::fs::read(&p).unwrap();
        let tag = format!("{}-{}", name.replace('.', "_"), fx.nzb_files.len());
        let segs = make_file_articles(&name, &data, art, &tag, &mut fx.articles);
        fx.nzb_files.push((name, segs));
        std::fs::remove_file(&p).unwrap();
    }
    true
}

/// Every article id whose tag names this posted file - the `missing`
/// set for a payload taken down WHOLE. `make_file_articles` tags each
/// id `<posted>-<nzb index>-<n>@mock`, so the posted hash plus its
/// index separates a payload from every other file in the post,
/// recovery volumes included.
fn all_articles_of(fx: &Fixture, posted: &str, idx: usize) -> std::collections::HashSet<String> {
    let stem = format!("{}-{}-", posted.replace('.', "_"), idx);
    let gone: std::collections::HashSet<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains(&stem))
        .cloned()
        .collect();
    assert!(!gone.is_empty(), "no articles found for {posted} at {idx}");
    gone
}

/// The three-file fully obfuscated post the ruling is about: real names
/// live only in the FileDescs, every declared length is unique, and one
/// set per file. Returns the fixture and the (real name, bytes) triples
/// in post order.
fn three_set_post(tag: &str) -> Option<(Fixture, Vec<(String, Vec<u8>)>)> {
    // Lengths deliberately far apart: the assignment's size band is
    // 90..120% of the POSTED (yEnc-encoded) byte count, so a fixture
    // whose files sit inside each other's band would be testing the
    // band rather than the uniqueness rule.
    let files: Vec<(String, Vec<u8>)> = [
        ("alpha.bin", 400_000usize, 11u64),
        ("beta.bin", 260_000, 22),
        ("gamma.bin", 120_000, 33),
    ]
    .iter()
    .map(|(n, len, seed)| (n.to_string(), payloads::unique_payload(*len, *seed)))
    .collect();
    let posted = ["Q7hd2Kx9Lm0", "Zb3vN81sRc4", "Wm5tYq02Hn7"];
    let mut fx = Fixture::new(tag);
    for (i, (name, data)) in files.iter().enumerate() {
        fx.add_file_renamed_by_par2(name, posted[i], data, 50_000);
    }
    for (i, (name, _)) in files.iter().enumerate() {
        // 100% redundancy: as many recovery blocks as data blocks, so a
        // set whose file arrived NOTHING can still rebuild it whole.
        if !add_set_over(&mut fx, 100, &format!("s{i}"), name, 50_000) {
            return None;
        }
    }
    Some((fx, files))
}

/// Run the post with `gone` refused, under an explicit NZB file ORDER.
///
/// The order is applied to `fx.nzb_files` AFTER the articles are built,
/// so message-ids are untouched and only the document the client reads
/// moves. Set order follows it, since a set is adopted when its packets
/// arrive.
async fn run_ordered(
    fx: &mut Fixture,
    order: &[usize],
    gone: std::collections::HashSet<String>,
) -> (String, bool, PathBuf) {
    // Permuted IN PLACE and restored, never by building a second
    // `Fixture` over the same directory: the fixture owns a
    // `ScratchDir` guard that removes that directory when it drops, so
    // a throwaway copy would delete the post out from under the next
    // order.
    let original = fx.nzb_files.clone();
    assert_eq!(order.len(), original.len(), "order must be a permutation");
    fx.nzb_files = order.iter().map(|&i| original[i].clone()).collect();
    let tag: String = order.iter().map(|i| i.to_string()).collect();
    let out = fx.dir.join(format!("out-{tag}"));
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            missing: gone,
            ..Default::default()
        },
    )
    .await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    fx.nzb_files = original;
    if std::env::var("NORAR_DUMP_LOG").is_ok() {
        eprintln!("==== order {order:?} ====\n{log}\n==== end ====");
    }
    (log, ok, out)
}

/// THE CAPABILITY. One file lost whole, one leftover set, one honest
/// answer - under every order the post can be read in.
#[tokio::test(flavor = "multi_thread")]
async fn the_one_file_this_post_lost_whole_is_rebuilt_from_the_one_leftover_set() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let Some((mut fx, files)) = three_set_post("residual-unique") else {
        eprintln!("skipping: par2 create failed");
        return;
    };
    let gone = all_articles_of(&fx, "Wm5tYq02Hn7", 2);
    // Six files in the post (three payloads, three sets). Two orders:
    // as posted, and fully reversed - which puts every recovery set
    // ahead of every payload and the lost file's set FIRST.
    let n = fx.nzb_files.len();
    let forward: Vec<usize> = (0..n).collect();
    let reverse: Vec<usize> = (0..n).rev().collect();
    for order in [forward, reverse] {
        let (log, ok, out) = run_ordered(&mut fx, &order, gone.clone()).await;
        assert!(
            !log.contains("different release's file"),
            "order {order:?}: gamma.bin's own set was called another release's:\n{log}"
        );
        assert!(
            ok,
            "order {order:?}: a post that can rebuild its own loss:\n{log}"
        );
        let got = std::fs::read(out.join("gamma.bin")).unwrap_or_default();
        assert!(
            got == files[2].1,
            "order {order:?}: gamma.bin is {} bytes on disk of {} expected:\n{log}",
            got.len(),
            files[2].1.len()
        );
        for (name, data) in &files[..2] {
            let got = std::fs::read(out.join(name)).unwrap_or_default();
            assert!(
                got == *data,
                "order {order:?}: {name} is not byte-exact:\n{log}"
            );
        }
    }
}

/// CONTROL 1 - INCOMPATIBLE. Exactly one leftover set and exactly one
/// file lost whole, so every COUNT in the uniqueness rule is satisfied:
/// what separates them is that the leftover set describes a file of
/// quite another size. It must decline, and the sentence it declines
/// with must name the set and say why - never the foreign-release
/// verdict.
#[tokio::test(flavor = "multi_thread")]
async fn a_leftover_set_of_the_wrong_size_declines_with_an_honest_reason() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("residual-incompat");
    let mine = payloads::unique_payload(400_000, 5);
    let lost = payloads::unique_payload(120_000, 6);
    fx.add_file_renamed_by_par2("mine.bin", "Q7hd2Kx9Lm0", &mine, 50_000);
    fx.add_file_renamed_by_par2("lost.bin", "Wm5tYq02Hn7", &lost, 50_000);
    if !add_set_over(&mut fx, 20, "s0", "mine.bin", 50_000) {
        eprintln!("skipping: par2 create failed");
        return;
    }
    // The other release: written only long enough for par2 to describe
    // it, and only the recovery set is posted. 900 KB against the
    // 120 KB this post lost - nowhere near the band.
    std::fs::write(
        fx.dir.join("elsewhere.bin"),
        payloads::unique_payload(900_000, 71),
    )
    .unwrap();
    assert!(add_set_over(&mut fx, 20, "s9", "elsewhere.bin", 50_000));
    std::fs::remove_file(fx.dir.join("elsewhere.bin")).unwrap();

    // lost.bin's set is NOT posted at all, so the only unclaimed set in
    // the post is the foreign one and the only wholly missing file is
    // lost.bin. Counts alone cannot separate them.
    let gone = all_articles_of(&fx, "Wm5tYq02Hn7", 1);
    let n = fx.nzb_files.len();
    let order: Vec<usize> = (0..n).collect();
    let (log, ok, out) = run_ordered(&mut fx, &order, gone).await;
    assert!(
        !ok,
        "a post that lost a file whole with no parity for it must fail:\n{log}"
    );
    assert!(
        !out.join("elsewhere.bin").exists(),
        "another release's file was rebuilt from its own parity:\n{log}"
    );
    assert!(
        !log.contains("different release's file"),
        "the foreign-release verdict is exactly what the ruling refuses:\n{log}"
    );
    assert!(
        log.contains("elsewhere.bin") && log.contains("it could rebuild it, and was not asked to"),
        "the decline must name the set and what it could rebuild:\n{log}"
    );
    assert!(
        log.contains("not the size of the one file this post lost whole"),
        "the decline must say WHY it was not attempted:\n{log}"
    );
}

/// CONTROL 2 - AMBIGUOUS. Two files lost whole, two leftover sets, and
/// the two declared lengths inside one band, so nothing distinguishes
/// which set stands for which loss. Both must decline.
#[tokio::test(flavor = "multi_thread")]
async fn two_losses_and_two_leftover_sets_of_one_size_both_decline() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("residual-ambig");
    let mine = payloads::unique_payload(400_000, 5);
    let a = payloads::unique_payload(200_000, 6);
    let b = payloads::unique_payload(200_000, 7);
    fx.add_file_renamed_by_par2("mine.bin", "Q7hd2Kx9Lm0", &mine, 50_000);
    fx.add_file_renamed_by_par2("twin-a.bin", "Zb3vN81sRc4", &a, 50_000);
    fx.add_file_renamed_by_par2("twin-b.bin", "Wm5tYq02Hn7", &b, 50_000);
    for (i, f) in ["mine.bin", "twin-a.bin", "twin-b.bin"].iter().enumerate() {
        if !add_set_over(&mut fx, 100, &format!("s{i}"), f, 50_000) {
            eprintln!("skipping: par2 create failed");
            return;
        }
    }
    let mut gone = all_articles_of(&fx, "Zb3vN81sRc4", 1);
    gone.extend(all_articles_of(&fx, "Wm5tYq02Hn7", 2));
    let n = fx.nzb_files.len();
    let order: Vec<usize> = (0..n).collect();
    let (log, ok, out) = run_ordered(&mut fx, &order, gone).await;
    assert!(
        !ok,
        "an undecidable assignment must not green the job:\n{log}"
    );
    for n in ["twin-a.bin", "twin-b.bin"] {
        assert!(
            !out.join(n).exists(),
            "{n} was rebuilt on a guess between two indistinguishable sets:\n{log}"
        );
    }
    assert!(
        !log.contains("different release's file"),
        "the foreign-release verdict is exactly what the ruling refuses:\n{log}"
    );
    assert!(
        log.contains("cannot be decided"),
        "the decline must say the assignment is undecidable:\n{log}"
    );
}
