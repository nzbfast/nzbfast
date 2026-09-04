//! Wave-4 matrix-read row M4-70: the extractor latched the FIRST
//! article's yEnc name, so ARRIVAL ORDER decided what the file was
//! called. CONFIRMED 30 Aug 2026, FIXED 31 Aug 2026 by the settle-time
//! re-decision in `nzbfast::get::yencname` - these are now the pins on
//! the property rather than on the gap.
//!
//! A CHILD of `e2e_norar` rather than a sibling directory, for
//! `pins.rs`'s reason word for word: a child sees the parent's builders
//! through `use super::*` where a sibling would need every one of them
//! made `pub(crate)` on lines other M4 lanes are also editing.
//!
//! ## The order control, and why a loop is not one
//!
//! Both rows here STALL CHOSEN MESSAGE-IDS (`Chaos::slow_ttfb`) rather
//! than running the same post repeatedly and hoping. The wave-5 round
//! measured that difference on this exact class: W4-11 presented as a
//! 1-in-5 and W4-15 as a 3-in-10 flake until order control was added,
//! and both are deterministic under a stall. A
//! `for _ in 0..25` pin for an arrival-order row passes on a fast box,
//! fails on a loaded one, and nextest retries it green either way.
//!
//! The honest-first arm stalls ONE article and lets three race; that is
//! deliberate and not a weaker pin, because all three carry the SAME
//! name, so which of them wins does not change the answer.

use super::*;

/// The decoy post: `parts` articles of one file, part 1 declaring a
/// short single-token yEnc name that `looks_obfuscated` does NOT reject,
/// every later article declaring the real one. Returns the message-id of
/// part 1, which is what the two arms stall against.
fn add_decoy_first_name(fx: &mut Fixture, real: &str, subject: &str, data: &[u8], art: usize) {
    add_file_yenc_names(fx, real, subject, data, art, |p| {
        if p == 1 {
            "x.dat".to_string()
        } else {
            real.to_string()
        }
    });
}

/// Post the decoy file, stall one side or the other, and report the
/// names the job actually published.
async fn published_names(decoy_first: bool, with_par2: bool) -> (String, Vec<(String, u64)>) {
    let mut fx = Fixture::new("norarlatch");
    let data = payload(120_000, 91);
    add_decoy_first_name(&mut fx, "Movie.2024.mkv", "Hs9kLm42TpQ", &data, 30_000);
    if with_par2 {
        assert!(fx.add_par2(20, &["Movie.2024.mkv"], 40_000));
    }
    // The builder ids parts `<{subject}-{index}-{part}@mock>`.
    let decoy_id = "<Hs9kLm42TpQ-0-1@mock>";
    assert!(
        fx.articles.contains_key(decoy_id),
        "the decoy article id moved - the stall would be a no-op"
    );
    let slow: std::collections::HashMap<String, u64> = fx
        .articles
        .keys()
        .filter(|k| {
            // Stall everything but the decoy, or the decoy alone. PAR2
            // articles ride the honest side either way; the row is about
            // the payload slot's own name.
            if decoy_first {
                *k != decoy_id
            } else {
                *k == decoy_id
            }
        })
        .map(|k| (k.clone(), 900))
        .collect();
    assert!(
        !slow.is_empty(),
        "nothing to stall - order control is inert"
    );
    let chaos = Chaos {
        slow_ttfb: slow,
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(ok, "the decoy-name post failed outright:\n{log}");
    let mut names: Vec<(String, u64)> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                e.metadata().unwrap().len(),
            )
        })
        .filter(|(n, _)| !n.ends_with(".par2"))
        .collect();
    names.sort();
    // The Fixture owns the ScratchDir; everything read out of `out`
    // happens above, while it is still alive.
    drop(fx);
    (log, names)
}

/// M4-70, FIXED 31 Aug 2026 - and this is the property assertion the
/// GAP pin that stood here asked to be replaced by, in its own words:
/// "both arms must publish the same name, and it must be the one the
/// post's own evidence supports".
///
/// It was RED and deterministic on the 30 Aug baseline (`a5c0d4615`):
/// one file, four articles, identical bytes on the wire, and stalling
/// the three honest articles published `x.dat` while stalling the one
/// decoy published `Movie.2024.mkv`. The filename was a function of the
/// network.
///
/// The fix is NOT a better latch, and the old pin was explicit that it
/// must not be: nothing at the moment of a write is order-free, because
/// when the first article lands there is exactly one name in hand. The
/// articles' declarations are RECORDED as they pass
/// (`unpack::slot_name::NameVotes`) and the question is re-decided at
/// settle by `get::yencname`, off what the whole post said. Three
/// articles of four say `Movie.2024.mkv`; a decoy is by construction a
/// minority.
///
/// WHAT THIS TEST IS FOR NOW. The `assert_eq!` between the two arms is
/// the load-bearing line and it is the one that could not be written
/// before: order-independence is the property, and only a comparison of
/// two ORDERS can state it. The value assertion beside it is what stops
/// that passing vacuously - two arms agreeing on `x.dat` would satisfy
/// order-independence and still be the decoy winning.
#[tokio::test(flavor = "multi_thread")]
async fn the_published_name_of_an_uncovered_file_is_the_one_its_articles_agree_on() {
    // par2-gate: both arms pass with_par2=false, so `published_names`
    // never reaches `add_par2` from here - an UNCOVERED file is the whole
    // row. The gate resolves the sink transitively through the helper and
    // cannot see the argument. The two tests below DO build a set and do
    // ask have_par2() first.
    let (decoy_log, decoy) = published_names(true, false).await;
    let (honest_log, honest) = published_names(false, false).await;
    assert_eq!(
        decoy.len(),
        1,
        "expected one published file, got {decoy:?}\n{decoy_log}"
    );
    assert_eq!(
        honest.len(),
        1,
        "expected one published file, got {honest:?}\n{honest_log}"
    );
    // Both arms deliver every byte - the row is identity, not loss.
    assert_eq!(
        decoy[0].1, 120_000,
        "decoy-first arm lost bytes\n{decoy_log}"
    );
    assert_eq!(
        honest[0].1, 120_000,
        "honest-first arm lost bytes\n{honest_log}"
    );
    assert_eq!(
        decoy[0].0, honest[0].0,
        "M4-70 REGRESSED: the same post published two different names \
         depending on which article the network delivered first. The \
         decoy-first arm says {:?} and the honest-first arm says {:?} - \
         if the decoy arm says `x.dat` the settle-time re-decision in \
         `get::yencname` is not running or not reaching this slot.\n\
         --- decoy first ---\n{decoy_log}\n--- honest first ---\n{honest_log}",
        decoy[0].0, honest[0].0
    );
    assert_eq!(
        decoy[0].0, "Movie.2024.mkv",
        "the two arms AGREE, so arrival order no longer decides - but \
         they agree on the wrong name. Three of this post's four \
         articles declare `Movie.2024.mkv` and one declares `x.dat`; a \
         decoy that wins a majority vote means the votes are being \
         counted wrong, not that the tier is missing.\n{decoy_log}"
    );
}

/// The BOUND on M4-70, measured 30 Aug 2026, and the reason the gap
/// above is narrow rather than a live data defect.
///
/// The same decoy post under a recovery set that names the file lands
/// correctly in BOTH arrival orders: the latch still writes `x.dat` to
/// disk (`[get] ✔ x.dat`), and settle renames it off the FileDesc
/// (`[extract] renamed x.dat → Movie.2024.mkv`). So the arrival-order
/// answer only survives to the user where nothing stronger names the
/// file at all.
///
/// This is also the CONTROL for the gap pin above: a red there with a
/// red here is the harness, not the row.
#[tokio::test(flavor = "multi_thread")]
async fn a_covering_filedesc_overrules_the_decoy_name_in_either_order() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    for decoy_first in [true, false] {
        let (log, names) = published_names(decoy_first, true).await;
        assert_eq!(
            names,
            vec![("Movie.2024.mkv".to_string(), 120_000u64)],
            "decoy_first={decoy_first}: the FileDesc did not overrule the \
             latched yEnc name\n{log}"
        );
    }
}

/// The sharp shape the row predicted - "a unique exact-match onto a
/// wrong FileDesc named `x.dat` if one exists" - MEASURED GREEN.
///
/// Two covered files in one set: `Movie.2024.mkv`, whose first article
/// carries the decoy name, and a real member genuinely called `x.dat`.
/// The decoy therefore exact-matches a descriptor that belongs to
/// somebody else's bytes, which before `2b7f5495e` is precisely how a
/// crossed pair each claimed the other's descriptor and verified
/// 1000/1000 bad.
///
/// It does not happen: the head key arbitrates the name candidate, the
/// decoy's bytes deny the `x.dat` descriptor, and both members settle on
/// content. The collision is visible on disk as the `001-x.dat`
/// disambiguation and the `.nzbfast-swap-0` two-step in the log, and
/// both are repaired by the publish planner. The load-bearing assertion
/// is that the two payloads are BYTE-EXACT under their own names: an
/// engine that let the name claim the descriptor would land both at
/// rc=0 with the contents swapped.
#[tokio::test(flavor = "multi_thread")]
async fn a_decoy_first_name_does_not_claim_the_real_members_descriptor() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarlatchx");
    let movie = payload(120_000, 91);
    let real_x = payload(90_000, 92);
    add_decoy_first_name(&mut fx, "Movie.2024.mkv", "Hs9kLm42TpQ", &movie, 30_000);
    add_file_yenc_names(&mut fx, "x.dat", "Wr2bNc58VgL", &real_x, 30_000, |_| {
        "x.dat".to_string()
    });
    assert!(fx.add_par2(20, &["Movie.2024.mkv", "x.dat"], 40_000));
    let decoy_id = "<Hs9kLm42TpQ-0-1@mock>";
    assert!(fx.articles.contains_key(decoy_id));
    let slow: std::collections::HashMap<String, u64> = fx
        .articles
        .keys()
        .filter(|k| *k != decoy_id)
        .map(|k| (k.clone(), 900))
        .collect();
    let chaos = Chaos {
        slow_ttfb: slow,
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(ok, "the crossed-name post failed:\n{log}");
    let got_movie = std::fs::read(out.join("Movie.2024.mkv"))
        .unwrap_or_else(|e| panic!("Movie.2024.mkv never landed: {e}\n{log}"));
    let got_x = std::fs::read(out.join("x.dat"))
        .unwrap_or_else(|e| panic!("x.dat never landed: {e}\n{log}"));
    assert!(
        got_movie == movie && got_x == real_x,
        "the decoy name claimed the wrong descriptor - contents are \
         swapped or short ({} / {} bytes)\n{log}",
        got_movie.len(),
        got_x.len()
    );
}

/// The SHARP shape for the settle-time tier itself, and the reason it
/// tests the name ON DISK rather than trusting its own record.
///
/// A recovery set names this file `Real.Name.mkv`; its articles
/// overwhelmingly declare `Decoy.mkv`. Both are real-looking names, so
/// GH #63's `hint_beats` rule declines neither and the majority is a
/// clear 3-1 - everything about the M4-70 verdict says rename. The only
/// thing standing between the post and a FileDesc name being overwritten
/// by an unchecksummed yEnc header is `get::yencname`'s precondition:
/// it renames only a file still sitting under a name the ARTICLES
/// declared (or the slot's own posted hint), and after the PAR2 rename
/// this one is not.
///
/// That ordering is the whole tiering argument made concrete. A yEnc
/// header is the poster's word with nothing behind it; a FileDesc is an
/// MD5 pair over the file. Delete the precondition and this test lands
/// the payload as `Decoy.mkv`, having thrown away the strongest name in
/// the post - which is the defect a settle-time re-decision could
/// introduce that the old first-article latch could not.
#[tokio::test(flavor = "multi_thread")]
async fn a_yenc_majority_does_not_overwrite_a_filedesc_name() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    for decoy_first in [true, false] {
        let mut fx = Fixture::new("norarlatchfd");
        let data = payload(120_000, 93);
        add_file_yenc_names(
            &mut fx,
            "Real.Name.mkv",
            "Zq4vBn71MdX",
            &data,
            30_000,
            |p| {
                if p == 1 {
                    "a.dat".to_string()
                } else {
                    "Decoy.mkv".to_string()
                }
            },
        );
        assert!(fx.add_par2(20, &["Real.Name.mkv"], 40_000));
        let first_id = "<Zq4vBn71MdX-0-1@mock>";
        assert!(
            fx.articles.contains_key(first_id),
            "the first article's id moved - the stall would be a no-op"
        );
        let slow: std::collections::HashMap<String, u64> = fx
            .articles
            .keys()
            .filter(|k| {
                if decoy_first {
                    *k != first_id
                } else {
                    *k == first_id
                }
            })
            .map(|k| (k.clone(), 900))
            .collect();
        let chaos = Chaos {
            slow_ttfb: slow,
            ..Chaos::default()
        };
        let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
        assert!(ok, "decoy_first={decoy_first}: the post failed:\n{log}");
        let got = std::fs::read(out.join("Real.Name.mkv")).unwrap_or_else(|e| {
            panic!(
                "decoy_first={decoy_first}: the recovery set's own name is \
                 not what landed - a yEnc-header majority overwrote an MD5 \
                 pair: {e}\n{log}"
            )
        });
        assert_eq!(
            got, data,
            "decoy_first={decoy_first}: wrong bytes under the FileDesc name\n{log}"
        );
        assert!(
            !out.join("Decoy.mkv").exists(),
            "decoy_first={decoy_first}: the yEnc majority published a second \
             copy under its own name\n{log}"
        );
        drop(fx);
    }
}

/// Finding F18 (1 Sep 2026): the sharp shape the test above misses by
/// ONE fixture token, and the reason a set-claimed slot is now skipped
/// by name rather than left to the on-disk test.
///
/// Same post as `a_yenc_majority_does_not_overwrite_a_filedesc_name`,
/// with the minority article's yEnc name changed from `a.dat` to
/// `Real.Name.mkv` - the very name the recovery set's FileDesc declares.
/// That is not exotic: a FileDesc name IS usually the real name, so a
/// post whose articles do not all agree (a filler or repost merge, or a
/// poster whose tool changed names midway) has some article declaring
/// it.
///
/// The on-disk precondition then reads TRUE for the wrong reason. After
/// the PAR2 rename the file sits under `Real.Name.mkv`, which IS one of
/// the names the articles declared, so the guard answers "this tier put
/// that name there" when in fact the MD5 pair did - and the majority,
/// still `Decoy.mkv` 3-1, walks a set-proved file onto the loser. The
/// bytes are never lost (`publish_weak_name` declines a collision), but
/// the job completes with the payload under the decoy and an info line
/// saying the post's majority decided.
///
/// The guard is the `set_reports` gate, which is the same predicate
/// `sfvname::land_sfv_names` already uses one line above the call: a
/// report exists exactly for a slot some recovery set claimed.
#[tokio::test(flavor = "multi_thread")]
async fn a_yenc_majority_does_not_take_a_filedesc_name_it_also_declared() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    for decoy_first in [true, false] {
        let mut fx = Fixture::new("norarlatchf18");
        let data = payload(120_000, 97);
        // The minority article declares the FileDesc name itself - the
        // one token that separates this row from the test above.
        add_file_yenc_names(
            &mut fx,
            "Real.Name.mkv",
            "Kp7xRt29ZfV",
            &data,
            30_000,
            |p| {
                if p == 1 {
                    "Real.Name.mkv".to_string()
                } else {
                    "Decoy.mkv".to_string()
                }
            },
        );
        assert!(fx.add_par2(20, &["Real.Name.mkv"], 40_000));
        let first_id = "<Kp7xRt29ZfV-0-1@mock>";
        assert!(
            fx.articles.contains_key(first_id),
            "the first article's id moved - the stall would be a no-op"
        );
        let slow: std::collections::HashMap<String, u64> = fx
            .articles
            .keys()
            .filter(|k| {
                if decoy_first {
                    *k != first_id
                } else {
                    *k == first_id
                }
            })
            .map(|k| (k.clone(), 900))
            .collect();
        let chaos = Chaos {
            slow_ttfb: slow,
            ..Chaos::default()
        };
        let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
        assert!(ok, "decoy_first={decoy_first}: the post failed:\n{log}");
        let got = std::fs::read(out.join("Real.Name.mkv")).unwrap_or_else(|e| {
            panic!(
                "decoy_first={decoy_first}: the recovery set's own name is \
                 not what landed - a yEnc-header majority took it back \
                 because one article had declared it too: {e}\n{log}"
            )
        });
        assert_eq!(
            got, data,
            "decoy_first={decoy_first}: wrong bytes under the FileDesc name\n{log}"
        );
        assert!(
            !out.join("Decoy.mkv").exists(),
            "decoy_first={decoy_first}: the yEnc majority published under \
             its own name over a set-claimed slot\n{log}"
        );
        drop(fx);
    }
}

/// GH #63's polarity, and the third of the three guards that keep this
/// tier from being a way to lose a name.
///
/// The poster obfuscated the FILES and left the SUBJECT clean - the
/// opposite of #43/#47/#55 - so the NZB carries the real name and the
/// yEnc headers carry hashes. The articles disagree among THEMSELVES as
/// well (one hash on the first article, a different one on the other
/// three), so an M4-70 verdict IS reached and its winner is a hash, 3
/// votes to 1.
///
/// It must not be taken. `hint_beats` is the project's answer to which
/// of two names is worth more and it is not suspended by a majority: a
/// name may not be replaced by one that GIVES UP what the post already
/// told us, however many articles repeat it. Delete
/// `filedesc_name_is_better` from `get::yencname` and this post's whole
/// filename is lost to a hash the engine had already read correctly -
/// which is #63 again, reintroduced through the tier that exists to fix
/// M4-70.
///
/// BOTH DECLARED NAMES ARE HASHES, and that is what makes this
/// deterministic rather than a stall. An earlier draft gave the first
/// article a short real-looking name, and the test went FLAKY - failing
/// then passing on retry - because `write_name`'s hint-versus-yEnc latch
/// is itself decided by whichever article calls it first, and those two
/// candidates fall on opposite sides of `stem_is_a_name`. With two
/// hashes that latch answers HINT whichever article wins, so the file
/// lands under the subject name every time and the only thing under test
/// is whether the majority can take it away.
#[tokio::test(flavor = "multi_thread")]
async fn a_majority_of_hash_yenc_names_does_not_take_the_posted_subject_name() {
    let real = "Movie.2024.German.DL.1080p.BluRay.x264.mkv";
    let minority = "a3f1c9e2b7d84605f2c1a9e3d7b40182";
    let hash = "d41d8cd98f00b204e9800998ecf8427e";
    let mut fx = Fixture::new("norarlatch63");
    let data = payload(120_000, 94);
    add_file_yenc_names(&mut fx, real, real, &data, 30_000, |p| {
        if p == 1 {
            minority.to_string()
        } else {
            hash.to_string()
        }
    });
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the #63-polarity post failed:\n{log}");
    let got = std::fs::read(out.join(real)).unwrap_or_else(|e| {
        panic!(
            "the subject's own name is not what landed - a majority of \
             yEnc hashes took it: {e}\n{log}"
        )
    });
    assert_eq!(got, data, "wrong bytes under the posted name\n{log}");
    assert!(
        !out.join(hash).exists() && !out.join(minority).exists(),
        "a yEnc header name was published beside the posted one\n{log}"
    );
    drop(fx);
}

/// W4-03's rule for this tier, and the last of the three guards: a
/// yEnc-header majority may DECLINE, but it may never replace a file
/// already sitting at the name it asks for.
///
/// The publish therefore goes through `publish_weak_name` and not
/// `publish_verified_name`. That difference is not academic - W4-03
/// (30 Aug 2026) is a post where a weak tier's rename replaced another
/// file at rc=0 with one `renamed X -> Y (replaced the previous copy)`
/// line as the only trace. The strong publish is right for the PAR2
/// tier, whose claim is an MD5 pair over the whole file and really is
/// authoritative over a previous run's copy. A repeated yEnc header is
/// not that, by a wide margin.
///
/// The shape here is the ordinary one: a re-download into a folder that
/// already holds a file of that name, from a previous run or another
/// job. `PublishedNames` cannot help - it knows only what THIS job
/// landed - so the belt is the filesystem's own answer, and declining is
/// the outcome the row calls acceptable.
///
/// Stalled so the minority name deterministically wins the write, which
/// is what puts the majority's rename on the table at all.
#[tokio::test(flavor = "multi_thread")]
async fn the_yenc_majority_declines_rather_than_replacing_a_file_already_there() {
    let mut fx = Fixture::new("norarlatchw403");
    let data = payload(120_000, 95);
    add_decoy_first_name(&mut fx, "Movie.2024.mkv", "Vt8jQp03WsE", &data, 30_000);
    // A previous run's copy, of different bytes, already at the name
    // this post's majority is about to ask for.
    let out = fx.dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let previous = payload(4_096, 96);
    std::fs::write(out.join("Movie.2024.mkv"), &previous).unwrap();
    let first_id = "<Vt8jQp03WsE-0-1@mock>";
    assert!(fx.articles.contains_key(first_id));
    let slow: std::collections::HashMap<String, u64> = fx
        .articles
        .keys()
        .filter(|k| *k != first_id)
        .map(|k| (k.clone(), 900))
        .collect();
    let chaos = Chaos {
        slow_ttfb: slow,
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(ok, "the post failed:\n{log}");
    assert_eq!(
        std::fs::read(out.join("Movie.2024.mkv")).unwrap(),
        previous,
        "the yEnc-name tier REPLACED a file that was already there - it \
         must publish weakly and decline. W4-03 is that defect measured \
         on another tier.\n{log}"
    );
    // ...and declining must not lose this download's own bytes: they
    // stay under the name the write path gave them.
    assert_eq!(
        std::fs::read(out.join("x.dat")).unwrap(),
        data,
        "declining the rename dropped the payload instead of leaving it \
         under its written name\n{log}"
    );
    drop(fx);
}
