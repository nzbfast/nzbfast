//! Regression tests pinning three confirmed index defects found by a
//! correctness review of the index (the C3, D3 and D2 cases).
//! Each test is written to FAIL against the defective code and pass
//! once the finding is fixed; an open finding ships `#[ignore]`d so the
//! suite stays green while it is open, and the `#[ignore]` comes off
//! when it is fixed. All three are fixed and running.

use crate::scratch;

use nzbkit::index::{BrowseQuery, BrowseSort, Credit, Index};
use nzbkit::nntp::OverEntry;

/// Fresh on-disk index in a per-test temp directory (same idiom as the
/// in-crate index tests - no tempdir dev-dependency in this crate).
fn temp_index(tag: &str) -> (Index, scratch::ScratchDir) {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-regr-{tag}-{}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    let ix = Index::open(&dir.join("index.db")).unwrap();
    (ix, dir)
}

fn entry(subject: &str, from: &str, id: &str, bytes: u64) -> OverEntry {
    OverEntry {
        number: 0,
        subject: subject.into(),
        from: from.into(),
        message_id: format!("<{id}>"),
        bytes,
        date: 0,
    }
}

/// Finding C3: the browse view's Category sort orders the `res` TEXT
/// column lexicographically, so a user sorting by Category (descending,
/// the default direction) sees 720p releases ranked ABOVE 2160p and
/// 1080p - the exact opposite of the "lead with the best encode" the
/// sort promises. A user picking the top row of a category gets a
/// worse encode than the index actually holds.
#[test]
fn category_sort_ranks_resolution_by_quality_not_lexicographically() {
    let (mut ix, _dir) = temp_index("c3");
    let mk =
        |f: &str, from: &str, id: &str| entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30);
    ix.ingest(
        "alt.binaries.test",
        &[
            mk("Alpha.Film.2020.480p.WEB.x264-GRP.mkv", "a@a", "r1"),
            mk("Bravo.Film.2021.2160p.BluRay.x265-GRP.mkv", "b@b", "r2"),
            mk("Charlie.Film.2022.720p.WEB.x264-GRP.mkv", "c@c", "r3"),
            mk("Delta.Film.2023.1080p.BluRay.x264-GRP.mkv", "d@d", "r4"),
        ],
        1_000,
    )
    .unwrap();
    let (rows, total) = ix
        .browse(&BrowseQuery {
            sort: BrowseSort::Kind,
            desc: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(total, 4);
    // All four are the same kind ("movie"), so within the category the
    // descending sort must lead with the best encode.
    let res: Vec<&str> = rows.iter().map(|r| r.res.as_str()).collect();
    assert_eq!(
        res,
        ["2160p", "1080p", "720p", "480p"],
        "Category sort (desc) must rank resolution by quality; \
         lexicographic TEXT ordering puts 720p above 2160p"
    );
}

/// Finding D3: `total_parts` is last-write-wins on re-ingest and part
/// numbers are unioned across batches. When a poster re-rars a release
/// reusing the same volume filenames, segments from BOTH generations
/// merge into one file row and the union satisfies the smaller total,
/// so the release is marked complete and its NZB mixes message-ids
/// from two incompatible rar sets. The user downloads a "complete"
/// release that extracts corrupt.
///
/// The expectation here CHANGED when TODO 136's scanner half landed.
/// The original guard's answer was to drop the conflicting batch, so
/// one row survived and the second generation was never indexed at all;
/// this asserted `rows.len() == 1`. `ingest` now routes the second
/// generation to its own release row, so the assertion is two rows,
/// neither complete, neither NZB mixing generations - which is what the
/// old single row could only approximate by throwing articles away.
#[test]
fn rerar_with_reused_filenames_must_not_mark_a_mixed_generation_complete() {
    let (mut ix, _dir) = temp_index("d3");
    let fname = "Echo.Film.2024.1080p.BluRay.x264-GRP.part1.rar";
    let poster = "poster@example.com";
    // Generation 1: a 5-part posting of which only parts 3..5 were seen
    // (parts 1 and 2 expired or were taken down). Incomplete, correctly.
    ix.ingest(
        "alt.binaries.test",
        &[
            entry(
                &format!("\"{fname}\" yEnc (3/5)"),
                poster,
                "gen1-p3",
                750_000,
            ),
            entry(
                &format!("\"{fname}\" yEnc (4/5)"),
                poster,
                "gen1-p4",
                750_000,
            ),
            entry(
                &format!("\"{fname}\" yEnc (5/5)"),
                poster,
                "gen1-p5",
                750_000,
            ),
        ],
        1_000,
    )
    .unwrap();
    let rows = ix.search("", 10).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].complete, "3 of 5 parts is incomplete");

    // Generation 2: the poster re-rars with different settings (now only
    // 3 parts) and reposts under the SAME filenames; parts 1 and 2 of
    // the new set arrive in a later scan batch.
    ix.ingest(
        "alt.binaries.test",
        &[
            entry(
                &format!("\"{fname}\" yEnc (1/3)"),
                poster,
                "gen2-p1",
                750_000,
            ),
            entry(
                &format!("\"{fname}\" yEnc (2/3)"),
                poster,
                "gen2-p2",
                750_000,
            ),
        ],
        2_000,
    )
    .unwrap();

    // Both generations are now indexed, side by side, under one stem.
    let rows = ix.search("", 10).unwrap();
    assert_eq!(rows.len(), 2, "the second generation was not indexed");
    // No coherent single-generation part set exists (gen2 is missing its
    // part 3; gen1 is missing parts 1 and 2), so NEITHER row may be
    // reported complete. Before the fix `total_parts` took the last
    // batch's 3, the unioned 5 part numbers satisfied
    // nsegs >= total_parts, and the single row flipped to complete.
    for rel in &rows {
        assert!(
            !rel.complete,
            "release {} marked complete from an incomplete generation",
            rel.id
        );
        // The corruption itself: one NZB carrying articles from two
        // incompatible rar sets, which is what "complete" would have
        // handed the user.
        let nzb = ix.make_nzb(rel.id).unwrap();
        assert!(
            !(nzb.contains("gen1-p4") && nzb.contains("gen2-p1")),
            "release {}'s NZB mixes message-ids from both generations",
            rel.id
        );
    }
}

/// Finding D2: `person_upsert`'s name fallback only refused rows whose
/// SAME handle type differed, so a person already pinned by one handle
/// type (a Wikidata Q-id) absorbed a same-named different person arriving
/// with the other handle type (a TVmaze id). The blank-fill UPDATE then
/// stamped the TVmaze id onto the wrong person, and every future credit
/// for that TVmaze id landed on the merged row: the person page showed
/// one human wearing two people's filmographies, and nothing in the UI
/// could split them apart again.
///
/// Fixed by giving the two id spaces something in common to disagree
/// about rather than by tightening the query - which could only have
/// forked the one person the merge exists for. `born` is that fact: it is
/// what BOTH cast providers publish (TVmaze in the cast payload,
/// Wikidata as P569), so it is the one that fires on this exact shape.
///
/// The IMDb id is matched too and is the stronger claim where it exists,
/// but only Wikidata can supply one for a person - measured 27 Jul 2026,
/// TVmaze exposes no person-level IMDb id by any route. See
/// `person_upsert`'s doc comment.
#[test]
fn person_upsert_keeps_two_people_apart_once_each_has_a_different_handle_type() {
    let (ix, _dir) = temp_index("d2");
    // "Chris Evans" the actor, from a film's cast: a Wikidata Q-id, and
    // the IMDb id and birthday that ride along with it.
    let actor = ix
        .person_upsert(&Credit {
            name: "Chris Evans".into(),
            role: "actor".into(),
            wikidata_qid: "Q170572".into(),
            imdb: "nm0262635".into(),
            born: "1981-06-13".into(),
            ..Default::default()
        })
        .unwrap();
    // "Chris Evans" the TV presenter, from a show's cast: a different
    // human, carrying a handle the actor's row does not have and no IMDb
    // id at all, because TVmaze has none to give.
    let presenter = ix
        .person_upsert(&Credit {
            name: "Chris Evans".into(),
            role: "presenter".into(),
            tvmaze_id: 42,
            born: "1966-04-01".into(),
            ..Default::default()
        })
        .unwrap();
    assert_ne!(
        actor, presenter,
        "a credit identified by TVmaze must not merge into a row already \
         identified by Wikidata just because the names match"
    );
    // The actor's row must not have been stamped with the presenter's id.
    let row = ix.person_get(actor).unwrap().unwrap();
    assert_eq!(
        row.tvmaze_id, 0,
        "the Wikidata-identified actor absorbed the presenter's TVmaze id"
    );
    assert_eq!(row.born, "1981-06-13", "the birth date was not stored");

    // The other half of the same rule: a credit that contradicts nothing
    // still merges. This is the shape the fix must not break - one human
    // whose TV credit and film credit share only a name and a birthday.
    let (ix, _dir) = temp_index("d2-merge");
    let film = ix
        .person_upsert(&Credit {
            name: "Tom Cruise".into(),
            role: "actor".into(),
            wikidata_qid: "Q37079".into(),
            imdb: "nm0000129".into(),
            born: "1962-07-03".into(),
            ..Default::default()
        })
        .unwrap();
    let tv = ix
        .person_upsert(&Credit {
            name: "Tom Cruise".into(),
            role: "actor".into(),
            tvmaze_id: 555,
            born: "1962-07-03".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        film, tv,
        "one human seen by two providers forked into two rows"
    );
    let row = ix.person_get(film).unwrap().unwrap();
    assert_eq!(
        (row.tvmaze_id, row.wikidata_qid.as_str(), row.imdb.as_str()),
        (555, "Q37079", "nm0000129"),
        "the merged row did not collect both handles"
    );
}

/// The IMDb id is an identity claim in its own right, in both
/// directions: two people who differ on one are different people even
/// when everything else about the credit matches, and one person is
/// found by it even when the providers agree on nothing else.
///
/// This is the join the `people.imdb` column was always shaped for. It
/// only fires between providers that both publish an `nm…` id, which
/// today means Wikidata and anything added later - see `person_upsert`
/// for why TVmaze is not one of them, and why `born` carries the
/// cross-provider case instead.
#[test]
fn person_upsert_separates_two_people_who_differ_on_the_imdb_id() {
    let (ix, _dir) = temp_index("d2-imdb");
    let a = ix
        .person_upsert(&Credit {
            name: "Michael Jordan".into(),
            role: "actor".into(),
            imdb: "nm0001392".into(),
            ..Default::default()
        })
        .unwrap();
    let b = ix
        .person_upsert(&Credit {
            name: "Michael Jordan".into(),
            role: "actor".into(),
            imdb: "nm2027656".into(),
            ..Default::default()
        })
        .unwrap();
    assert_ne!(a, b, "two different IMDb ids are two different people");
    // …and the same id is the same person, arriving with a handle the
    // first credit never had.
    let again = ix
        .person_upsert(&Credit {
            name: "Michael Jordan".into(),
            role: "actor".into(),
            imdb: "nm0001392".into(),
            tvmaze_id: 77,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(again, a, "the IMDb id did not identify the person it names");
    let row = ix.person_get(a).unwrap().unwrap();
    assert_eq!(
        row.tvmaze_id, 77,
        "the second provider's handle was not filled in"
    );
    // A credit that knows only the name still lands on one of them
    // rather than forking a third row: a blank never contradicts.
    let bare = ix
        .person_upsert(&Credit {
            name: "Michael Jordan".into(),
            role: "actor".into(),
            ..Default::default()
        })
        .unwrap();
    assert!(
        bare == a || bare == b,
        "a handle-less credit forked a new row"
    );
}

// ---- TODO 136's scanner half: the generation split in `ingest` -------
//
// §136 fixed the repost collision in `promote_spot` and left it live in
// the scanner, on the understanding that the D3 guard at least limited
// the damage there. It does not - see the first test, which is the shape
// D3 cannot see at all.
//
// Four of these five fail on the pre-fix code. The fifth
// (`an_ordinary_release_arriving_in_chunks_stays_one_release`) passes
// BOTH ways on purpose: it is the no-regression half, and what it
// catches is somebody "tightening" the adopt rule from "contradicted?"
// to "proven the same?", which would fork a card per scan chunk for
// every release in the index.

/// The case the D3 guard cannot see at all, and the reason "limits the
/// damage to one file" overstated what it did: when the re-rar keeps the
/// SAME volume size, `total_parts` agrees, the guard never fires, and
/// the two article sets union into one file row - part 2 silently
/// rewritten from generation 1's message-id to generation 2's. The union
/// then satisfies `nsegs >= total_parts` and the release goes COMPLETE
/// carrying one article from one posting and two from another.
#[test]
fn a_same_size_rerar_does_not_complete_a_release_out_of_two_postings() {
    let (mut ix, _dir) = temp_index("gen-same-total");
    let fname = "Golf.Film.2024.1080p.BluRay.x264-GRP.part1.rar";
    let poster = "poster@example.com";
    let batch = |a: (&str, u32), b: (&str, u32)| {
        [
            entry(
                &format!("\"{fname}\" yEnc ({}/3)", a.1),
                poster,
                a.0,
                750_000,
            ),
            entry(
                &format!("\"{fname}\" yEnc ({}/3)", b.1),
                poster,
                b.0,
                750_000,
            ),
        ]
    };
    // Generation 1: parts 1 and 2 of 3.
    ix.ingest(
        "alt.binaries.test",
        &batch(("gen1-p1", 1), ("gen1-p2", 2)),
        1_000,
    )
    .unwrap();
    // Generation 2, re-rarred at the same volume size: parts 2 and 3.
    // Part 2 is the collision - same file, same part number, a different
    // message-id, which is proof and not a guess.
    ix.ingest(
        "alt.binaries.test",
        &batch(("gen2-p2", 2), ("gen2-p3", 3)),
        2_000,
    )
    .unwrap();

    let rows = ix.search("", 10).unwrap();
    assert_eq!(rows.len(), 2, "the repost did not get its own release row");
    for rel in &rows {
        assert!(
            !rel.complete,
            "release {} is 2 of 3 parts and was called complete",
            rel.id
        );
        let nzb = ix.make_nzb(rel.id).unwrap();
        assert!(
            !(nzb.contains("gen1-p1") && nzb.contains("gen2-p3")),
            "release {}'s NZB mixes articles from both postings",
            rel.id
        );
    }
}

/// The chunk-stability property the whole design turns on. A spot can
/// key its generation off a digest of the payload because it holds the
/// complete manifest; the scanner sees arbitrary slices, so a digest of
/// the slice would mint a fresh row per slice. Membership is decided by
/// AGREEMENT with what is stored instead: generation 2's later batches
/// share no part with generation 1 but also contradict nothing in
/// generation 2's own row, so they land on it.
///
/// Without this the ~0.6% repost case would fork a new card per scan
/// chunk - a worse failure than the one being fixed.
#[test]
fn later_batches_of_a_repost_land_on_the_row_it_already_minted() {
    let (mut ix, _dir) = temp_index("gen-chunk-stable");
    let stem = "Hotel.Film.2024.1080p.BluRay.x264-GRP";
    let poster = "poster@example.com";
    let art = |f: &str, part: u32, id: &str| {
        entry(
            &format!("\"{stem}.{f}\" yEnc ({part}/2)"),
            poster,
            id,
            750_000,
        )
    };
    // Generation 1, complete: two files of two parts each.
    ix.ingest(
        "alt.binaries.test",
        &[
            art("part1.rar", 1, "g1-a1"),
            art("part1.rar", 2, "g1-a2"),
            art("part2.rar", 1, "g1-b1"),
            art("part2.rar", 2, "g1-b2"),
        ],
        1_000,
    )
    .unwrap();
    assert_eq!(ix.search("", 10).unwrap().len(), 1);

    // Generation 2 arrives in two chunks. The FIRST contradicts
    // generation 1 (part1.rar part 1 under a new id) and mints a row.
    ix.ingest(
        "alt.binaries.test",
        &[art("part1.rar", 1, "g2-a1"), art("part1.rar", 2, "g2-a2")],
        2_000,
    )
    .unwrap();
    let after_first = ix.search("", 10).unwrap();
    assert_eq!(after_first.len(), 2, "the repost did not fork a row");

    // The SECOND chunk covers a file the new row has never seen, so it
    // shares no part number with EITHER row. It must still land on the
    // row its own generation minted rather than forking a third.
    ix.ingest(
        "alt.binaries.test",
        &[art("part2.rar", 1, "g2-b1"), art("part2.rar", 2, "g2-b2")],
        3_000,
    )
    .unwrap();
    let rows = ix.search("", 10).unwrap();
    assert_eq!(
        rows.len(),
        2,
        "a later chunk of the same repost minted a third card"
    );
    // And it landed on the right one: generation 2's row is now the
    // complete four-article set, with nothing of generation 1 in it.
    let g2 = rows
        .iter()
        .find(|r| ix.make_nzb(r.id).unwrap().contains("g2-a1"))
        .expect("generation 2's row vanished");
    let nzb = ix.make_nzb(g2.id).unwrap();
    for id in ["g2-a1", "g2-a2", "g2-b1", "g2-b2"] {
        assert!(nzb.contains(id), "{id} did not reach generation 2's row");
    }
    for id in ["g1-a1", "g1-a2", "g1-b1", "g1-b2"] {
        assert!(!nzb.contains(id), "{id} leaked into generation 2's row");
    }
}

/// The in-memory half. `clusters` merges by part number BEFORE the
/// database is consulted, so both generations inside ONE OVER window -
/// what a backfill leg spanning the weeks between a post and its repost
/// routinely returns - used to lose one article per colliding part
/// without any code ever seeing a conflict. The pass defers what it
/// cannot place and re-drives it against the rows it just committed, so
/// there is one arbiter rather than two.
#[test]
fn one_over_window_holding_both_generations_keeps_every_article() {
    let (mut ix, _dir) = temp_index("gen-one-window");
    let fname = "India.Film.2024.1080p.BluRay.x264-GRP.part1.rar";
    let poster = "poster@example.com";
    // A single batch carrying both postings of the same two parts.
    ix.ingest(
        "alt.binaries.test",
        &[
            entry(&format!("\"{fname}\" yEnc (1/2)"), poster, "g1-p1", 750_000),
            entry(&format!("\"{fname}\" yEnc (2/2)"), poster, "g1-p2", 750_000),
            entry(&format!("\"{fname}\" yEnc (1/2)"), poster, "g2-p1", 750_000),
            entry(&format!("\"{fname}\" yEnc (2/2)"), poster, "g2-p2", 750_000),
        ],
        1_000,
    )
    .unwrap();
    let rows = ix.search("", 10).unwrap();
    assert_eq!(
        rows.len(),
        2,
        "both generations arrived in one window and were folded into one row"
    );
    // Every article survived, and each row holds exactly one posting.
    let nzbs: Vec<String> = rows.iter().map(|r| ix.make_nzb(r.id).unwrap()).collect();
    for id in ["g1-p1", "g1-p2", "g2-p1", "g2-p2"] {
        assert!(
            nzbs.iter().any(|n| n.contains(id)),
            "{id} was dropped by the in-memory clustering"
        );
    }
    for nzb in &nzbs {
        assert!(
            !(nzb.contains("g1-p1") && nzb.contains("g2-p2")),
            "one row mixes both postings"
        );
    }
}

/// The other half of the "unkeyed means unknown" rule §136 settled for
/// spots, and the reason the adopt test asks about CONTRADICTION rather
/// than about proof of sameness. An ordinary release that arrives over
/// many scan chunks shares no part number between chunks, so a rule
/// demanding positive evidence of sameness would fork a card per chunk
/// for every release in the index. Silence adopts.
#[test]
fn an_ordinary_release_arriving_in_chunks_stays_one_release() {
    let (mut ix, _dir) = temp_index("gen-no-false-fork");
    let stem = "Juliet.Film.2024.1080p.BluRay.x264-GRP";
    let poster = "poster@example.com";
    for (n, id) in [(1, "c1"), (2, "c2"), (3, "c3"), (4, "c4")] {
        ix.ingest(
            "alt.binaries.test",
            &[entry(
                &format!("\"{stem}.part{n}.rar\" yEnc (1/1)"),
                poster,
                id,
                750_000,
            )],
            1_000 + n as i64,
        )
        .unwrap();
    }
    let rows = ix.search("", 10).unwrap();
    assert_eq!(rows.len(), 1, "a chunked arrival forked into several cards");
    assert!(rows[0].complete, "the release did not converge on complete");
    let nzb = ix.make_nzb(rows[0].id).unwrap();
    for id in ["c1", "c2", "c3", "c4"] {
        assert!(nzb.contains(id), "{id} did not reach the release");
    }
}
