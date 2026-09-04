//! The maintenance suite: what the two reapers prune and what they leave,
//! the split-part merge and PAR2 sidecar fold, NZB synthesis, the size
//! accounting behind the M32 cap, and compaction (TODO 106 code motion
//! out of maintenance.rs, behaviour unchanged).

use super::*;
use crate::index::testutil::{entry, teardown};

/// A prune budget no test can spend: the two reapers take a
/// deadline, and every case except the budget test itself is about
/// what they reap, not when they stop.
fn forever() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(3_600)
}

/// R3: the orphan sweep at the tail of `prune_size` stopped running
/// on every call. It runs when the prune deleted something, and
/// once on an index that has never been swept - the
/// historical-repair pass for the autocommit era, which is what the
/// stamp records. What it must never do is let an orphan outlive a
/// committed delete: the recycled rowid would adopt it.
#[test]
fn prune_size_sweeps_orphans_once_then_only_when_it_deleted() {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-sweep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ix = Index::open(&dir.join("index.db")).unwrap();
    // Children of a release that is not there: exactly what a
    // pre-transaction crash left behind.
    let orphan = |id: i64| {
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts) VALUES(?1, 'a.rar', 1)",
                [id],
            )
            .unwrap();
        ix.db
            .execute(
                "INSERT INTO pre_corr(release_id, predb_id, score, delta, at)
                 VALUES(?1, 1, 900, 0, 0)",
                [id],
            )
            .unwrap();
    };
    let orphans = || {
        ix.db
            .query_row(
                "SELECT (SELECT COUNT(*) FROM files WHERE release_id NOT IN
                           (SELECT id FROM releases))
                      + (SELECT COUNT(*) FROM pre_corr WHERE release_id NOT IN
                           (SELECT id FROM releases))",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap()
    };

    orphan(901);
    assert_eq!(ix.prune_size(1, 5_000).unwrap(), 0, "nothing to prune");
    assert_eq!(orphans(), 0, "the historical-repair pass swept anyway");
    assert_eq!(ix.kv_get("orphan_sweep_done_v1").as_deref(), Some("1"));

    // Stamped, and this call deletes nothing: the two anti-joins -
    // the point of the gate - are skipped, so the orphan survives.
    orphan(902);
    assert_eq!(ix.prune_size(1, 5_000).unwrap(), 0);
    assert_eq!(orphans(), 2, "a no-op prune no longer walks `files`");

    // A prune that deletes re-arms the sweep, and it clears the
    // rows it just orphaned along with the ones it skipped: nothing
    // a recycled id could adopt survives the commit.
    ix.db
        .execute(
            "INSERT INTO releases(id, stem, poster, grp, total_bytes)
             VALUES(903, 'Huge.Rel', 'p', 'g', 9_000)",
            [],
        )
        .unwrap();
    orphan(903);
    assert_eq!(ix.prune_size(1, 5_000).unwrap(), 1, "oversize pruned");
    assert_eq!(orphans(), 0, "the deleting prune swept");

    // Crash recovery: an index whose sweep never got to stamp (the
    // stamp is written in the sweep's own transaction, so this is
    // the only shape a rollback can leave) sweeps on the next call
    // whatever the prune matched.
    ix.db
        .execute("DELETE FROM kv WHERE k='orphan_sweep_done_v1'", [])
        .unwrap();
    orphan(904);
    assert_eq!(ix.prune_size(1, 5_000).unwrap(), 0);
    assert_eq!(orphans(), 0, "an unstamped index sweeps unconditionally");
    teardown(&dir, ix);
}

/// A4: `stats_cached` memoizes the full-table-scan figures per
/// connection. Within the TTL a write - even one on this very
/// connection - is invisible (a progress line tolerates that);
/// a zero TTL always recomputes; and an exact `stats()` call
/// reseeds the memo for free.
#[test]
fn stats_cached_serves_the_memo_within_ttl_and_stats_reseeds_it() {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-statsmemo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ix = Index::open(&dir.join("index.db")).unwrap();
    let ins = |stem: &str| {
        ix.db
            .execute(
                "INSERT INTO releases(stem, poster, grp, first_posted, complete)
                 VALUES(?1, 'p', 'g', 1000, 1)",
                [stem],
            )
            .unwrap();
    };
    let ttl = std::time::Duration::from_secs(3_600);
    ins("a");
    assert_eq!(ix.stats_cached(ttl).unwrap(), (1, 1), "cold memo computes");
    ins("b");
    assert_eq!(
        ix.stats_cached(ttl).unwrap(),
        (1, 1),
        "within the TTL the memo is served - the new row stays unseen"
    );
    assert_eq!(
        ix.stats_cached(std::time::Duration::ZERO).unwrap(),
        (2, 2),
        "a zero TTL always recomputes"
    );
    ins("c");
    assert_eq!(ix.stats().unwrap(), (3, 3), "the exact query sees all");
    ins("d");
    assert_eq!(
        ix.stats_cached(ttl).unwrap(),
        (3, 3),
        "stats() reseeded the memo in passing"
    );
    teardown(&dir, ix);
}

/// The sampler's pick, after it stopped sorting the whole table
/// (see `Index::oracle_pick`). The seek draw changed HOW candidates
/// are found; what it must not change is which of them wins - a
/// never-sampled release outranks a sampled one, and junk stays out
/// of the sample entirely.
#[test]
fn oracle_pick_prefers_the_unsampled_and_skips_junk() {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-opick-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ix = Index::open(&dir.join("index.db")).unwrap();
    ix.db
        .execute(
            "INSERT INTO releases(stem, poster, grp, first_posted, junk, oracle_at)
             VALUES('sampled','p','g',1000, 0, 500),
                   ('never','p','g',2000, 0, 0),
                   ('junky','p','g',3000, 90, 0)",
            [],
        )
        .unwrap();

    // Seeded so the draw is replayable; the window is tiny here, so
    // every seek lands on the same three rows either way.
    let picked = ix.oracle_pick_seeded(2, 7).unwrap();
    let names: Vec<i64> = picked.iter().map(|&(_, _, posted)| posted).collect();
    // Never-sampled first, sampled second, junk not at all.
    assert_eq!(names, vec![2000, 1000], "picked {picked:?}");

    // Stamping the unsampled row rotates the pick, which is what
    // stops one release pinning the sampler forever.
    let rid = picked[0].0;
    ix.oracle_mark(rid, 9_000).unwrap();
    let after = ix.oracle_pick_seeded(1, 7).unwrap();
    assert_eq!(after.first().map(|r| r.2), Some(1000), "got {after:?}");

    teardown(&dir, ix);
}

/// The repost table: remember once, recognise later, and never let a
/// second download rewrite what the first one taught us on no better
/// evidence than turning up second.
#[test]
fn par_hashes_remember_first_and_recognise_reposts() {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-ph-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ix = Index::open(&dir.join("index.db")).unwrap();
    let pairs = |hs: &[&str]| -> Vec<(String, String)> {
        hs.iter()
            .map(|h| ((*h).to_string(), format!("{h}.r00")))
            .collect()
    };
    let weak = NameEvidence::Hash16kLen;

    // Nothing known yet.
    assert_eq!(ix.par_hash_lookup(&pairs(&["aa", "bb"])).unwrap(), None);

    let named = pairs(&["aa", "bb", "cc"]);
    assert_eq!(
        ix.par_hash_remember(
            &named,
            "Example.Movie.2019.1080p-GRP",
            "m:example movie:2019",
            100,
            weak,
        )
        .unwrap(),
        3
    );
    // A repost whose sidecar shares ONE volume fingerprint is the
    // same bytes, and one hit answers for the whole set - and the
    // answer says WHICH fingerprint proved it.
    assert_eq!(
        ix.par_hash_lookup(&pairs(&["zz", "cc"])).unwrap(),
        Some((
            "cc".into(),
            "Example.Movie.2019.1080p-GRP".into(),
            "m:example movie:2019".into()
        ))
    );

    // The obfuscated repost must NOT overwrite the good name: the
    // first writer knew what it was, and every future repost depends
    // on that answer staying put. It must not CONTEST it either - a
    // hash is not a claim, so it has no standing to make the row
    // ambiguous, and a table that fell silent whenever an obfuscated
    // repost arrived would answer nothing for exactly the arrivals it
    // exists to serve.
    assert_eq!(
        ix.par_hash_remember(&named, "8a7f2c1b9d0e4f", "", 200, weak)
            .unwrap(),
        0,
        "a later download rewrote a fingerprint it did not name"
    );
    assert_eq!(
        ix.par_hash_lookup(&pairs(&["aa"])).unwrap().unwrap().1,
        "Example.Movie.2019.1080p-GRP"
    );

    // A nameless job records nothing at all rather than a blank row
    // that would then shadow the real name forever.
    assert_eq!(
        ix.par_hash_remember(&pairs(&["dd"]), "  ", "", 300, weak)
            .unwrap(),
        0
    );
    assert_eq!(ix.par_hash_lookup(&pairs(&["dd"])).unwrap(), None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// W7-01: a later naming with STRONGER evidence corrects the row, and
/// a weaker one still cannot. The table used to be first-writer-wins
/// forever, so a fingerprint a subject parse named wrongly stayed
/// wrong for every future repost even after the payload's own bytes
/// said otherwise.
#[test]
fn a_proof_corrects_a_name_a_weak_lane_taught() {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-phfix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ix = Index::open(&dir.join("index.db")).unwrap();
    let one = vec![("aa".to_string(), "aa.r00".to_string())];

    ix.par_hash_remember(
        &one,
        "Wrong.Movie.2019.1080p",
        "m:wrong movie:2019",
        100,
        NameEvidence::Hash16kLen,
    )
    .unwrap();
    // The pesto lane matched the payload's own bytes against this
    // set's FileDesc. That outranks a posted stem, so it lands.
    assert_eq!(
        ix.par_hash_remember(
            &one,
            "Real.Movie.2019.1080p",
            "m:real movie:2019",
            200,
            NameEvidence::Par2SetId
        )
        .unwrap(),
        1
    );
    let hit = ix.par_hash_lookup(&one).unwrap().unwrap();
    assert_eq!(hit.1, "Real.Movie.2019.1080p");
    assert_eq!(hit.2, "m:real movie:2019");

    // And the correction does not swing back: a weak lane disagreeing
    // with a proof is not news, and must neither replace it nor make
    // the row ambiguous.
    assert_eq!(
        ix.par_hash_remember(
            &one,
            "Wrong.Movie.2019.1080p",
            "",
            300,
            NameEvidence::Hash16kLen
        )
        .unwrap(),
        0
    );
    assert_eq!(
        ix.par_hash_lookup(&one).unwrap().unwrap().1,
        "Real.Movie.2019.1080p"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// W7-03: `hash16k` is the identical-head twin family, so two jobs
/// with equally good claims and different names is not an answer.
/// Both the per-row contest and the cross-member disagreement decline,
/// and a later proof can still settle the row.
#[test]
fn equally_evidenced_disagreement_declines_and_a_proof_settles_it() {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-phamb-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ix = Index::open(&dir.join("index.db")).unwrap();
    let pairs = |hs: &[&str]| -> Vec<(String, String)> {
        hs.iter()
            .map(|h| ((*h).to_string(), format!("{h}.r00")))
            .collect()
    };
    let weak = NameEvidence::Hash16kLen;

    ix.par_hash_remember(&pairs(&["aa"]), "Alpha.Movie.2019.1080p", "", 100, weak)
        .unwrap();
    assert_eq!(
        ix.par_hash_remember(&pairs(&["aa"]), "Beta.Show.2021.1080p", "", 200, weak)
            .unwrap(),
        1,
        "the second, equally-evidenced name must mark the row contested"
    );
    assert_eq!(
        ix.par_hash_lookup(&pairs(&["aa"])).unwrap(),
        None,
        "a fingerprint claimed by two names is not an answer"
    );
    // A third weak claim changes nothing - the row is already refused,
    // and re-marking it would be a write per arriving repost forever.
    assert_eq!(
        ix.par_hash_remember(&pairs(&["aa"]), "Gamma.Movie.2020.1080p", "", 250, weak)
            .unwrap(),
        0
    );

    // CROSS-MEMBER: two members of one set that answer two different
    // releases. Each row on its own is a perfectly good answer, which
    // is why taking the first hit read as one.
    ix.par_hash_remember(&pairs(&["bb"]), "Alpha.Movie.2019.1080p", "", 100, weak)
        .unwrap();
    ix.par_hash_remember(&pairs(&["cc"]), "Beta.Show.2021.1080p", "", 100, weak)
        .unwrap();
    assert!(ix.par_hash_lookup(&pairs(&["bb"])).unwrap().is_some());
    assert!(ix.par_hash_lookup(&pairs(&["cc"])).unwrap().is_some());
    assert_eq!(
        ix.par_hash_lookup(&pairs(&["bb", "cc"])).unwrap(),
        None,
        "one set naming two releases answers nothing"
    );

    // Re-teaching the HELD name at the same weak tier must not settle
    // the contest either. Otherwise the twin that happens to be
    // downloaded twice clears an ambiguity it never resolved, and the
    // more-frequent poster wins - first-writer-wins wearing a hat.
    assert_eq!(
        ix.par_hash_remember(&pairs(&["aa"]), "Alpha.Movie.2019.1080p", "", 260, weak)
            .unwrap(),
        0
    );
    assert_eq!(ix.par_hash_lookup(&pairs(&["aa"])).unwrap(), None);

    // A proof settles the contested row: the name it names wins, the
    // contest is over, and the table starts answering again. Here it
    // names the OTHER contender, so it replaces as well as settles.
    assert_eq!(
        ix.par_hash_remember(
            &pairs(&["aa"]),
            "Beta.Show.2021.1080p",
            "t:beta show",
            300,
            NameEvidence::Par2SetId
        )
        .unwrap(),
        1
    );
    assert_eq!(
        ix.par_hash_lookup(&pairs(&["aa"])).unwrap().unwrap().1,
        "Beta.Show.2021.1080p"
    );

    // And a proof AGREEING with the held name settles it too - the
    // contest was between that name and another, and this side just
    // won on evidence.
    ix.par_hash_remember(&pairs(&["ee"]), "Alpha.Movie.2019.1080p", "", 100, weak)
        .unwrap();
    ix.par_hash_remember(&pairs(&["ee"]), "Beta.Show.2021.1080p", "", 110, weak)
        .unwrap();
    assert_eq!(ix.par_hash_lookup(&pairs(&["ee"])).unwrap(), None);
    assert_eq!(
        ix.par_hash_remember(
            &pairs(&["ee"]),
            "Alpha.Movie.2019.1080p",
            "",
            120,
            NameEvidence::Par2SetId
        )
        .unwrap(),
        1
    );
    assert_eq!(
        ix.par_hash_lookup(&pairs(&["ee"])).unwrap().unwrap().1,
        "Alpha.Movie.2019.1080p"
    );

    // A proof AGREEING with an uncontested weak row upgrades its tier
    // rather than doing nothing, so the next weak disagreement loses
    // instead of contesting.
    assert_eq!(
        ix.par_hash_remember(
            &pairs(&["bb"]),
            "Alpha.Movie.2019.1080p",
            "",
            400,
            NameEvidence::Par2SetId
        )
        .unwrap(),
        1
    );
    assert_eq!(
        ix.par_hash_remember(&pairs(&["bb"]), "Delta.Movie.2022.1080p", "", 500, weak)
            .unwrap(),
        0
    );
    assert_eq!(
        ix.par_hash_lookup(&pairs(&["bb"])).unwrap().unwrap().1,
        "Alpha.Movie.2019.1080p"
    );

    // The STRONGEST hit is what comes back when members agree, because
    // the hash it returns is the proving key the claims layer records.
    ix.par_hash_remember(&pairs(&["dd"]), "Alpha.Movie.2019.1080p", "", 600, weak)
        .unwrap();
    assert_eq!(
        ix.par_hash_lookup(&pairs(&["dd", "bb"]))
            .unwrap()
            .unwrap()
            .0,
        "bb"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn retention_prune_reaps_old_spares_recent_hidden_and_undated() {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-ret-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    const DAY: i64 = 86_400;
    let now = 1_000 * DAY;
    // now: full-size rows at various ages + one undated + one hidden.
    let mut old = entry(
        "\"Ancient.Movie.2001.1080p.mkv\" yEnc (1/1)",
        "p@x",
        "r1",
        4 << 30,
    );
    old.date = now - 800 * DAY;
    let mut recent = entry(
        "\"Fresh.Movie.2026.1080p.mkv\" yEnc (1/1)",
        "p@x",
        "r2",
        4 << 30,
    );
    recent.date = now - 10 * DAY;
    let mut hidden = entry(
        "\"Hidden.Movie.2000.1080p.mkv\" yEnc (1/1)",
        "p@x",
        "r3",
        4 << 30,
    );
    hidden.date = now - 900 * DAY;
    let undated = entry(
        "\"Undated.Movie.2010.1080p.mkv\" yEnc (1/1)",
        "p@x",
        "r4",
        4 << 30,
    );
    ix.ingest("alt.test", &[old, recent, hidden, undated], now)
        .unwrap();
    ix.hide_title(&crate::release::parse_release("Hidden.Movie.2000.1080p").key)
        .unwrap();

    // Keep 2 years (~730 days): the 800/900-day rows are candidates,
    // but the 900-day one is hidden and must survive.
    let (removed, done) = ix.prune_age(730 * DAY, now, forever()).unwrap();
    assert!(
        done,
        "a prune with budget to spare reports itself caught up"
    );
    assert_eq!(removed, 1, "only the old non-hidden row");
    assert_eq!(ix.search("ancient", 10).unwrap().len(), 0, "old reaped");
    assert_eq!(ix.search("fresh", 10).unwrap().len(), 1, "recent kept");
    assert_eq!(
        ix.search("hidden movie", 10).unwrap().len(),
        1,
        "hidden kept"
    );
    assert_eq!(
        ix.search("undated", 10).unwrap().len(),
        1,
        "unknown-date kept"
    );
    // FTS index stayed in sync (rowid count == releases count) and no
    // orphan files rows survived the batch delete.
    let (rels, _) = ix.stats().unwrap();
    let fts_rows: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM rel_fts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(fts_rows as u64, rels, "FTS in sync");
    let orphans: i64 = ix
        .db
        .query_row(
            "SELECT COUNT(*) FROM files WHERE release_id NOT IN (SELECT id FROM releases)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(orphans, 0, "no orphan files rows");
    teardown(&dir, ix);
}

#[test]
fn stale_partials_reaps_dead_junk_spares_wall_and_settle() {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-stale-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    const DAY: i64 = 86_400;
    let now = 1_000 * DAY;
    // Obfuscated hash name -> junk>=50, missing parts, OLD -> dead, reaped.
    let mut dead = entry(
        "\"ugpoqs3l6bthdkgbn1ktwkl2wwxju8.part1.rar\" yEnc (1/9)",
        "p@x",
        "s1",
        750_000,
    );
    dead.date = now - 30 * DAY;
    // Same junk shape and an OLD POST, but only just indexed (mid-backfill
    // into history): first_seen is recent, so the reaper must spare it - the
    // settle clock is index age, not post age. (The old code reaped this.)
    let mut fresh = entry(
        "\"zzq9x2m7v5t8k1n3b6h4j0w2e5r7y9.part1.rar\" yEnc (1/9)",
        "p@x",
        "s2",
        750_000,
    );
    fresh.date = now - 30 * DAY;
    // Wall-visible (parses clean, junk<50), missing parts, OLD -> the
    // always-on reaper must NOT touch it (opt-in age prune's job).
    let mut real = entry(
        "\"Real.Show.S01E01.720p.WEB.x264-GRP.mkv\" yEnc (1/9)",
        "p@x",
        "s3",
        400 << 20,
    );
    real.date = now - 30 * DAY;
    // Junk + COMPLETE + old -> not this reaper (spares complete blobs).
    let mut donejunk = entry(
        "\"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3.mkv\" yEnc (1/1)",
        "p@x",
        "s4",
        750_000,
    );
    donejunk.date = now - 30 * DAY;
    // dead/real/donejunk were indexed long ago (first_seen old); `fresh`
    // is indexed now, so its settle window has not elapsed.
    ix.ingest("alt.test", &[dead, real, donejunk], now - 30 * DAY)
        .unwrap();
    ix.ingest("alt.test", &[fresh], now).unwrap();

    let (removed, done) = ix.prune_stale_partials(7 * DAY, now, forever()).unwrap();
    assert!(
        done,
        "a prune with budget to spare reports itself caught up"
    );
    assert_eq!(removed, 1, "only the old junk missing-parts row");
    assert_eq!(
        ix.search("ugpoqs3l6bthdkgbn1ktwkl2wwxju8", 10)
            .unwrap()
            .len(),
        0,
        "dead junk reaped"
    );
    assert_eq!(
        ix.search("zzq9x2m7v5t8k1n3b6h4j0w2e5r7y9", 10)
            .unwrap()
            .len(),
        1,
        "in settle window"
    );
    assert_eq!(
        ix.search("real show", 10).unwrap().len(),
        1,
        "wall-visible spared"
    );
    assert_eq!(
        ix.search("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3", 10)
            .unwrap()
            .len(),
        1,
        "complete junk spared"
    );
    teardown(&dir, ix);
}

/// A deadline the caller has already spent still buys ONE batch and
/// then hands the write mutex back, saying it is not caught up.
///
/// This is the 15 Aug wedge, in the small. The reap's batching
/// bounded a transaction and nothing else, so an entry with more
/// rows than a batch simply kept going: on a live 34.6 M-row index
/// that was six hours holding the index write mutex, with every
/// other index caller parked behind it - the download runner among
/// them, which left a finished job frozen in the queue reading
/// "Extracting" for the life of the daemon. The two assertions are
/// the whole contract: it stops at ONE batch, and it SAYS there is
/// more, which is what stops the caller stamping its hourly clock
/// and walking away.
#[test]
fn stale_partials_stops_on_the_deadline_and_reports_more_to_do() {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-budget-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    const DAY: i64 = 86_400;
    let now = 1_000 * DAY;
    // One batch (8000) and change, all in the reaper's sights:
    // obfuscated stem (junk >= 50), missing parts, long settled.
    let dead: Vec<crate::nntp::OverEntry> = (0..8_500u32)
        .map(|i| {
            let mut e = entry(
                &format!("\"ugpoqs3l6bthdkgbn1ktwkl2ww{i:04x}.part1.rar\" yEnc (1/9)"),
                "p@x",
                &format!("b{i}"),
                750_000,
            );
            e.date = now - 30 * DAY;
            e
        })
        .collect();
    ix.ingest("alt.test", &dead, now - 30 * DAY).unwrap();

    let spent = std::time::Instant::now() - std::time::Duration::from_secs(1);
    let (removed, done) = ix.prune_stale_partials(7 * DAY, now, spent).unwrap();
    // One CHUNK, not one 8000-row batch. That is the 20 Aug tightening:
    // the batch used to be the unbounded thing left, since a row count
    // says nothing about what a row costs to delete (see
    // `prune_batch_until`). A spent budget now buys the smallest unit of
    // work there is, and the deleted rows are the FIRST 64 - the reaper
    // walks in rowid order, so the tail is untouched, not skipped.
    assert_eq!(
        removed, 64,
        "a spent budget buys exactly one chunk, never a whole batch"
    );
    assert!(!done, "rows are still waiting - the caller must come back");

    // ...and coming back finishes it, which is what makes the
    // hourly stamp safe to withhold above. Nothing may be lost in
    // between: a short batch parks the cursor on the last id that
    // actually went, so the next pass picks up the other 8,000.
    let (rest, done) = ix.prune_stale_partials(7 * DAY, now, forever()).unwrap();
    assert_eq!(rest, 8_436, "the remainder, on the next pass");
    assert!(done, "nothing left to reap");
    let left: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, 0, "a short batch skipped rows instead of resuming");
    teardown(&dir, ix);
}

/// The other half of the same wedge (read-only sweep 3, M9): the
/// SELECTION is bounded too, not just the loop around it.
///
/// A deadline checked between statements cannot stop the statement
/// that is running, and this reaper's own predicates have no index
/// to ride - so one selection was a full walk of the releases table
/// with the write mutex held, however long that took. Here the rows
/// worth reaping sit at the END of the table behind 8,000 that are
/// not: a walk that reaches them has scanned everything, which is
/// exactly what a spent budget must not buy. The stride keeps the
/// statement to its own slice of the rowid space and the cursor
/// makes the next call resume there rather than start again.
#[test]
fn stale_partials_bounds_one_selection_to_a_stride_of_the_table() {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-stride-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    const DAY: i64 = 86_400;
    let now = 1_000 * DAY;
    let old = now - 30 * DAY;
    // A full stride of rows this reaper must never take: junk-hidden
    // and long settled, but COMPLETE, so only a scan that reads them
    // all can tell.
    let whole: Vec<crate::nntp::OverEntry> = (0..8_000u32)
        .map(|i| {
            let mut e = entry(
                &format!("\"a1b2c3d4e5f6a1b2c3d4e5f6{i:06x}.mkv\" yEnc (1/1)"),
                "p@x",
                &format!("c{i}"),
                750_000,
            );
            e.date = old;
            e
        })
        .collect();
    ix.ingest("alt.test", &whole, old).unwrap();
    // ...and the reapable rows behind them, so they sit past the
    // first stride's rowids.
    let dead: Vec<crate::nntp::OverEntry> = (0..100u32)
        .map(|i| {
            let mut e = entry(
                &format!("\"ugpoqs3l6bthdkgbn1ktwkl2ww{i:04x}.part1.rar\" yEnc (1/9)"),
                "p@x",
                &format!("d{i}"),
                750_000,
            );
            e.date = old;
            e
        })
        .collect();
    ix.ingest("alt.test", &dead, old).unwrap();

    let spent = std::time::Instant::now() - std::time::Duration::from_secs(1);
    let (removed, done) = ix.prune_stale_partials(7 * DAY, now, spent).unwrap();
    assert_eq!(
        removed, 0,
        "a spent budget buys ONE stride of rowids - reaching the rows \
         beyond it means the whole table was scanned under the mutex"
    );
    assert!(!done, "the lap is unfinished - the caller must come back");

    // The next call resumes at the cursor rather than walking the
    // spared stride again, and finishes the lap.
    let (rest, done) = ix.prune_stale_partials(7 * DAY, now, forever()).unwrap();
    assert_eq!(rest, 100, "the reapable rows, on the next pass");
    assert!(done, "the lap finished");
    assert_eq!(
        ix.kv_get("stale_prune_cursor").as_deref(),
        Some("0"),
        "a finished lap parks the cursor so the next entry starts a fresh one"
    );
    teardown(&dir, ix);
}

/// The 2 Aug wedge's proximate cause was an index that had never been
/// analyzed, so this pins the two things the daily maintenance leg
/// needs from `optimize`: a database with no statistics at all comes
/// out of it WITH some (the `PRAGMA optimize` path alone would not
/// guarantee that - it only reconsiders tables the connection has
/// queried), and calling it again on an already-analyzed database is
/// a no-op rather than an error, because the leg runs it forever.
#[test]
fn optimize_creates_statistics_and_is_safe_to_repeat() {
    let dir = std::env::temp_dir().join(format!("nzbfast-analyze-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    let now = 1_753_000_000i64;
    let entries: Vec<crate::nntp::OverEntry> = (0..200)
        .map(|i| crate::nntp::OverEntry {
            number: i + 1,
            subject: format!("\"Stats.Test.S01E{i:02}.1080p-GRP.rar\" yEnc (1/1)"),
            from: "p@x".into(),
            date: now - (i as i64) * 3_600,
            message_id: format!("<stats{i}@x>"),
            bytes: 4096,
        })
        .collect();
    ix.ingest("alt.binaries.teevee", &entries, now).unwrap();

    let stat_rows = |ix: &Index| -> i64 {
        ix.db
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'sqlite_stat1'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(stat_rows(&ix), 0, "a fresh index has never been analyzed");
    ix.optimize().expect("first optimize");
    assert_eq!(
        stat_rows(&ix),
        1,
        "the first pass must produce statistics, not defer to a query that never came"
    );
    let analyzed: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM sqlite_stat1", [], |r| r.get(0))
        .unwrap();
    assert!(analyzed > 0, "and rows in them, not just the table");

    // Every later pass, forever. Nothing to do is the normal case.
    ix.optimize().expect("second optimize");
    ix.optimize().expect("third optimize");
    assert!(
        ix.stats().unwrap().0 > 0,
        "the index still answers after being analyzed"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A VACUUM is minutes of synchronous rewriting on a multi-GB index,
/// and the daemon holds it under the same gate a starting download
/// waits on - so the rewrite has to be abortable, or a job that
/// arrives mid-compact stalls for its whole duration. The property
/// that makes aborting safe: VACUUM is one transaction, so the
/// database is exactly as it was.
#[test]
fn a_compact_can_be_aborted_and_leaves_the_database_intact() {
    let dir = std::env::temp_dir().join(format!("nzbfast-vacabort-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("index.db");
    let ix = Index::open(&path).unwrap();

    // Ballast enough that the rewrite has a VM phase worth
    // interrupting in at all. Since the interrupt is delivered from
    // a progress handler rather than on a timer, "enough" is an
    // OPCODE count, not a duration: the handler fires every
    // `num_ops` VDBE steps OF THE STATEMENT RUNNING AT THE TIME, so
    // the only requirement is that some statement inside the VACUUM
    // runs past `num_ops`. VACUUM copies each table with one
    // `INSERT INTO vacuum_db.x SELECT * FROM main.x`, which measures
    // ~5 opcodes per row, so at the 1000 below the floor is ~200
    // SURVIVING rows - 400 built, half deleted. Measured: 400 built
    // fires exactly once, 300 never fires at all.
    //
    // The 2 000 below is therefore five handler calls against a
    // floor of 1. It is NOT sized for duration, whatever the 20 000
    // it replaced suggests, so do not read it as "the rewrite must
    // last long enough to be hit" and do not tune it as a timing
    // margin. Five is ample: the floor moves only if VACUUM's copy
    // loop changes its opcodes per row, and it cannot spend fewer
    // than the ~4 it takes to step a cursor and insert a record.
    //
    // Undershooting is not a flake. Too little ballast means the
    // handler never fires at all, and `fired` below then fails
    // loudly and identically on every platform - it cannot walk the
    // interrupt somewhere subtler, because the fire point is a count
    // of opcodes within one statement rather than a moment in time.
    let payload = vec![7u8; 4096];
    ix.db
        .execute_batch("CREATE TABLE IF NOT EXISTS vac_ballast(id INTEGER PRIMARY KEY, b BLOB)")
        .unwrap();
    {
        let tx = ix.db.unchecked_transaction().unwrap();
        for _ in 0..2_000 {
            tx.execute("INSERT INTO vac_ballast(b) VALUES(?1)", [&payload])
                .unwrap();
        }
        tx.commit().unwrap();
    }
    ix.db
        .execute("DELETE FROM vac_ballast WHERE id % 2 = 0", [])
        .unwrap();
    let free_before: i64 = ix
        .db
        .query_row("PRAGMA freelist_count", [], |r| r.get(0))
        .unwrap();
    assert!(free_before > 0, "the delete left the rewrite nothing to do");

    // The interrupt has to land inside the rewrite's VM phase, and
    // nothing about ELAPSED TIME says when that is. Only the first
    // part of a VACUUM - copying the live pages into the temp
    // database - runs in the VDBE, which is the only place the
    // interrupt flag is read; the `sqlite3BtreeCopyFile` tail that
    // writes the result back over the original checks nothing and
    // cannot be stopped. Measured on Windows against an 80 MB index
    // (see `interrupt_handle`): the window is the first few hundred
    // milliseconds of a rewrite that runs ~2 s idle and ~6 s with
    // the cores busy, because the window is memory-speed work and
    // only the tail is disk-bound. Load stretches the rewrite and
    // leaves the window where it was.
    //
    // Both earlier shapes bet on time and lost. Sleeping 5 ms and
    // interrupting once failed the Windows nightly leg on 2026-08-02
    // (it fired before VACUUM had begun). Interrupting in a 1 ms
    // loop until compact() returns failed the per-push windows-unit
    // leg on d1716767, twice including the nextest retry: a freshly
    // spawned thread on a loaded runner took longer to reach its
    // first call than the window stayed open. On a 14-core Windows
    // laptop with every core busy that first call measured 27-32 ms;
    // the margin is real but it is only ever a margin.
    //
    // So take time out of it. The progress callback runs from
    // inside the rewrite's own VM loop, so when it fires the VACUUM
    // is provably mid-flight and provably still in the phase that
    // reads the flag. It hands the job to another thread - the
    // daemon aborts a compact from another thread, and that is the
    // property worth pinning - and blocks until that thread's
    // `interrupt()` has returned, so the rewrite cannot outrun it.
    // The callback returns false: aborting is the interrupt's job
    // here, not the progress handler's, or the test would pass
    // without `interrupt_handle` working at all.
    //
    // 1000 opcodes is also what keeps the first call landing in the
    // table copy rather than in VACUUM's own preamble. Traced by
    // reporting the busy statement from inside the handler: at 1000
    // the first call is always the `INSERT INTO vacuum_db.
    // 'vac_ballast' SELECT*FROM main.'vac_ballast'`; at 100 and 10
    // it is the schema mirror; at 5 it is the `ATTACH '' AS
    // vacuum_...` that opens the temp database, which fails as
    // "unable to open database" instead of "interrupted" - still an
    // Err, so still a green test, but no longer the interrupt this
    // is here to pin.
    let handle = ix.interrupt_handle();
    let (ask, asked) = std::sync::mpsc::channel::<()>();
    let (landed, confirm) = std::sync::mpsc::channel::<()>();
    let aborter = std::thread::spawn(move || {
        if asked.recv().is_ok() {
            handle.interrupt();
            let _ = landed.send(());
        }
    });
    let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let once = std::sync::Arc::clone(&fired);
    ix.db
        .progress_handler(
            1000,
            Some(move || {
                if !once.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    // A dead aborter closes the channel rather than
                    // hanging the rewrite here.
                    if ask.send(()).is_ok() {
                        let _ = confirm.recv();
                    }
                }
                false
            }),
        )
        .unwrap();
    let r = ix.compact();
    ix.db.progress_handler(1000, None::<fn() -> bool>).unwrap();
    aborter.join().unwrap();
    assert!(
        fired.load(std::sync::atomic::Ordering::SeqCst),
        "the rewrite never reached its VM loop, so nothing was interrupted"
    );
    assert!(
        r.is_err(),
        "the rewrite must abort rather than run to completion"
    );
    // And it aborted with work still to do. `fired` alone only says
    // the VM loop was reached; the free pages are what say the
    // interrupt beat `sqlite3BtreeCopyFile`, because a rewrite that
    // reached the copy-back has no freelist left. This is the
    // property the ballast is sized for, so it is the one that has
    // to fail if the ballast ever gets too small to hold the first
    // handler call inside the copy.
    let free_after: i64 = ix
        .db
        .query_row("PRAGMA freelist_count", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        free_after, free_before,
        "the abort landed after the rewrite, so it saved nothing"
    );

    // Nothing was lost: the odd-id half is still all there, and the
    // index is usable straight afterwards.
    let n: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM vac_ballast", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1_000, "an aborted VACUUM must not cost a single row");
    assert!(
        ix.db_bytes().unwrap() > 0,
        "the connection still works after the abort"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The exit path's checkpoint: fold the log into the database and
/// leave nothing behind.
///
/// This is what a proper CLOSE does for free, and the daemon never
/// closes - it exits through `process::exit` or `exec`. So the whole
/// write-ahead log survived every stop, and the next start recovered
/// it instead of opening a database that was already whole.
#[test]
fn checkpoint_truncate_leaves_no_write_ahead_log() {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-ckpt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("index.db");
    let ix = Index::open(&db).unwrap();
    ix.kv_set("probe", "before").unwrap();
    let wal = dir.join("index.db-wal");
    assert!(
        wal.metadata().map(|m| m.len()).unwrap_or(0) > 0,
        "fixture wrote nothing to the log - the assertion below would prove nothing"
    );

    assert!(
        ix.checkpoint_truncate(std::time::Duration::from_secs(1))
            .unwrap(),
        "nothing else holds this database, so the checkpoint had no reason to report busy"
    );

    assert_eq!(
        wal.metadata().map(|m| m.len()).unwrap_or(0),
        0,
        "the log is still on disk after a truncating checkpoint"
    );
    // And the point of folding it in: the data is in the database
    // file itself, so the next open has nothing to recover.
    drop(ix);
    let reopened = Index::open(&db).unwrap();
    assert_eq!(reopened.kv_get("probe").as_deref(), Some("before"));
    teardown(&dir, reopened);
}

/// A reader that has not caught up blocks a TRUNCATE checkpoint, and
/// the caller is an exit with a budget. It must come back with
/// `false` inside the wait it asked for rather than sitting on the
/// connection's own 10 s busy timeout.
#[test]
fn checkpoint_truncate_gives_up_on_a_reader_inside_its_wait() {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-ckptb-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("index.db");
    let ix = Index::open(&db).unwrap();
    ix.kv_set("probe", "one").unwrap();

    // A read transaction left open on a second connection: the
    // shape of a query handler holding a pooled read connection
    // when the signal arrives.
    let reader = Index::open_read_only(&db).unwrap();
    reader.db.execute_batch("BEGIN").unwrap();
    assert_eq!(reader.kv_get("probe").as_deref(), Some("one"));
    // Written after the reader pinned its snapshot, so the log now
    // holds frames that reader cannot see - which is precisely what
    // a checkpoint may not overwrite.
    ix.kv_set("probe", "two").unwrap();

    let started = std::time::Instant::now();
    let truncated = ix
        .checkpoint_truncate(std::time::Duration::from_millis(300))
        .unwrap();
    let took = started.elapsed();

    assert!(!truncated, "a pinned reader must be reported, not ignored");
    assert!(
        took < std::time::Duration::from_secs(5),
        "waited {took:?} - the wait argument was ignored and this fell back \
         to the connection's own 10 s busy timeout"
    );
    // The timeout it borrowed is put back, not left at 300 ms.
    let restored: i64 = ix
        .db
        .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
        .unwrap();
    assert_eq!(restored, 10_000, "the busy timeout was not put back");

    reader.db.execute_batch("COMMIT").unwrap();
    drop(reader);
    teardown(&dir, ix);
}

/// TODO 198 tail: what `PRAGMA analysis_limit=1000` costs, on the
/// smallest fixture that can show it.
///
/// The undocumented half first, because the deep leg's whole design
/// rests on it: a limited ANALYZE writes NO `sqlite_stat4` rows. That
/// is what makes `shallow_stat_index` an exact reading of the database
/// rather than a guess at one, and what makes the leg self-heal after a
/// `PRAGMA optimize` resets a table. Then the documented half: with
/// 3,000 rows behind one `kind` value, the sampled per-value estimate
/// comes back pinned near the 1000-row sample and the measured one
/// comes back near 3,000.
///
/// The loop at the bottom is the convergence property. An index that a
/// full pass leaves without samples would make the daemon's leg pick
/// the same index every pass forever; the guard against that is the
/// `CAST(stat AS INTEGER) > 0` term, and this is what proves the guard
/// is enough on a real schema rather than only on the fixture.
#[test]
fn the_deep_pass_measures_what_the_sampled_one_estimates() {
    let dir = std::env::temp_dir().join(format!("nzbfast-deepstats-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ix = Index::open(&dir.join("index.db")).unwrap();
    // A skewed leading column, which is the shape `releases(kind, ...)`
    // has: 3,000 rows behind one value, three times the sample limit.
    ix.db
        .execute_batch(
            "CREATE TABLE skew(id INTEGER PRIMARY KEY, kind TEXT NOT NULL);
             CREATE INDEX idx_skew_kind ON skew(kind);
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<3000)
             INSERT INTO skew(kind) SELECT 'movie' FROM n;",
        )
        .unwrap();
    ix.optimize().expect("the sampled pass");
    let samples = |ix: &Index, idx: &str| -> i64 {
        ix.db
            .query_row(
                "SELECT COUNT(*) FROM sqlite_stat4 WHERE idx = ?1",
                [idx],
                |r| r.get(0),
            )
            .unwrap()
    };
    let stat = |ix: &Index, idx: &str| -> String {
        ix.db
            .query_row("SELECT stat FROM sqlite_stat1 WHERE idx = ?1", [idx], |r| {
                r.get(0)
            })
            .unwrap()
    };
    assert_eq!(
        samples(&ix, "idx_skew_kind"),
        0,
        "a limited ANALYZE must leave sqlite_stat4 empty - if this ever \
         starts writing samples the deep leg's probe stops meaning \
         'was analyzed under a limit' and it will re-measure forever"
    );
    assert_eq!(
        stat(&ix, "idx_skew_kind"),
        "3000 1001",
        "the sampled per-value estimate should be pinned near the 1000-row \
         sample, not near the 3,000 rows actually behind that value"
    );
    assert_eq!(
        ix.shallow_stat_index().as_deref(),
        Some("idx_skew_kind"),
        "biggest still-sampled index first, and on this schema every other \
         index is empty"
    );
    ix.analyze_index_deep("idx_skew_kind").expect("measure it");
    assert_eq!(
        stat(&ix, "idx_skew_kind"),
        "3000 3000",
        "and measured it says what is there"
    );
    assert!(
        samples(&ix, "idx_skew_kind") > 0,
        "a measured index carries stat4 samples, which is what stops the \
         daemon's leg picking it again"
    );
    // Convergence: hand the whole schema to the leg and it must run out.
    for _ in 0..80 {
        let Some(next) = ix.shallow_stat_index() else {
            break;
        };
        ix.analyze_index_deep(&next).expect("measure");
    }
    assert_eq!(
        ix.shallow_stat_index(),
        None,
        "the deep leg never finishes on this database - some index it \
         measures comes back with no samples and it will pick that one on \
         every maintenance pass, forever"
    );
    teardown(&dir, ix);
}

/// The plan the sampled statistics steer wrong, at the smallest size
/// that steers it (TODO 198 tail).
///
/// This is §198's one unwinnable shape, reduced: a kind-leading index
/// over everything, a partial covering index over the 2% that are
/// `complete`, and an \*arr's `kind = ? AND complete AND posted >= ?`
/// count. Sampled, both indexes claim 1001 rows per `kind` and the
/// planner takes the big one - measured on the 33.4M-release index at
/// 219 ms against the partial index's 15 ms. Measured, they claim
/// 282,000 and 5,640 and it takes the partial one.
///
/// 300,000 rows because the flip needs the two estimates to be far
/// enough apart to matter: it does not happen at 100,000 and does at
/// 250,000 on SQLite 3.53.2, so this sits above the knee with margin
/// rather than on it. It builds in well under a second.
#[test]
fn the_sampled_limit_picks_the_wrong_index_for_an_arr_count() {
    let dir = std::env::temp_dir().join(format!("nzbfast-deepplan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ix = Index::open(&dir.join("index.db")).unwrap();
    ix.db
        .execute_batch(
            "CREATE TABLE rel(id INTEGER PRIMARY KEY, kind TEXT NOT NULL,
                              posted INTEGER NOT NULL, complete INTEGER NOT NULL,
                              stem TEXT NOT NULL);
             CREATE INDEX i_kind ON rel(kind, posted);
             CREATE INDEX i_complete_kind ON rel(kind, posted, stem) WHERE complete;
             WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<299999)
             INSERT INTO rel(kind, posted, complete, stem)
               SELECT CASE WHEN i % 100 < 6 THEN 'tv' ELSE 'movie' END,
                      1700000000 + i, i % 50 = 0, 'stem' || (i / 3)
                 FROM n;",
        )
        .unwrap();
    let sql = "SELECT COUNT(*) FROM rel
                WHERE kind = 'movie' AND complete AND posted >= 1700100000";
    let plan = |ix: &Index| -> String {
        let mut stmt = ix.db.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let rows: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        rows.join(" | ")
    };
    ix.optimize().expect("the sampled pass");
    let sampled = plan(&ix);
    assert!(
        sampled.contains("i_kind") && !sampled.contains("i_complete_kind"),
        "the sampled statistics no longer mis-steer this count. If SQLite \
         got better at it, this test has done its job and can go - but \
         check that it is not the fixture that stopped being skewed \
         first: {sampled}"
    );
    while let Some(next) = ix.shallow_stat_index() {
        ix.analyze_index_deep(&next).expect("measure");
    }
    let measured = plan(&ix);
    assert!(
        measured.contains("i_complete_kind"),
        "measured statistics must take the partial covering index - this \
         is the whole of what the deep leg buys: {measured}"
    );
    teardown(&dir, ix);
}

/// The stem rewrite at the end of `split_merge_group` used to leave
/// `stem_fold` alone, so the merged row kept the FIRST FRAGMENT's fold
/// - a value naming a stem the row no longer wears. Every non-FTS
/// search path (`query::stem_fold_arm` and the browse exclusion twin)
/// reads that column, so a Cyrillic set went unfindable by the base
/// name the merge had just given it.
#[test]
fn split_merge_rewrites_the_unicode_stem_fold_with_the_stem() {
    let d = std::env::temp_dir().join(format!("nzbfast-splitfold-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    let base = "ВОЙНА.И.МИР.7z";
    for part in ["001", "002"] {
        let stem = format!("{base}.{part}");
        ix.db
            .execute(
                "INSERT INTO releases(stem, poster, grp, total_bytes, files, complete,
                                      has_par2, first_posted, first_seen, kind, junk,
                                      stem_fold)
                 VALUES(?1, 'p@x', 'alt.binaries.x264', 1000, 1, 1, 0, 4600, 5000,
                        'other', 75, ?2)",
                rusqlite::params![stem, crate::index::fold::stored(&stem)],
            )
            .unwrap();
        let rid = ix.db.last_insert_rowid();
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes)
                 VALUES(?1, ?2, 1, 1000)",
                rusqlite::params![rid, stem],
            )
            .unwrap();
    }
    let (groups, folded, _) = ix.split_merge(6000, crate::index::testutil::WALK).unwrap();
    assert_eq!((groups, folded), (1, 1));
    let (stem, got): (String, String) = ix
        .db
        .query_row("SELECT stem, stem_fold FROM releases", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(stem, base);
    let want = crate::index::fold::stored(base);
    assert!(!want.is_empty(), "a Cyrillic stem earns a stored fold");
    assert_eq!(got, want, "the fold follows the stem the merge wrote");
    teardown(&d, ix);
}

/// The rule the album fold hit live (`album_fold_merge`): a pass that
/// rewrites `kind`, `title_key` or `junk` on an existing row is doing
/// ingest's job and owes ingest's classification recoveries. This
/// merge rewrites all three, off a base stem no member wore.
///
/// The set here is the shape this pass actually meets: a dark split
/// container in a BOOK group. The fragment stems end `.001`, which is
/// no plain extension, so ingest recovered them to the lane the group
/// vouches for; the base keeps the `.7z` those fragments were split
/// from, which IS a plain extension, so the same recovery declines it
/// and the merged row lands on the fall-through lane. That divergence
/// is measured and deliberately left alone: the merged row is a
/// junk-70 obfuscated container either way, hidden on every wall.
///
/// What this test pins is the rule - the merged row is classified and
/// scored exactly as ingest classifies and scores the stem it now wears.
#[test]
fn a_merged_split_set_is_classified_the_way_ingest_classifies_it() {
    let d = std::env::temp_dir().join(format!("nzbfast-splitkind-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    let grp = "alt.binaries.audiobooks";
    let base = "Deliver.Us.From.Evil.gUSbVwIDqhrR.7z";
    for part in ["001", "002"] {
        let stem = format!("{base}.{part}");
        let mut p = crate::categories::classify(&stem, &ix.custom);
        crate::release::recover_media_kind(&mut p, &stem, &stem);
        crate::release::recover_kind_from_group(&mut p, grp, &stem);
        let junk = junk_score(&stem, &p, 700_000_000, false);
        assert!(junk >= 70, "the fragment must be in this pass's band");
        ix.db
            .execute(
                "INSERT INTO releases(stem, poster, grp, total_bytes, files, complete,
                                      has_par2, first_posted, first_seen, kind, junk,
                                      title_key, stem_fold)
                 VALUES(?1, 'p@x', ?2, 700000000, 1, 1, 0, 4600, 5000, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    stem,
                    grp,
                    kind_str(&p.kind),
                    junk,
                    p.key,
                    crate::index::fold::stored(&stem)
                ],
            )
            .unwrap();
        let rid = ix.db.last_insert_rowid();
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes)
                 VALUES(?1, ?2, 1, 700000000)",
                rusqlite::params![rid, stem],
            )
            .unwrap();
    }
    let was: String = ix
        .db
        .query_row("SELECT kind FROM releases LIMIT 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(was, "book", "ingest recovered the fragments off the group");

    let (groups, folded, _) = ix.split_merge(6000, crate::index::testutil::WALK).unwrap();
    assert_eq!((groups, folded), (1, 1));

    let (stem, kind, junk, key, bytes): (String, String, i64, String, i64) = ix
        .db
        .query_row(
            "SELECT stem, kind, junk, title_key, total_bytes FROM releases",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(stem, base, "merged onto the base");
    let mut want = crate::categories::classify(&stem, &ix.custom);
    crate::release::recover_media_kind(&mut want, &stem, &stem);
    crate::release::recover_kind_from_group(&mut want, grp, &stem);
    if !crate::index::ingest::stem_obfuscated(&stem, &want) {
        crate::release::recover_episode_from_group(&mut want, grp, &stem);
    }
    assert_eq!(kind, kind_str(&want.kind), "the merged lane is ingest's");
    assert_eq!(key, want.key, "and so is the title key it cards on");
    assert_eq!(
        junk,
        junk_score(&stem, &want, bytes as u64, false),
        "the merge scored junk against a kind ingest would not have used"
    );
    assert!(junk >= 70, "an obfuscated container stays dark either way");
    teardown(&d, ix);
}
