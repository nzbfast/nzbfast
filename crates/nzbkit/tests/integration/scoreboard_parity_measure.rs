//! The parity scoreboard's own before/after ruler (TODO §144 item 2 /
//! REFRESH sweep finding M8).
//!
//! Changing what counts as identity moves the coverage% / named% the
//! scoreboard reports, so no such change may land without the same
//! sample set measured on both sides of it. This is that measurement,
//! kept in the repo so the next person can re-run it rather than trust
//! a number in a note.
//!
//! `#[ignore]`d and env-gated: it needs a real, populated index
//! (millions of releases and a Spotnet spot table), which no fixture
//! can stand in for - the collision density of a live index IS the
//! thing being measured.
//!
//! ```sh
//! SB_MEASURE_DB=$HOME/Claude/nzbfast-data/index.db \
//!   cargo test -p nzbkit --test scoreboard_parity_measure -- --ignored --nocapture
//! ```
//!
//! `SB_MEASURE_N` caps the parity sample (default 3000, drawn as an
//! even stride over id order so the same rows come back on every run -
//! "the same sample set" is the entire point).
//!
//! Two reference sample sets, both already sitting in the index and
//! both external feeds carrying name + size + posted time + category,
//! which is the shape a reference newznab answers with:
//!
//! - `predb` - scene release names. The closest proxy there is to what
//!   a real reference indexer lists, and therefore the set that
//!   exercises the exact-stem key.
//! - `spots` - Spotnet, human-written titles. Far fewer stem hits, but
//!   it spans months rather than the pre feed's retention and it always
//!   carries a size, so it is the set that exercises the size band.
//!
//! Neither feeds the key under measurement: promotion from either
//! source writes `pre_title` and never `stem`, and `stem` is the
//! scanner's own reading of the Usenet subject.

use nzbkit::index::Index;
use rusqlite::{Connection, OpenFlags};

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty())
}

/// A second, raw handle for the census and sampling queries, so the
/// measurement needs no new public API on `Index`.
fn raw(db: &str) -> Connection {
    let c = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .expect("open raw read-only");
    c.busy_timeout(std::time::Duration::from_secs(30)).unwrap();
    c.execute_batch("PRAGMA query_only=ON; PRAGMA temp_store=MEMORY;")
        .unwrap();
    c
}

/// Phase 1 - the stem census, and the evidence the identity ruling was
/// chosen from. For every distinct stem in the index: what
/// [`stem_evidence`] calls it, how many releases carry it, and how far
/// apart in time those releases sit. The last column is what decides
/// whether the 48 h bound on a token costs anything - a stem whose
/// rows are all one posting loses nothing to it, and a stem reused
/// across the calendar is exactly the false proof M8 describes.
fn census(c: &Connection) {
    let mut stmt = c
        .prepare(
            "SELECT stem, count(*) c, max(first_posted)-min(first_posted) span
               FROM releases GROUP BY stem ORDER BY c DESC",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .unwrap();

    use nzbkit::index::StemEvidence as E;
    /// stems, releases carrying them, shared stems, stems whose rows
    /// span more than one 48 h posting window, releases under those.
    #[derive(Default)]
    struct Class {
        stems: u64,
        rows: u64,
        shared: u64,
        spanning: u64,
        spanning_rows: u64,
        worst: Vec<(i64, i64, String)>,
    }
    let mut acc: std::collections::BTreeMap<&str, Class> = Default::default();
    for row in rows {
        let (stem, n, span) = row.unwrap();
        let class = match nzbkit::index::stem_evidence(&stem) {
            E::Name => "Name  (global, proves naming)",
            E::Token => "Token (48h-bounded, proves presence)",
            E::None => "None  (refused outright)",
        };
        let e = acc.entry(class).or_default();
        e.stems += 1;
        e.rows += n as u64;
        if n > 1 {
            e.shared += 1;
        }
        if span > 2 * 24 * 3_600 {
            e.spanning += 1;
            e.spanning_rows += n as u64;
            if e.worst.len() < 4 {
                e.worst.push((n, span, stem));
            }
        }
    }
    println!("\n== phase 1: stem census (every distinct stem in the index) ==");
    for (class, k) in &acc {
        println!(
            "  {class:<38} {:>8} stems {:>10} releases  ({} shared)",
            k.stems, k.rows, k.shared
        );
        println!(
            "      reused across the calendar (>48h): {} stems, {} releases",
            k.spanning, k.spanning_rows
        );
        for (n, span, s) in &k.worst {
            println!("        {n:>6}x  span {:>4}d  {s}", span / 86_400);
        }
    }
}

/// One reference sample, in the shape `scoreboard_match` scores.
struct Ref {
    kind: &'static str,
    name: String,
    size: u64,
    posted: i64,
}

/// A scene category string reduced to the scoreboard's own buckets.
fn predb_kind(cat: &str) -> &'static str {
    let c = cat.to_ascii_uppercase();
    if c.starts_with("TV") || c.contains("SPORT") {
        "tv"
    } else if c.contains("MP3") || c.contains("FLAC") || c.contains("MUSIC") {
        "audio"
    } else if c.contains("BOOK") {
        "books"
    } else if c.contains("GAME") || c.contains("APP") || c.contains("0DAY") {
        "other"
    } else {
        "movies"
    }
}

fn sample_set(c: &Connection, src: &str, want: usize) -> Vec<Ref> {
    let (count_sql, rows_sql) = match src {
        "spots" => (
            "SELECT count(*) FROM spots WHERE size>0 AND date>0 AND title<>''",
            "SELECT title, size, date, category FROM spots
              WHERE size>0 AND date>0 AND title<>'' ORDER BY id",
        ),
        _ => (
            "SELECT count(*) FROM predb WHERE size>0 AND pt>0 AND title<>''",
            "SELECT title, size, pt, category FROM predb
              WHERE size>0 AND pt>0 AND title<>'' ORDER BY id",
        ),
    };
    let total: i64 = c.query_row(count_sql, [], |r| r.get(0)).unwrap();
    // An even stride over id order: deterministic, and it keeps the
    // sample spread over the whole feed rather than the newest page.
    let stride = (total as usize / want.max(1)).max(1);
    let mut stmt = c.prepare(rows_sql).unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?.max(0) as u64,
                r.get::<_, i64>(2)?,
                r.get::<_, rusqlite::types::Value>(3)?,
            ))
        })
        .unwrap();
    let mut out = Vec::new();
    for (n, row) in rows.enumerate() {
        if n % stride != 0 || out.len() >= want {
            continue;
        }
        let (name, size, posted, cat) = row.unwrap();
        let kind = match cat {
            rusqlite::types::Value::Integer(i) => nzbkit::index::spot_kind(i as u8),
            rusqlite::types::Value::Text(t) => predb_kind(&t),
            _ => "other",
        };
        out.push(Ref {
            kind,
            name,
            size,
            posted,
        });
    }
    out
}

#[derive(Default)]
struct Tally {
    total: u64,
    named: u64,
    unnamed: u64,
    by_stem: u64,
    by_band: u64,
    lags: Vec<i64>,
}

impl Tally {
    fn add(&mut self, m: &nzbkit::index::ScoreboardMatch) {
        self.total += 1;
        match m.verdict {
            "have_named" => self.named += 1,
            "have_unnamed" => self.unnamed += 1,
            _ => {}
        }
        match m.key_used {
            "stem" => self.by_stem += 1,
            "band" => self.by_band += 1,
            _ => {}
        }
        if m.verdict != "missing" {
            self.lags.push(m.lag_secs);
        }
    }
    fn line(&self, label: &str) -> String {
        let pct = |n: u64| {
            if self.total == 0 {
                0.0
            } else {
                100.0 * n as f64 / self.total as f64
            }
        };
        let mut l = self.lags.clone();
        l.sort_unstable();
        let med = l.get(l.len() / 2).copied().unwrap_or(0);
        format!(
            "  {label:<6} n={:<5} named {:>6.2}%  coverage {:>6.2}%  \
             (stem {:>5} / band {:>5})  lag_med {:>8}s",
            self.total,
            pct(self.named),
            pct(self.named + self.unnamed),
            self.by_stem,
            self.by_band,
            med
        )
    }
}

/// Phase 3 - the calibration pass, which is where the M8 finding
/// actually bites: it reads EVERY distinct subject stem out of a
/// fetched reference NZB and takes any hit as proof that the reference
/// posting is present.
///
/// Simulated without spending a grab: a release's own `files` rows ARE
/// the filenames its NZB carries, so for each sampled release we run
/// its own file stems through both lookups and ask which release the
/// answer lands on. An answer whose posting time is more than a window
/// away from the release the stems came from is a posting we do not
/// hold being recorded as one we do - a false proof of presence.
fn calibration_probe(c: &Connection, ix: &Index, want: usize) {
    let total: i64 = c
        .query_row("SELECT count(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    let stride = (total as usize / want.max(1)).max(1);
    let mut pick = c
        .prepare("SELECT id, first_posted FROM releases ORDER BY id")
        .unwrap();
    let mut names = c
        .prepare("SELECT filename FROM files WHERE release_id=?1")
        .unwrap();
    // Exactly the lookup this change replaced, kept here so the two
    // columns below are the same query on the same rows.
    let mut old = c
        .prepare(
            "SELECT id, first_posted FROM releases WHERE stem=?1 ORDER BY first_posted LIMIT 1",
        )
        .unwrap();

    let mut n = 0u64;
    // (answered, of which a different posting) for each lookup.
    let (mut o_hit, mut o_bad, mut w_hit, mut w_bad) = (0u64, 0u64, 0u64, 0u64);
    let mut o_vacuous = 0u64;
    let (mut o_false, mut w_repost) = (0u64, 0u64);
    let mut vacuous_eg: Vec<String> = Vec::new();
    let mut lost_eg: Vec<String> = Vec::new();
    // The same stem lookup with this posting's own window cut out.
    let mut away = c
        .prepare(
            "SELECT id FROM releases
              WHERE stem=?1 AND first_posted NOT BETWEEN ?2 AND ?3
              ORDER BY first_posted LIMIT 1",
        )
        .unwrap();
    let rows = pick
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
        .unwrap();
    for (i, row) in rows.enumerate() {
        if i % stride != 0 || n >= want as u64 {
            continue;
        }
        let (id, posted) = row.unwrap();
        let mut stems: Vec<String> = names
            .query_map([id], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(|f| f.ok())
            .map(|f| nzbkit::extract::release_stem(&f))
            .filter(|s| !s.is_empty())
            .collect();
        stems.sort_unstable();
        stems.dedup();
        if stems.is_empty() {
            continue;
        }
        n += 1;
        // A hit is honest when it lands on the release the stems came
        // from, or on a sibling row of the same posting (one posting
        // fans out over random per-article posters).
        let honest = |at: i64| (at - posted).abs() <= 48 * 3_600;
        let old_hit = stems.iter().find_map(|s| {
            old.query_row([s], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
                .ok()
                .map(|(rid, at)| (rid, at, s))
        });
        if let Some((_, at, deciding)) = old_hit {
            o_hit += 1;
            if !honest(at) {
                o_bad += 1;
            }
            // The proof was VACUOUS when the stem that carried it holds
            // no identity: the answer is right here only because we do
            // hold this release, and the same stem would have answered
            // "present" for any reference NZB that happened to contain
            // it.
            if nzbkit::index::stem_evidence(deciding) == nzbkit::index::StemEvidence::None {
                o_vacuous += 1;
                if vacuous_eg.len() < 5 {
                    vacuous_eg.push(deciding.clone());
                }
            }
        }
        let new_hit = stems
            .iter()
            .find_map(|s| ix.scoreboard_stem_lookup(s, posted).ok().flatten());
        if let Some((rid, _)) = new_hit {
            w_hit += 1;
            let at: i64 = c
                .query_row(
                    "SELECT first_posted FROM releases WHERE id=?1",
                    [rid],
                    |r| r.get(0),
                )
                .unwrap();
            if !honest(at) {
                w_bad += 1;
            }
        } else if old_hit.is_some() && lost_eg.len() < 5 {
            lost_eg.push(stems.join(" | "));
        }

        // The counterfactual, and the half the loop above cannot see:
        // pretend we do NOT hold this posting. Would its NZB's stems
        // still prove it present, out of rows belonging to something
        // else? That is the M8 false proof, made observable by
        // excluding this posting's own window from the answer.
        let mut elsewhere = |s: &str, named_only: bool| -> Option<i64> {
            if named_only && nzbkit::index::stem_evidence(s) != nzbkit::index::StemEvidence::Name {
                return None;
            }
            away.query_row(
                rusqlite::params![s, posted - 48 * 3_600, posted + 48 * 3_600],
                |r| r.get::<_, i64>(0),
            )
            .ok()
        };
        if stems.iter().any(|s| elsewhere(s, false).is_some()) {
            o_false += 1;
        }
        // After the change a Token can only answer inside this
        // posting's own window, which the counterfactual removes, and
        // a None answers nowhere - so anything left is a release NAME
        // matching elsewhere, i.e. a repost, which the ruling counts
        // as a hit rather than a false proof.
        if stems.iter().any(|s| elsewhere(s, true).is_some()) {
            w_repost += 1;
        }
    }
    let pct = |a: u64, b: u64| {
        if b == 0 {
            0.0
        } else {
            100.0 * a as f64 / b as f64
        }
    };
    println!("\n== phase 3: calibration presence proof over {n} releases ==");
    println!(
        "  before : {o_hit:>6} proved present, {o_bad:>6} of them a DIFFERENT posting ({:.2}%)",
        pct(o_bad, o_hit)
    );
    println!(
        "  after  : {w_hit:>6} proved present, {w_bad:>6} of them a DIFFERENT posting ({:.2}%)",
        pct(w_bad, w_hit)
    );
    println!(
        "  presence we can still prove: {:.2}% of before",
        pct(w_hit, o_hit)
    );
    println!(
        "  before, proved by a stem carrying NO identity: {o_vacuous} ({:.2}%)",
        pct(o_vacuous, o_hit)
    );
    for s in &vacuous_eg {
        println!("      vacuous proof: {s}");
    }
    for s in &lost_eg {
        println!("      no longer provable: {s}");
    }
    println!("  counterfactual - pretend we do NOT hold the posting, does its NZB still prove it?");
    println!(
        "    before : {o_false:>6} of {n} still proved present ({:.2}%) - the M8 false proof",
        pct(o_false, n)
    );
    println!(
        "    after  : {w_repost:>6} of {n} ({:.2}%), every one of them a release NAME held \
         elsewhere - a repost, which the ruling counts as a hit",
        pct(w_repost, n)
    );
}

#[test]
#[ignore = "needs a live populated index; see the module doc"]
fn scoreboard_parity_on_a_live_index() {
    let db = env("SB_MEASURE_DB").expect("set SB_MEASURE_DB to a populated index.db");
    let want: usize = env("SB_MEASURE_N")
        .and_then(|v| v.parse().ok())
        .unwrap_or(3_000);
    let c = raw(&db);
    let releases: i64 = c
        .query_row("SELECT count(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    println!("\nindex {db}: {releases} releases");
    census(&c);

    let ix = Index::open_read_only(std::path::Path::new(&db)).expect("open index read-only");
    for src in ["predb", "spots"] {
        let refs = sample_set(&c, src, want);
        println!(
            "\n== phase 2 [{src}]: parity over {} samples ==",
            refs.len()
        );
        let t0 = std::time::Instant::now();
        let mut all = Tally::default();
        let mut per: std::collections::BTreeMap<&'static str, Tally> = Default::default();
        for r in &refs {
            let m = ix.scoreboard_match(&r.name, r.size, r.posted).unwrap();
            all.add(&m);
            per.entry(r.kind).or_default().add(&m);
        }
        for (k, t) in &per {
            println!("{}", t.line(k));
        }
        println!("{}", all.line("ALL"));
        println!("  ({:.1}s)", t0.elapsed().as_secs_f64());
    }
    calibration_probe(&c, &ix, want);
}
