//! OVER ingest and classification (TODO 106 phase 2.2, cut 5): the
//! subject/counter parsers, the junk scorer, custom-category
//! (re)classification, per-server watermarks and `ingest` itself. Bodies
//! are verbatim moves from the old index.rs; see
//! research/SEAM-TABLE-index-rs-2026-08-05.md.

use super::*;
use aggregates::RelAgg;
use claims::norm_msgid;
use spots::{GEN_HEX, POSTER_GEN_MARK};

// The two largest test subjects in this file live in their own children
// under the size gate (TODO 106). `cfg(test)` is redundant on a module
// that only test code reaches, but it is what size-gate.py's
// CFG_TEST_MOD resolver keys on to score the child as test code rather
// than gate it at the production fn ceiling; both resolve to
// `ingest/<name>.rs` because this module is reached by a plain
// `mod ingest;` in index/mod.rs, not by a `#[path]`.
#[cfg(test)]
mod custom_category_tests;
#[cfg(test)]
mod gen_split_tests;

// The strip lives beside the detector it feeds - `crate::junk` takes its
// own `use crate::release::bare_stem;` - so the picks and the claims
// apply-gate cannot drift apart; see `release::stem_is_a_name`. The
// `pub(super) use` that stood here went with the scorer at the
// nzbkit-base cut: `index::scoreboard` was its last in-crate reader and
// it names `crate::release::bare_stem` directly.

// The junk scorer itself is `crate::junk` since the nzbkit-base cut: it is
// a pure function over a stem and its `release::Parsed`, and `release`'s own
// test table pins it. Re-exported here so `nzbkit::index::junk_score` and
// every `super::ingest::` path inside the indexer are unchanged.
pub use crate::junk::{junk_score, stem_obfuscated};

/// `… "name" yEnc (n/m)` → (subject minus counter, n, m).
///
/// The counter is the RIGHTMOST group that actually parses as one:
/// `(n/m)`, `[n/m]`, or `(n of m)`. Taking the last `(` unconditionally
/// broke on trailing tags - `… (5/50) (German)` or `… (5/50) (4.2 GB)`
/// returned None, every part collapsed to (1,1), and a 50-part file
/// indexed as one segment yet counted "complete".
pub fn split_subject(subject: &str) -> Option<(String, u32, u32)> {
    split_subject_at(subject).map(|(base, n, m, _)| (base, n, m))
}

/// [`split_subject`], plus the BYTE OFFSET of the bracket it consumed.
///
/// The offset is what tells a leading session tag from a trailing part
/// counter, and only the offset can: the two are indistinguishable by
/// value, because `[1/3] "x.mkv" yEnc (1/3)` carries the same pair
/// twice and a value test reads the trailing counter as the tag.
pub fn split_subject_at(subject: &str) -> Option<(String, u32, u32, usize)> {
    let opens: Vec<(usize, char, char)> = subject
        .char_indices()
        .filter_map(|(i, c)| match c {
            '(' => Some((i, '(', ')')),
            '[' => Some((i, '[', ']')),
            _ => None,
        })
        .collect();
    for &(open, _, close_ch) in opens.iter().rev() {
        let Some(close) = subject[open..].find(close_ch).map(|j| j + open) else {
            continue;
        };
        let inner = &subject[open + 1..close];
        let sep = inner
            .find('/')
            .map(|i| (i, 1))
            .or_else(|| inner.to_ascii_lowercase().find(" of ").map(|i| (i, 4)));
        let Some((si, sl)) = sep else { continue };
        let (Ok(n), Ok(m)) = (
            inner[..si].trim().parse::<u32>(),
            inner[si + sl..].trim().parse::<u32>(),
        ) else {
            continue;
        };
        let mut base = String::new();
        base.push_str(subject[..open].trim_end());
        base.push_str(subject[close + close_ch.len_utf8()..].trim_end());
        return Some((base, n, m, open));
    }
    None
}

/// Is the pair at byte offset `open` the subject's LEADING one - the
/// posting-session tag rather than a part counter?
fn pair_is_leading(subject: &str, open: usize) -> bool {
    subject
        .find(|c| !char::is_whitespace(c))
        .is_some_and(|first| first == open)
}

/// The posting-session tag: a subject that OPENS with `[37/209]` (or
/// `(37/209)`) is announcing "this file is number 37 of a 209-file
/// posting session" - a different pair from the trailing `(n/m)` part
/// counter `split_subject` extracts. The shattered-poster family keeps
/// it even while randomizing From per article (13 Aug 2026 census), so
/// it is session-assembly evidence. Digits only on both sides, both
/// nonzero, idx <= total - a leading hex repost tag (`[a1911f7bca]`)
/// or a bare year never parses.
pub fn session_tag(subject: &str) -> Option<(i64, i64)> {
    let s = subject.trim_start();
    let (open, close) = match s.chars().next()? {
        '[' => ('[', ']'),
        '(' => ('(', ')'),
        _ => return None,
    };
    let inner = &s[open.len_utf8()..s.find(close)?];
    let (a, b) = inner.split_once('/')?;
    let (Ok(idx), Ok(total)) = (a.trim().parse::<i64>(), b.trim().parse::<i64>()) else {
        return None;
    };
    (idx > 0 && total > 0 && idx <= total).then_some((idx, total))
}

/// Filename from a counter-stripped subject: the quoted name, else - for
/// the unquoted convention `Release.Name.part01.rar yEnc` - the first
/// whitespace token with a plausible extension (all-digit `.001`-style,
/// or letter-led 2-5 alphanumerics, or `.7z`). Quote-only parsing made
/// entire unquoted releases invisible to the indexer.
pub fn quoted_name(s: &str) -> Option<String> {
    if let Some(name) = crate::nzb::quoted_filename(s) {
        return Some(name.to_string());
    }
    s.split_whitespace()
        .find(|t| {
            // Poster furniture ("[#a.b.group]", "<foo.bar>") is not a
            // filename even when it carries a dotted extension shape.
            if !t.starts_with(|c: char| c.is_ascii_alphanumeric()) || t.contains('@') {
                return false;
            }
            let Some(dot) = t.rfind('.') else {
                return false;
            };
            let ext = &t[dot + 1..];
            dot > 0
                && ((ext.len() >= 2 && ext.bytes().all(|c| c.is_ascii_digit()))
                    || (ext.len() >= 2
                        && ext.len() <= 5
                        && ext.as_bytes()[0].is_ascii_alphabetic()
                        && ext.bytes().all(|c| c.is_ascii_alphanumeric()))
                    || ext.eq_ignore_ascii_case("7z"))
        })
        .map(str::to_string)
}

// ---- the scanner's generation split ----------------------------------
//
// TODO 136's closing paragraph: `promote_spot` learned to keep two
// generations of one release apart, and `ingest` did not. It still
// folds a repost onto `(stem, poster, grp)` - a re-rar, a repair
// repost, an automated reposter's second pass - so one row ends up
// holding two incompatible article sets, `make_nzb` emits ids from
// both, and the user downloads a "complete" release that extracts to
// garbage.
//
// The asymmetry that makes this NOT the spot fix: a spot arrives
// holding one post's complete manifest and can decide up front, while
// the scanner only learns the split when the conflicting article shows
// up, by which time rows are written. So the scanner cannot decide from
// its own batch. It asks the rows instead:
//
//   the triple decides where to LOOK; the article set decides whether
//   to ADOPT.
//
// A message-id is globally unique, so part N of file F of one posting
// always carries the same id. A candidate row that holds part N of F
// under a DIFFERENT id has been contradicted - proof, not a heuristic.
// Anything else (no such file, no shared part) is not evidence of
// anything, and unknown keeps the old adopt-in-place behaviour, exactly
// the "unkeyed means unknown" rule §136 settled for spots.
//
// That makes the routing chunk-stable without a stable digest of the
// chunk, which is what the spot fix relies on and the scanner cannot
// have: generation 2's second batch finds generation 2's row already
// there and adopts it, because sharing no parts with it contradicts
// nothing. Only a batch that contradicts EVERY candidate mints a row.
//
// Storage is the H4 marker, and deliberately so: `releases` carries
// UNIQUE(stem, poster, grp) as a TABLE constraint and `files` carries
// UNIQUE(release_id, filename) the same way, so neither can gain a
// generation column without a table rebuild - 16.35M file rows and
// 8.8 GB of segments JSON on the live index, the multi-GB open stall
// §136 rejected one table over. One marker vocabulary also means
// `base_poster` keeps working for every reader, spot-minted and
// scanner-minted rows alike.

/// One clustered file of a batch: its `(x/y)` total and its parts,
/// numbered part → (message-id, bytes).
type ClusterFiles = HashMap<String, (u32, BTreeMap<u32, (String, u64)>)>;

/// What one ingest pass makes of a batch of articles in memory, before
/// it opens a transaction: the clusters themselves, the four per-cluster
/// side-tables, and the two ledgers of what could not be placed.
///
/// A struct rather than seven returned values, because
/// [`Index::cluster_batch`] is the seam [`Index::ingest_pass`] was split
/// at and all seven cross it.
struct Clustered {
    /// (poster, stem) -> filename -> (total, parts: number -> (msgid, bytes)).
    clusters: HashMap<(String, String), ClusterFiles>,
    /// Earliest article Date per cluster - the release's upload time.
    posted: HashMap<(String, String), i64>,
    /// Pesto family: decoded counter range + earliest clock per cluster.
    pesto: HashMap<(String, String), (i64, i64, i64)>,
    /// Posting-session tag: the leading "[037/209]" file-of-session marker.
    sess: HashMap<(String, String), (i64, i64)>,
    /// Articles this pass refuses to place - see [`Index::ingest`].
    deferred: Vec<OverEntry>,
    /// Per-slot deferral ledger, for the generation-depth census.
    slot_gen: SlotGens,
    drops: DropCensus,
}

/// Fold one batch's parts into the parts a `files` row already holds,
/// keeping the LARGER byte count for a part BOTH of them carry.
///
/// `:bytes` is a per-SERVER approximation of one article, not a
/// property of the article, and two backbones measurably state it in
/// two different conventions. Measured 31 Aug 2026 over one article on
/// five providers: all five delivered the identical body (739,699
/// octets as received, CRLF), and three stated `:bytes` 740,327 while
/// two stated 734,624 / 734,581 - the same count with the line
/// terminators counted as LF, 0.77% low. Over a 3,000-article slab of
/// one group, servers on one backbone agreed on 99.8% of shared
/// articles and servers on DIFFERENT backbones agreed on NONE of
/// ~2,960.
///
/// `gapfill` re-scans an incomplete release on the SECONDARY provider
/// by design, so a plain overwrite is last-writer-wins between two
/// conventions: 28% of a banked 35,535-release census had moved three
/// days later, 97.5% of them downward, 533 of them by exactly 1/129 -
/// the pure signature of 128-character yEnc lines recounted LF instead
/// of CRLF - and 27 of them across a `junk_score` size threshold.
///
/// `max` is taken rather than first-writer-wins for three measured
/// reasons: it is monotone, so the stored number converges instead of
/// tracking whichever server was asked last; the larger value is the
/// better estimate of what a download actually pulls (740,327 stated
/// against 740,170 received, where the smaller convention is 5,546
/// octets under); and it heals a row whose stored count is 0, which is
/// what an unparseable OVER byte field parses to. The trade is that one
/// server over-stating a count pins it - acceptable for a field every
/// consumer already treats as an estimate, and the safe direction for a
/// size estimate to err in. Full write-up:
/// `research/INDEX-FILE-BYTES-REINGEST-DRIFT-2026-08-31.md`.
fn merge_parts(merged: &mut BTreeMap<u32, (String, u64)>, parts: BTreeMap<u32, (String, u64)>) {
    for (n, mut v) in parts {
        if let Some(prev) = merged.get(&n) {
            v.1 = v.1.max(prev.1);
        }
        merged.insert(n, v);
    }
}

/// One `files` row a release already holds, for a filename a batch is
/// about to write. `bytes` and `nsegs` are the row's stored aggregate
/// contribution, carried so the merge can subtract exactly what the
/// last write added (N8) instead of re-scanning every file row.
struct ExistingFile {
    segs: Vec<Seg>,
    total: u32,
    bytes: i64,
    nsegs: i64,
}

/// The `files` rows a release already holds, keyed by filename, for the
/// filenames a batch is about to write.
type ExistingFiles = HashMap<String, ExistingFile>;

/// Read back the file rows `rid` holds for the batch's filenames. One
/// statement per file, which is what the merge did anyway - this hoists
/// the read rather than adding one.
fn fetch_existing(
    db: &Connection,
    rid: i64,
    files: &ClusterFiles,
) -> rusqlite::Result<ExistingFiles> {
    let mut out = ExistingFiles::new();
    let mut q = db.prepare_cached(
        "SELECT segments, total_parts, bytes, nsegs
           FROM files WHERE release_id=?1 AND filename=?2",
    )?;
    for fname in files.keys() {
        if let Some(row) = q
            .query_row(rusqlite::params![rid, fname], |r| {
                Ok(ExistingFile {
                    segs: r.get::<_, SegList>(0)?.0,
                    total: r.get(1)?,
                    bytes: r.get(2)?,
                    nsegs: r.get(3)?,
                })
            })
            .optional()?
        {
            out.insert(fname.clone(), row);
        }
    }
    Ok(out)
}

/// Has this row been PROVEN to hold a different posting than `files`?
///
/// Only two things count, and both are proof rather than inference: a
/// file whose `(x/y)` total disagrees, and a part number the row holds
/// under a different message-id. A row that shares no file, or shares a
/// file but no part number, contradicts nothing - it is silent, not
/// disagreeing, and silence adopts.
///
/// The message-id test is the stronger of the two: a globally unique id
/// under a shared part number cannot be anything but a second posting.
/// The total test is weaker - a garbled subject line can invent an
/// `(x/y)` - and it deliberately keeps the D3 guard's old verdict while
/// changing what happens NEXT. D3 dropped such a batch; it now gets a
/// release of its own. For a real re-rar at a new volume size, which
/// shares no part number with the first posting and so has no other
/// signal, that is the whole point. For a garbled header the cost moves
/// from silence to one junk-scored row holding one article - noise in
/// the index, and noise is the side of this trade to be wrong on: the
/// other side hands somebody a "complete" download that extracts to
/// garbage.
fn contradicts(existing: &ExistingFiles, files: &ClusterFiles) -> bool {
    for (fname, (total, parts)) in files {
        let Some(prev) = existing.get(fname) else {
            continue;
        };
        if prev.total > 0 && *total > 0 && prev.total != *total {
            return true;
        }
        for (n, id, _) in &prev.segs {
            if parts
                .get(n)
                .is_some_and(|(mine, _)| norm_msgid(mine) != norm_msgid(id))
            {
                return true;
            }
        }
    }
    false
}

/// How many generation-marked siblings of one triple are ever
/// considered.
///
/// "A backstop, not a policy - reaching this would itself be the
/// anomaly" stood here until 1 Sep 2026, and was wrong in the same way
/// [`MAX_GEN_PASSES`]'s contract was, for the same reason. Measured over
/// 21 h of live daemon log: **811,828 postings dropped at this cap in
/// 15,759 events, 99.5% of them alt.binaries.teevee**. The shape is in
/// the per-event rate - moovee/movies/tv drop 1.0-1.3 postings per
/// event, which IS the backstop this comment described; teevee drops
/// 63.0, and its hourly count tracks the [`MAX_GEN_PASSES`] overflow at
/// Pearson r = 0.914 over 23 hourly buckets. One phenomenon, two caps.
///
/// The marked namespace does not hold "the reposts of one name by one
/// poster in one group": the key is a digest of the BATCH's own lowest
/// message-ids (see `pick_release_row`), so a reinjection flood that
/// presents a different msgid set every window mints a different
/// sibling every window. That is what puts the families past this cap
/// that [`pick_release_row`] counts and dates, and why the exact-home
/// probe below exists. The count is kept in that one place on purpose:
/// it has already more than doubled once, and a second copy here would
/// be the copy that goes stale.
const MAX_GEN_SIBLINGS: i64 = 16;

/// Every release row this batch's triple could mean: the plain-poster
/// row first, then any generation-marked siblings, oldest first.
///
/// TWO index-driven lookups rather than one predicate over both. The
/// obvious `stem=? AND grp=? AND (poster=? OR poster LIKE ?)` drops
/// `poster` from the UNIQUE(stem, poster, grp) prefix and degrades to a
/// scan of every row sharing the stem - which on the live index means
/// 22,831 rows for the worst obfuscated stem, per cluster, on the
/// hottest path in the scanner. The first query here is the exact point
/// lookup ingest always did; the second is a RANGE over the marked
/// namespace, which keeps the index prefix and so probes straight to an
/// empty range on the ordinary batch that has no siblings.
///
/// The range bounds are built rather than pattern-matched for the same
/// reason: SQLite only rewrites `LIKE 'lit%'` into a range under
/// conditions this column does not meet, and the poster is untrusted
/// header data whose own `%` would have to be escaped anyway.
fn gen_candidates(
    db: &Connection,
    stem: &str,
    poster: &str,
    grp: &str,
) -> rusqlite::Result<Vec<(i64, String)>> {
    let mut out: Vec<(i64, String)> = Vec::new();
    if let Some(id) = db
        .prepare_cached("SELECT id FROM releases WHERE stem=?1 AND poster=?2 AND grp=?3")?
        .query_row(rusqlite::params![stem, poster, grp], |r| r.get(0))
        .optional()?
    {
        out.push((id, poster.to_string()));
    }
    // [lo, hi) spans exactly the values `POSTER_GEN_MARK` can produce
    // for this poster: `hi` is `lo` with its last byte stepped, which
    // is the successor of every string having `lo` as a prefix.
    let lo = format!("{poster}{POSTER_GEN_MARK}");
    let mut hi = lo.clone().into_bytes();
    *hi.last_mut().expect("POSTER_GEN_MARK is never empty") += 1;
    let hi = String::from_utf8(hi).expect("POSTER_GEN_MARK ends in ASCII ':'");
    // No ORDER BY: adding one makes the planner abandon the covering
    // index for `idx_rel_stem` and scan every row sharing the stem -
    // measured on the live index, the exact regression this function is
    // shaped to avoid. The range scan already returns poster order,
    // which is deterministic, so the LIMIT is a stable cut and the id
    // ordering the adopt loop wants is applied below.
    let mut q = db.prepare_cached(
        "SELECT id, poster FROM releases
          WHERE stem=?1 AND poster>=?2 AND poster<?3 AND grp=?4
          LIMIT ?5",
    )?;
    let mut rows = q
        .query_map(
            rusqlite::params![stem, lo, hi, grp, MAX_GEN_SIBLINGS],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?
        .collect::<rusqlite::Result<Vec<(i64, String)>>>()?;
    rows.sort_unstable_by_key(|(id, _)| *id);
    out.extend(rows);
    Ok(out)
}

/// How many of the batch's own message-ids [`hidden_home`] probes
/// through the reverse map. `msgid_map_insert` keys the lowest
/// [`MSGID_KEYS_PER_FILE`] segments of each file, so probing that many
/// per file is the whole set the map could be holding for this posting
/// - anything beyond it is a lookup that cannot hit. The overall cut
/// bounds a cluster carrying hundreds of files; it costs the tail of a
/// wide cluster its probe, never a wrong answer. Spent BREADTH first,
/// so the tail that goes unprobed is only past this many FILENAMES -
/// see the loop in [`hidden_home`] for what depth-first cost.
const MAX_HOME_PROBES: usize = 32;

/// How many rows the reverse probe will TEST. Ordered by how many of
/// the batch's ids each one matched, so the row that shares the most
/// evidence is tested first; a stranger that collided on one truncated
/// hash cannot push the real home out of a window this wide.
const MAX_HOME_ROWS: usize = 4;

/// The row of this triple that already holds one of the batch's own
/// ARTICLES, found through the reverse message-id map rather than
/// through a key derived from coverage.
///
/// The saturated path's exact-home lookup is keyed on
/// `msgid_set_key(lowest present part of each present file)`, and that
/// is a function of what the BATCH carries, not of the generation it
/// belongs to. Coverage grows - a second server's spool carries part 1
/// where the first only had part 2, or carries a file the first never
/// saw - and the later batch computes a different key. The key lookup
/// misses, the LIMITed window cannot reach the row either, and the
/// cluster is dropped on every scan forever: the parts that had just
/// become available could never be added to the generation waiting for
/// them (read-only sweep 2, 15 Aug 2026, M4).
///
/// A message-id is the invariant: it does not change when its
/// neighbours arrive, and `msgid_map` is append-only per release, so
/// the ids a row was written under keep joining after it grows. Two
/// gates keep this from being a merge tool. The row must belong to
/// THIS triple's marked namespace - same stem, same group, the same
/// plain poster - so a shared article can never fold two postings by
/// different posters together. And `contradicts` still decides:
/// 64 bits of msgid hash can collide, and a batch that shares one
/// article while disagreeing on another part IS a second posting, which
/// is the case the D3 backstop exists for.
fn hidden_home(
    db: &Connection,
    stem: &str,
    poster: &str,
    grp: &str,
    files: &ClusterFiles,
    seen: &[(i64, String)],
) -> rusqlite::Result<Option<(i64, String, ExistingFiles)>> {
    // Deterministic order over a HashMap, so which ids a very wide
    // cluster spends its budget on is a property of the batch and not
    // of this run's hash seed.
    let mut names: Vec<&String> = files.keys().collect();
    names.sort_unstable();
    // BREADTH first, never depth: one id from EVERY filename before a
    // second from any. Spending the budget depth-first covered only the
    // first ~11 names (3 keys each into a 32-probe cut) and left the
    // rest of a wide cluster unprobed - so a compatible out-of-window
    // row that shares an article only with a LATER filename was never
    // found, hidden_home returned None, and the whole cluster was
    // dropped as Saturated. That is deterministic (the names are sorted
    // exactly so the probe set is a function of the batch), so it
    // repeated on every rescan and the newly available files stayed out
    // of the index for good - the same forever-drop the M4 fix above was
    // written to end, one step further in (read-only sweep 3, 16 Aug
    // 2026, M10). Same probes, same determinism; coverage goes from ~11
    // filenames to MAX_HOME_PROBES of them.
    let mut probes: Vec<&str> = Vec::new();
    'budget: for round in 0..MSGID_KEYS_PER_FILE {
        for name in &names {
            let (_, parts) = &files[*name];
            if let Some((id, _)) = parts.values().nth(round) {
                probes.push(id.as_str());
                if probes.len() >= MAX_HOME_PROBES {
                    break 'budget;
                }
            }
        }
    }
    let mut sel = db.prepare_cached("SELECT release_id FROM msgid_map WHERE h=?1")?;
    let mut hits: BTreeMap<i64, u32> = BTreeMap::new();
    let mut probed: std::collections::HashSet<i64> = std::collections::HashSet::new();
    for id in probes {
        let h = claims::msgid_hash(id);
        if !probed.insert(h) {
            continue;
        }
        for rid in sel.query_map([h], |r| r.get::<_, i64>(0))? {
            let rid = rid?;
            // Every candidate the window offered was already fetched
            // and contradicted above; re-testing them buys nothing.
            if seen.iter().any(|(id, _)| *id == rid) {
                continue;
            }
            *hits.entry(rid).or_default() += 1;
        }
    }
    let mut ranked: Vec<(i64, u32)> = hits.into_iter().collect();
    ranked.sort_by_key(|&(rid, n)| (std::cmp::Reverse(n), rid));
    let mark = format!("{poster}{POSTER_GEN_MARK}");
    let mut q =
        db.prepare_cached("SELECT poster FROM releases WHERE id=?1 AND stem=?2 AND grp=?3")?;
    for (rid, _) in ranked.into_iter().take(MAX_HOME_ROWS) {
        let Some(row_poster) = q
            .query_row(rusqlite::params![rid, stem, grp], |r| r.get::<_, String>(0))
            .optional()?
        else {
            continue;
        };
        if row_poster != poster && !row_poster.starts_with(&mark) {
            continue;
        }
        let existing = fetch_existing(db, rid, files)?;
        if !contradicts(&existing, files) {
            return Ok(Some((rid, row_poster, existing)));
        }
    }
    Ok(None)
}

/// What [`pick_release_row`] decided for one cluster.
enum RowPick {
    /// Write into this row (plain or marked); the batch does not
    /// contradict it. Carries the file rows the row already holds, and
    /// the row's id when the pick already found it - every adopt but the
    /// two "this triple is free" ones probed the UNIQUE index to decide,
    /// so handing the id on saves the caller probing it a second time.
    /// `None` means no row exists under this key yet.
    Adopt(Option<i64>, String, ExistingFiles),
    /// Every candidate is contradicted: write under this brand-new
    /// marked poster value.
    Mint(String),
    /// Every candidate is contradicted, the marked namespace is already
    /// at [`MAX_GEN_SIBLINGS`], and no existing row is this batch's exact
    /// home. Drop the cluster - the articles re-arrive on the next scan
    /// of this window, exactly like the [`MAX_GEN_PASSES`] overflow.
    Saturated,
}

/// Pick the `releases.poster` value this batch should be written under,
/// and hand back the file rows that row already holds so the caller's
/// merge does not read them a second time.
///
/// Adopts the first candidate that does not contradict, which for every
/// ordinary batch is the plain-poster row on the first test. The cost
/// over the old unconditional upsert is one empty range probe: the
/// per-file reads are the ones the merge was going to do anyway, handed
/// back rather than repeated. Mints a marked row only when every
/// candidate is contradicted AND the plain row is among them, so a
/// triple whose plain row is somehow free still lands there rather than
/// starting life marked.
///
/// Minting stops at [`MAX_GEN_SIBLINGS`]: `gen_candidates` never looks
/// past that many marked rows, so a seventeenth sibling could never be
/// adopted by any later batch - every re-arrival of its articles would
/// mint an eighteenth, and so on without bound. Measured on a live
/// index (14 Aug 2026): 6.5M marked rows, 166k families past the cap,
/// one family at 2,730 rows - flood bots reinject the same posting
/// under fresh message-ids, which this key treats as a new generation
/// every time. Re-measured 1 Sep 2026: 7,366,437 marked rows (32.78% of
/// the index) and 346,779 families at or past the cap, 2.1x the 14 Aug
/// figure - the flood did not abate, and this cap is what stands in it.
/// "At or past" is as sharp as that count can be:
/// `research/GEN-ROW-DEPTH-CENSUS-2026-09-01.md` measures stored family
/// depth as TRUNCATED at exactly 17 by this cap (2 families in 15.1M
/// exceed it), so the depth a flood actually reaches - 133 to 850,
/// dumped from memory during ingest - is not recorded anywhere and
/// cannot be recovered from the index.
/// Past the cap the cluster is dropped instead, but only
/// after one exact lookup of the batch's own marked key: no row of its
/// own can be minted, and dropping is right only when no EXISTING row
/// is its exact home. A family already past the cap has siblings the
/// candidate window cannot reach, and the pre-cap code reached them
/// through the caller's `ON CONFLICT` upsert.
fn pick_release_row(
    db: &Connection,
    stem: &str,
    poster: &str,
    grp: &str,
    files: &ClusterFiles,
) -> rusqlite::Result<RowPick> {
    let candidates = gen_candidates(db, stem, poster, grp)?;
    if candidates.is_empty() {
        return Ok(RowPick::Adopt(
            None,
            poster.to_string(),
            ExistingFiles::new(),
        ));
    }
    for (rid, row_poster) in &candidates {
        let existing = fetch_existing(db, *rid, files)?;
        if !contradicts(&existing, files) {
            return Ok(RowPick::Adopt(Some(*rid), row_poster.clone(), existing));
        }
    }
    // Every candidate holds a different posting, so this batch needs a
    // row of its own. If the PLAIN row is not among the candidates -
    // only marked siblings are, which nothing produces today - the plain
    // triple is free and is the natural home; starting life marked would
    // leave the unmarked row permanently unclaimable.
    if !candidates.iter().any(|(_, p)| p == poster) {
        return Ok(RowPick::Adopt(
            None,
            poster.to_string(),
            ExistingFiles::new(),
        ));
    }
    // Marked, keyed by the batch's own articles so the value is a
    // function of what it carries rather than an ordinal - the same
    // property the spot marker has, though here it is the adopt test
    // above and not the key that makes a later batch land right.
    //
    // The batch may itself straddle two generations across DIFFERENT
    // files (one file contradicts, another agrees), which no per-file
    // test can see. That costs the agreeing file a duplicate row on the
    // new release; the contradicted one is still kept apart, which is
    // the half that corrupts a download.
    //
    // Computed BEFORE the saturation test because the test needs it: see
    // the exact-home probe below.
    let lowest: Vec<&str> = files
        .values()
        .filter_map(|(_, parts)| parts.values().next().map(|(id, _)| id.as_str()))
        .collect();
    let marked = format!(
        "{poster}{POSTER_GEN_MARK}{}",
        &msgid_set_key(&lowest)[..GEN_HEX]
    );
    if candidates.iter().filter(|(_, p)| p != poster).count() >= MAX_GEN_SIBLINGS as usize {
        // The cap stops new rows being MINTED; it was never meant to
        // stop an existing row being FED. `gen_candidates` cuts at
        // MAX_GEN_SIBLINGS in poster order, so on a family already past
        // the cap - hundreds of thousands of them, counted and dated at
        // `pick_release_row`, plus anything the uncapped spot minting
        // site pushes over - this batch's own
        // deterministic home can sort outside the window and never be
        // offered for adoption. Before the fix that row was invisible
        // and the cluster was dropped on every scan, forever: a second
        // server's spool holding parts the first missed could never add
        // them. One indexed point lookup, only on the already-rare
        // saturated path, and only when the window did not already show
        // the key (in which case it was tested and contradicted above).
        if !candidates.iter().any(|(_, p)| *p == marked)
            && let Some(rid) = db
                .prepare_cached("SELECT id FROM releases WHERE stem=?1 AND poster=?2 AND grp=?3")?
                .query_row(rusqlite::params![stem, &marked, grp], |r| {
                    r.get::<_, i64>(0)
                })
                .optional()?
        {
            // Still gated on `contradicts`: 12 hex digits of the msgid
            // set key can collide, and adopting on the key alone would
            // union two postings into one row - the "complete download
            // that extracts to garbage" the D3 backstop exists to stop.
            let existing = fetch_existing(db, rid, files)?;
            if !contradicts(&existing, files) {
                return Ok(RowPick::Adopt(Some(rid), marked, existing));
            }
        }
        // The key above only finds a row minted from the SAME coverage
        // this batch carries. `hidden_home` asks the question the key
        // cannot: which row past the window already holds one of these
        // very articles.
        if let Some((rid, row_poster, existing)) =
            hidden_home(db, stem, poster, grp, files, &candidates)?
        {
            return Ok(RowPick::Adopt(Some(rid), row_poster, existing));
        }
        return Ok(RowPick::Saturated);
    }
    // debug, not warn: reinjection floods hit this thousands of times a
    // tick, and the per-cluster storm wrote 90 MB of daemon.log in one
    // day on a tester's box (which Windows never caps - the logtee's
    // file cap is unix-only). The per-pass summary in `ingest_pass`
    // carries the counts at warn level.
    tracing::debug!(
        target: "index",
        "{stem} by {poster} in {grp} is already release {} with different articles - \
         indexing this posting separately",
        candidates[0].0
    );
    // A brand-new row by construction: the marked value did not appear
    // among the candidates, all of which were contradicted.
    Ok(RowPick::Mint(marked))
}

/// How many times [`Index::ingest`] re-drives its own leftovers before
/// giving up on a batch, and so the most generations of one release a
/// single OVER window can contribute.
///
/// "Three generations inside one window is beyond anything observed"
/// stood here until 1 Sep 2026 and was wrong by a factor of ~45.
/// Measured on live `alt.binaries.teevee` traffic, 25,000-header
/// windows: **194 distinct (poster, file, part) slots carrying 133-134
/// distinct message-ids each** - a reinjection flood, the same shape
/// [`MAX_GEN_SIBLINGS`] was raised against on 14 Aug 2026. So this cap
/// is load-bearing on ordinary production traffic, not the
/// untrusted-input backstop the old comment claimed, and 91% of a
/// teevee window defers on the first pass.
///
/// Raising it is the wrong lever twice over: draining a 134-deep slot
/// needs ~134 passes (each pass places exactly one article per slot -
/// measured leftover series `[25000, 23257, 23058, 22862, 22668]`,
/// shrinking by the 194-slot count every time), and every pass past the
/// first mints another marked generation row for a copy that carries no
/// article the index does not already hold. Full measurement:
/// `research/TEEVEE-GENERATION-PASS-DROPS-2026-09-01.md`.
const MAX_GEN_PASSES: u32 = 4;

/// How many articles one [`Index::ingest`] call should carry.
///
/// A caller that has fetched MORE than this - the deepen scan asks the
/// wire for up to 100,000 headers in one OVER when the fan-out is a
/// single connection - should ingest in `entries.chunks(INGEST_BATCH)`
/// rather than hand the whole fetch over at once. The fetch size and the
/// ingest size are separate decisions that want opposite answers: on the
/// wire a lone connection reads 82-95k headers/s at 100k ranges against
/// 31-54k/s at 10k, so big is right there; in `ingest` big is wrong.
///
/// Measured 3 Sep 2026 on `crates/nzbkit/examples/indexscan_bench`
/// (400,000 headers, four sizes interleaved, three rounds, median):
///
/// | batch | instructions/header | max RSS | transaction p50 | p90 | max |
/// |---|---|---|---|---|---|
/// | 10,000 | 207,239 | 140 MB | 242 ms | 405 ms | 657 ms |
/// | 20,000 | 203,146 | 151 MB | 533 ms | 715 ms | 821 ms |
/// | 50,000 | 200,295 | 178 MB | 1,350 ms | 1,630 ms | 2,620 ms |
/// | 100,000 | 198,860 | 218 MB | 2,660 ms | 3,410 ms | 4,140 ms |
///
/// A bigger batch buys 4.0% of instructions and costs 11x the hold, plus
/// 55% more RSS. The CPU saving is real, monotonic and tiny; the hold is
/// neither. `ingest` runs its passes in a transaction, and the scan's
/// `Index::open_scratch` connection is not the daemon's, so that hold is
/// a SQLite WRITE-LOCK hold every other connection waits out against a
/// 10 s `busy_timeout` - a 4.14 s transaction spends 41% of that budget
/// in one call. It is the stall in memory topic
/// `nzbfast-tail-blocked-on-index-mutex`, priced.
///
/// 20,000 rather than 10,000 because it is what the rest of the engine
/// already picked independently - the gapfill leg's `CHUNK` and the tip
/// walker's `TIP_CHUNK` are both 20,000 - so this makes the deepen pass
/// agree with its neighbours instead of minting a third number, and it
/// keeps three quarters of the instruction saving.
///
/// # This changes generation outcomes on reposted traffic, deliberately
///
/// [`Index::ingest`]'s generation split resolves a second posting of the
/// same (file, part) slot WITHIN a batch, under a budget of
/// [`MAX_GEN_PASSES`] passes; articles past that budget are dropped and
/// re-arrive on a later scan. The budget is PER BATCH, so regrouping the
/// same header stream changes both how many articles the budget drops
/// and the `POSTER_GEN_MARK` suffix of any generation row it mints
/// (that suffix is a digest of the batch's own lowest message-ids, so it
/// is a function of what the batch carries, by design).
///
/// Measured on 600,000 headers at a 25% repost rate, the same stream at
/// three batch sizes - every one of which the SHIPPED code already
/// reaches today, because `scan_pass` picks `(100_000 / nconn)` and
/// `nconn` follows the user's connection count:
///
/// | batch | reached today at | releases | files | msgid_map | gen-depth drops |
/// |---|---|---|---|---|---|
/// | 10,000 | nconn 10 (turbo) | 86,856 | 93,475 | 107,301 | 936 |
/// | 20,000 | nconn 5 (default) | 86,850 | 93,428 | 107,161 | 2,808 |
/// | 100,000 | nconn 1 (one server) | 86,838 | 93,291 | 106,757 | 12,182 |
///
/// So the row set is ALREADY a function of a setting in the UI: a
/// single-server install drops 13x more articles than a ten-connection
/// one on an identical stream. Pinning ingest here does not introduce
/// that variance, it REMOVES it - the generation outcome stops depending
/// on the fan-out - and it lands on the end of the range that keeps more
/// articles. On traffic with no repost in the window the regrouping is
/// inert: 600,000 headers dumped at 100,000 and at 20,000 differ in one
/// `kv` row, `ingest_drop_since`, which is a `SystemTime::now()` stamp
/// that differs between any two runs of any binary.
///
/// Full record: `research/INDEXER-SCAN-CPU-AUDIT-2026-09-03.md`.
pub const INGEST_BATCH: usize = 20_000;

/// The generation pass loop's state for one batch: how many passes
/// remain AFTER the current one, and the running census of articles the
/// loop dropped because their slot is deeper than it can place.
#[derive(Default)]
struct GenPasses {
    /// Passes still to come after this one. A slot can gain at most one
    /// article per pass, so this is exactly how many more of a slot's
    /// contradicting articles are worth carrying; at 0 the last pass is
    /// running and a deferral has nowhere left to go.
    budget: u32,
    /// Articles dropped for being past `budget` in their slot.
    dropped: u64,
    /// Articles seen for the single deepest (cluster, file, part) slot -
    /// the flood-depth number, and the one worth reading.
    deepest: usize,
    /// This batch's slot-depth distribution - see [`GenDepthCensus`].
    /// Instrumentation only; nothing here is read by the pass loop.
    depth: GenDepthCensus,
    /// FIRST pass only: each clashing cluster to the depth of its
    /// SHALLOWEST clashing slot, carried across the passes so a
    /// generation row minted in pass 2, 3 or 4 can be filed under the
    /// depth the whole window really presented. A later pass sees only
    /// the leftovers, where every slot is at most `MAX_GEN_PASSES`
    /// deep, so its own ledger cannot answer that. Only clashing
    /// clusters get an entry, so an ordinary batch never allocates.
    floor: HashMap<(String, String), usize>,
}

impl GenPasses {
    /// Is the FIRST pass running? `budget` is `MAX_GEN_PASSES - pass`,
    /// so this is the pass that sees the batch entire - the only one
    /// whose slot ledger holds a window's true depth, and the one whose
    /// row a depth cutoff would keep rather than decline.
    fn first_pass(&self) -> bool {
        self.budget + 1 == MAX_GEN_PASSES
    }

    /// Fold the FIRST pass's slot ledger into the census, ignoring
    /// every later one - a later pass sees only leftovers and would
    /// count the same slots again at a shallower depth. Called AFTER
    /// the clustering loop rather than inside it: only slots that
    /// actually clashed have an entry, so this walks hundreds where the
    /// loop walks tens of thousands.
    ///
    /// Depth is `1 + distinct deferred ids + articles dropped` - the
    /// same quantity `defer_fits_budget` folds into `deepest`, and it
    /// carries the same stated limit: a repeat of an id that was already
    /// dropped counts twice, so a window that re-presents the same
    /// message-id past the budget reads one deeper than it is. Live
    /// message-ids inside one window are unique, so this is a
    /// hostile-input caveat rather than a measurement error.
    fn observe_slots(&mut self, slots: &SlotGens) {
        if !self.first_pass() {
            return;
        }
        for ((cluster, _, _), (kept, dropped)) in slots {
            let depth = 1 + kept.len() + dropped;
            self.depth.slots[gen_depth_bucket(depth)] += 1;
            let floor = self.floor.entry(cluster.clone()).or_insert(depth);
            *floor = (*floor).min(depth);
        }
    }

    /// File one freshly minted generation row under its cluster's
    /// shallowest first-pass slot depth.
    ///
    /// Passes 2+ only: pass 1's row is the one a depth cutoff would
    /// KEEP, so counting it would overstate the policy by one row per
    /// clashing cluster. A cluster with no first-pass entry never
    /// clashed and is not a generation this census is about - which is
    /// also why the key is only built after those two tests.
    fn note_gen_row(&mut self, poster: &str, stem: &str) {
        if self.first_pass() || self.floor.is_empty() {
            return;
        }
        if let Some(&depth) = self.floor.get(&(poster.to_string(), stem.to_string())) {
            self.depth.rows[gen_depth_bucket(depth)] += 1;
        }
    }
}

/// One [`Index::ingest_pass`]'s per-slot deferral ledger: a (cluster,
/// file, part) slot to the distinct message-ids it has already deferred
/// and the count it dropped outright.
type SlotGens =
    HashMap<((String, String), String, u32), (std::collections::HashSet<String>, usize)>;

/// Can this contradicting article still reach a row from this batch?
///
/// A pass places exactly ONE article per (cluster, file, part) slot, so
/// with `gp.budget` passes left after this one, only that many more of
/// the slot's contradicting articles can ever be placed. Everything past
/// that is provably unplaceable, and answering `false` drops it in the
/// pass that can prove it rather than carrying it through every
/// remaining pass to be dropped at the end - the same articles placed
/// and the same articles dropped, without the passes. Measured on
/// teevee, 22,463 of 23,257 leftovers now go in the first pass rather
/// than the fourth.
///
/// Distinct ids, not articles: a repeat of an already-deferred id is
/// free, because the next pass writes it into the slot it just filled.
fn defer_fits_budget(
    slots: &mut SlotGens,
    slot: ((String, String), String, u32),
    msgid: &str,
    gp: &mut GenPasses,
) -> bool {
    let seen = slots.entry(slot).or_default();
    let idn = norm_msgid(msgid);
    let fits = seen.0.contains(idn) || seen.0.len() < gp.budget as usize;
    if fits {
        seen.0.insert(idn.to_string());
    } else {
        seen.1 += 1;
    }
    gp.deepest = gp.deepest.max(1 + seen.0.len() + seen.1);
    fits
}

/// The generation-depth census's buckets: the LOW bound of each, with
/// the label its `kv` key carries. Labels are zero-padded low bounds so
/// a plain `ORDER BY k` over the census sorts by depth rather than
/// putting `1025_up` between `0009_0012` and `0013_0016`.
///
/// Log-ish, but singleton up to 8 and quartered to 32, because that is
/// where the decision lives: the prior from the stored (truncated) index
/// is ordinary reposts at depth 2-3 and floods at 133-850, so a cutoff
/// is going to be argued somewhere in 5..32 and a reader must be able to
/// price each candidate exactly. A cutoff at any bucket's low bound is
/// answered EXACTLY by summing that bucket and every one above it; a
/// cutoff at some other N (say 20) is bracketed, not answered.
const GEN_DEPTH_BUCKETS: [(usize, &str); 17] = [
    (2, "0002"),
    (3, "0003"),
    (4, "0004"),
    (5, "0005"),
    (6, "0006"),
    (7, "0007"),
    (8, "0008"),
    (9, "0009_0012"),
    (13, "0013_0016"),
    (17, "0017_0024"),
    (25, "0025_0032"),
    (33, "0033_0064"),
    (65, "0065_0128"),
    (129, "0129_0256"),
    (257, "0257_0512"),
    (513, "0513_1024"),
    (1025, "1025_up"),
];

/// Which [`GEN_DEPTH_BUCKETS`] entry a slot depth falls in. Depth is
/// never below 2 here - a slot only gets a ledger entry when a second,
/// contradicting article arrives for it - so the floor is bucket 0.
fn gen_depth_bucket(depth: usize) -> usize {
    GEN_DEPTH_BUCKETS
        .iter()
        .rposition(|(lo, _)| depth >= *lo)
        .unwrap_or(0)
}

/// How deep the generation slots in one batch were, and what it cost.
///
/// Stage 1 of the generation-row policy (1 Sep 2026): pure
/// instrumentation, and the ONLY way the question can be answered.
/// `MAX_GEN_SIBLINGS` truncates stored family depth at exactly 17
/// (`research/GEN-ROW-DEPTH-CENSUS-2026-09-01.md`), so the depths a
/// flood really reaches - 133 to 850 for one (poster, file, part) slot
/// inside one 25,000-header window - exist only in memory during ingest
/// and are in no stored row. A depth-N cutoff therefore cannot be
/// backtested; it can only be costed on forward traffic, here.
///
/// NOT a drop census, and deliberately NOT under the `ingest_drop_`
/// prefix that `DropCensus` writes and `Index::ingest_drop_census`
/// scans, for two reasons. `rows` counts generation rows MINTED, which
/// is the opposite of a drop and would be classified as one by any
/// prefix reader; and this census is group x bucket, so it is up to a
/// few hundred keys, which would swamp that reader's unclassified
/// bucket. Read it with sqlite3 (see the module tests) until somebody
/// needs a surface, and note the near-rhyme with the existing
/// `ingest_drop_gen_depth`, which is a genuine drop counter for
/// articles this arm refuses.
///
/// TWO QUANTITIES, and whoever picks the cutoff wants the second.
///
/// * `slots` counts (cluster, file, part) SLOTS at a depth. It answers
///   the safety half - does depth separate a flood from an ordinary
///   repost, per group - which needs a distribution and not a total.
/// * `rows` counts generation-marked rows the batch actually MINTED,
///   filed under the bucket of the SHALLOWEST clashing slot in their
///   cluster. That is exactly "rows a depth-N cutoff would decline":
///   a row is minted per cluster per pass, and a cutoff at N stops a
///   cluster reaching pass 2 only when EVERY one of its clashing slots
///   is at depth >= N, because a slot below the cutoff still defers and
///   still carries the cluster forward. Filing by the deepest slot
///   instead would over-count a mixed cluster.
///
/// Rows are counted where they are minted rather than derived from
/// depth, which matters on this index: a family already at
/// `MAX_GEN_SIBLINGS` mints nothing at all (`RowPick::Saturated`), so
/// the arithmetic `min(depth, MAX_GEN_PASSES) - 1` would price a cutoff
/// well above what it would really reclaim.
#[derive(Default)]
struct GenDepthCensus {
    slots: [u64; GEN_DEPTH_BUCKETS.len()],
    rows: [u64; GEN_DEPTH_BUCKETS.len()],
}

/// The prefix every generation-depth counter shares, and the epoch the
/// readout dates them by. One copy, read by both the writer below and
/// [`Index::gen_depth_census`] - a second spelling of a key is a census
/// that silently reports nothing.
pub(crate) const GEN_DEPTH_KEY_PREFIX: &str = "ingest_gen_depth_census_";
pub(crate) const GEN_DEPTH_SINCE_KEY: &str = "ingest_gen_depth_census_since";

impl GenDepthCensus {
    /// Fold one batch into the running per-group totals. One kv
    /// read/write per NON-EMPTY bucket and nothing for a batch that
    /// clashed nowhere, which is every ordinary batch; the measured
    /// flood shape touches two keys.
    fn record(&self, ix: &Index, grp: &str, now: i64) -> rusqlite::Result<()> {
        let mut wrote = false;
        for (metric, counts) in [("slots", &self.slots), ("rows", &self.rows)] {
            for (i, add) in counts.iter().enumerate().filter(|(_, n)| **n > 0) {
                let k = format!(
                    "{GEN_DEPTH_KEY_PREFIX}{metric}:{grp}:{}",
                    GEN_DEPTH_BUCKETS[i].1
                );
                let cur: u64 = ix.kv_get(&k).and_then(|v| v.parse().ok()).unwrap_or(0);
                ix.kv_set(&k, &(cur + add).to_string())?;
                wrote = true;
            }
        }
        // The totals are cumulative and never reset, so a rate needs a
        // start. Stamped once, and only on an index this census has
        // never touched, so it dates the counters rather than the read -
        // the same rule `ingest_drop_since` follows. `now` is the scan
        // clock the rest of the batch is written against, not a fresh
        // syscall.
        if wrote && ix.kv_get(GEN_DEPTH_SINCE_KEY).is_none() {
            ix.kv_set(GEN_DEPTH_SINCE_KEY, &now.to_string())?;
        }
        Ok(())
    }
}

/// What one [`Index::ingest_pass`] threw away, and why.
///
/// The first three (commissioning memo rec 3, 31 Aug 2026) were silent
/// `continue`s for the life of the indexer, so the size of the
/// fully-subject-obfuscated band - every article whose subject carries
/// no filename at all, the ngPost `--obfuscate` shape - was not merely
/// unknown but unknowable. nZEDb counts the same drop (`notYEnc++`) and
/// writes it to a log; these run into kv totals, which is the number the
/// no-filename admission decision (rec 4) has been waiting on.
///
/// `gen_depth` (1 Sep 2026) is the fourth and is not an obfuscation
/// measure: it counts the reinjection surplus `defer_fits_budget`
/// refuses.
#[derive(Default)]
struct DropCensus {
    unparseable: u64,
    no_filename: u64,
    empty_stem: u64,
    gen_depth: u64,
}

/// When this index started counting drops, stamped once and never
/// again. NOT a counter and never reported as one - the census excludes
/// it by name, so a `kv` prefix scan cannot mistake a clock for a total.
pub(crate) const DROP_SINCE_KEY: &str = "ingest_drop_since";

/// The prefix every census counter shares. The readout scans for this
/// rather than hard-listing the counters it knows, so a counter added
/// later is VISIBLE the day it lands instead of waiting for someone to
/// extend a list - which is the exact defect this census had for its
/// first day of life, when four keys accumulated 5.8M drops and nothing
/// outside a unit test read any of them.
pub(crate) const DROP_KEY_PREFIX: &str = "ingest_drop_";

impl DropCensus {
    /// Running totals only, no per-batch log line: a tier-4 group makes
    /// these drops on nearly every batch, and a routine event logged
    /// routinely is a log nobody reads. `kv` is the census.
    fn record(&self, ix: &Index) -> rusqlite::Result<()> {
        let keys = [
            ("ingest_drop_unparseable", self.unparseable),
            ("ingest_drop_no_filename", self.no_filename),
            ("ingest_drop_empty_stem", self.empty_stem),
            ("ingest_drop_gen_depth", self.gen_depth),
        ];
        // Stamp the window OPEN, once, and only on an index that has
        // never counted: a cumulative total with no start is a number
        // nobody can turn into a rate, and stamping one on an index that
        // was ALREADY counting would date 5.8M drops to this afternoon.
        // So the guard is the absence of every counter key, which is the
        // one moment the claim is true - and an index that was already
        // counting when this landed stays unstamped forever and is
        // reported as an unknown window rather than a confident one.
        // This is the same argument as `shatter_fold_census_partial`,
        // taken from the other end: that one records that the totals are
        // partial, this one records when they stopped being so.
        if ix.kv_get(DROP_SINCE_KEY).is_none() && keys.iter().all(|(k, _)| ix.kv_get(k).is_none()) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            ix.kv_set(DROP_SINCE_KEY, &now.to_string())?;
        }
        for (k, add) in keys {
            if add > 0 {
                let cur: u64 = ix.kv_get(k).and_then(|v| v.parse().ok()).unwrap_or(0);
                ix.kv_set(k, &(cur + add).to_string())?;
            }
        }
        Ok(())
    }
}

impl Index {
    /// The ingest drop census, read back (`mode=index_drops`).
    ///
    /// The counters have been written since 31 Aug 2026 and, until this
    /// existed, nothing outside a unit test read one: 5.8M no-filename
    /// drops sat on the live index while the no-filename admission
    /// decision they were taken for could not be made from any shipped
    /// surface. Read-only, one `kv` scan, no table touched.
    ///
    /// TWO FAMILIES, and they do not mean the same thing:
    ///
    /// * `dropped` - the article was discarded and does not come back.
    ///   `no_filename` is the fully-subject-obfuscated band (the ngPost
    ///   `--obfuscate` shape), `empty_stem` a filename that reduces to
    ///   nothing, `unparseable` a missing message-id or an `(n/m)` that
    ///   will not parse.
    /// * `over_budget` - `gen_depth`, the reinjection surplus a pass
    ///   refuses because the slot already holds more contradicting
    ///   articles than the remaining generation passes can place. Those
    ///   articles are NOT lost: they re-arrive on the next scan of that
    ///   window. Summing them with the first family would be a category
    ///   error, so nothing here does.
    ///
    /// A KEY THIS DOES NOT KNOW IS REPORTED, NOT DROPPED. The scan is
    /// over the `ingest_drop_` prefix rather than a list of four names,
    /// and anything unrecognised lands in `unclassified` under its full
    /// key with its raw value. A counter added tomorrow is therefore
    /// visible the day it lands - unclaimed as to meaning, which is the
    /// honest half - instead of waiting for somebody to remember this
    /// function. That is this census's own founding defect, and it is
    /// the one a `git grep` for the key name will not save you from.
    ///
    /// THE TOTALS ARE CUMULATIVE AND NEVER RESET, and `window_known`
    /// says whether that window has a start at all. `since` is stamped
    /// only on an index that had never counted (see `DROP_SINCE_KEY`),
    /// so an index already counting when the stamp landed reports
    /// `window_known: false` forever - which is the truth, and is what
    /// stops a reader dividing 5.8M by an uptime it made up.
    ///
    /// A FAILED SCAN IS AN ERROR, NOT AN EMPTY CENSUS. Swallowing it
    /// would answer a database this could not read with a full set of
    /// confident zeroes, which reads as "nothing was dropped" - the same
    /// class of silence the counters were added to end.
    pub fn ingest_drop_census(&self) -> rusqlite::Result<serde_json::Value> {
        // `_` is a LIKE wildcard, and this prefix carries two of them:
        // unescaped, `ingest_drop_%` also matches whatever a future
        // `ingestXdropY` key is called, which is how a census quietly
        // starts reporting somebody else's numbers.
        let pat = format!("{}%", DROP_KEY_PREFIX.replace('_', r"\_"));
        let mut stmt = self
            .db
            .prepare("SELECT k, v FROM kv WHERE k LIKE ?1 ESCAPE '\\'")?;
        let rows: Vec<(String, String)> = stmt
            .query_map([pat], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut dropped = serde_json::Map::new();
        let mut over_budget = serde_json::Map::new();
        let mut unclassified = serde_json::Map::new();
        let mut dropped_total: u64 = 0;
        // Materialize the three known `dropped` counters as zeroes: a
        // counter that has never fired has no key (`empty_stem` has none
        // on the live index), and an absent field reads as "this build
        // does not count that" rather than "it has not happened".
        for k in ["no_filename", "empty_stem", "unparseable"] {
            dropped.insert(k.to_string(), serde_json::json!(0));
        }
        over_budget.insert("gen_depth".to_string(), serde_json::json!(0));
        let mut since: Option<i64> = None;
        for (k, v) in rows {
            if k == DROP_SINCE_KEY {
                since = v.parse().ok();
                continue;
            }
            let short = k.trim_start_matches(DROP_KEY_PREFIX);
            let n: Option<u64> = v.parse().ok();
            match (short, n) {
                ("no_filename" | "empty_stem" | "unparseable", Some(n)) => {
                    dropped_total += n;
                    dropped.insert(short.to_string(), serde_json::json!(n));
                }
                ("gen_depth", Some(n)) => {
                    over_budget.insert(short.to_string(), serde_json::json!(n));
                }
                // A known name whose value will not parse is a corrupt
                // counter, not a zero: it goes to `unclassified` with the
                // string that is actually there.
                _ => {
                    unclassified.insert(k, serde_json::json!(v));
                }
            }
        }
        Ok(serde_json::json!({
            "dropped": dropped,
            "dropped_total": dropped_total,
            "over_budget": over_budget,
            "unclassified": unclassified,
            "since": since,
            "window_known": since.is_some(),
        }))
    }

    /// The generation-depth census, nested for reading: metric ->
    /// group -> bucket -> count, plus the bucket vocabulary IN ORDER.
    ///
    /// Served as a `gen_depth` object beside `dropped` and `over_budget`
    /// on `mode=index_drops` and deliberately NEVER merged into either:
    /// `slots` is not a drop and `rows` is the opposite of one, so
    /// `dropped_total` must keep summing exactly the three outright-drop
    /// counters. Its window is its OWN - the two censuses are stamped
    /// independently and on any existing index their stamps differ, so
    /// one shared `window_known` would be wrong the moment it mattered.
    ///
    /// `buckets` is the half a reader cannot reconstruct: the counters
    /// are a histogram and the cutoff question is "sum this bucket and
    /// every DEEPER one", which needs the order and needs to include
    /// the buckets no group has reached. Labels sort lexicographically
    /// by design, but a reader should not have to know that.
    ///
    /// Same three rules as [`Self::ingest_drop_census`], for the same
    /// reasons: the scan is over a prefix rather than a name list (with
    /// the `_` LIKE wildcards escaped, or it would also match a future
    /// `ingestXgenY` key), an unrecognised key is REPORTED under
    /// `unclassified` rather than dropped, and a failed scan is an
    /// error rather than a census of confident zeroes.
    pub fn gen_depth_census(&self) -> rusqlite::Result<serde_json::Value> {
        let pat = format!("{}%", GEN_DEPTH_KEY_PREFIX.replace('_', r"\_"));
        let mut stmt = self
            .db
            .prepare("SELECT k, v FROM kv WHERE k LIKE ?1 ESCAPE '\\'")?;
        let rows: Vec<(String, String)> = stmt
            .query_map([pat], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut by_metric: std::collections::BTreeMap<
            String,
            serde_json::Map<String, serde_json::Value>,
        > = ["slots", "rows"]
            .iter()
            .map(|m| ((*m).to_string(), serde_json::Map::new()))
            .collect();
        let mut unclassified = serde_json::Map::new();
        let mut since: Option<i64> = None;
        for (k, v) in rows {
            if k == GEN_DEPTH_SINCE_KEY {
                since = v.parse().ok();
                continue;
            }
            // `<metric>:<group>:<bucket>`. Split the metric off the
            // front and the bucket off the BACK, so a group carrying a
            // colon lands whole rather than shredding the key into
            // `unclassified` - newsgroup names cannot, but the census
            // should not be the thing that assumes it.
            let short = k.trim_start_matches(GEN_DEPTH_KEY_PREFIX);
            match (
                short
                    .split_once(':')
                    .and_then(|(m, rest)| rest.rsplit_once(':').map(|(grp, bkt)| (m, grp, bkt))),
                v.parse::<u64>().ok(),
            ) {
                (Some((m, grp, bkt)), Some(n))
                    if by_metric.contains_key(m)
                        && GEN_DEPTH_BUCKETS.iter().any(|(_, l)| *l == bkt) =>
                {
                    by_metric
                        .get_mut(m)
                        .expect("checked by contains_key")
                        .entry(grp.to_string())
                        .or_insert_with(|| serde_json::json!({}))
                        .as_object_mut()
                        .expect("just inserted an object")
                        .insert(bkt.to_string(), serde_json::json!(n));
                }
                // An unknown metric, an unknown bucket label, or a value
                // that will not parse. All three are somebody else's key
                // or a corrupt counter, and reporting is the honest
                // answer to both.
                _ => {
                    unclassified.insert(k, serde_json::json!(v));
                }
            }
        }
        Ok(serde_json::json!({
            "slots": by_metric["slots"],
            "rows": by_metric["rows"],
            "buckets": GEN_DEPTH_BUCKETS.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            "unclassified": unclassified,
            "since": since,
            "window_known": since.is_some(),
        }))
    }

    /// Ingest-time parse: built-in classifier plus the installed custom
    /// categories. Every site that WRITES kind/title_key must call this,
    /// not `parse_release`, or custom rows would flap back to their
    /// built-in kind on the next re-ingest touch.
    fn classify(&self, stem: &str) -> crate::release::Parsed {
        crate::categories::classify(stem, &self.custom)
    }

    /// TODO 24D: chunked re-classification of stored rows after the
    /// category config changed. Same shape as the quality_v10 migration
    /// (10k-row transactions, persisted cursor, write-only-on-change) so
    /// it can run against a live db without starving parallel scanners.
    /// The current config's fingerprint is stamped in `kv`; calling this
    /// again with an unchanged config is a cheap no-op. Returns the
    /// number of rows whose classification changed.
    pub fn reclassify_custom(&self) -> rusqlite::Result<u64> {
        let want = crate::categories::config_hash(&self.custom);
        let have: Option<String> = self
            .db
            .query_row("SELECT v FROM kv WHERE k='custom_cats_cfg'", [], |r| {
                r.get(0)
            })
            .ok();
        let cursor_key = "custom_cats_cursor";
        let mut cursor: i64 = if have.as_deref() == Some(want.as_str()) {
            // Same config: either done (no cursor) or resuming a pass
            // that a restart interrupted.
            match self
                .db
                .query_row("SELECT v FROM kv WHERE k=?1", [cursor_key], |r| {
                    r.get::<_, String>(0)
                })
                .ok()
                .and_then(|v| v.parse().ok())
            {
                Some(c) => c,
                None => return Ok(0),
            }
        } else {
            // New config: stamp it and start from the top. Stamping
            // FIRST is deliberate - an interrupted pass resumes from the
            // cursor rather than restarting, exactly like quality_v10.
            // The fingerprint and cursor are ONE state transition. Two
            // autocommit writes left a crash window where the new
            // fingerprint existed without a cursor; every later call then
            // read that as "already finished" and skipped reclassification
            // forever.
            // IMMEDIATE, not the deferred `unchecked_transaction`: this
            // reads a cursor and writes it back, and a deferred lock
            // upgrade does NOT get the busy timeout - it returns
            // SQLITE_BUSY at once (the same trap the nsegs migration
            // above documents). Losing it costs no data, but the retry is
            // a whole scan interval away, so a category change looks like
            // it did nothing.
            let tx = rusqlite::Transaction::new_unchecked(
                &self.db,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('custom_cats_cfg', ?1)
                 ON CONFLICT(k) DO UPDATE SET v=?1",
                [&want],
            )?;
            tx.execute(
                "INSERT INTO kv(k, v) VALUES(?1, '0')
                 ON CONFLICT(k) DO UPDATE SET v='0'",
                [cursor_key],
            )?;
            tx.commit()?;
            0
        };
        let mut changed = 0u64;
        loop {
            let tx = rusqlite::Transaction::new_unchecked(
                &self.db,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            // COALESCE(pre_title, stem), the same name every other
            // classification site reads (ingest_pass, the quality_v10
            // backfill): classifying the raw stem here rewrote pre-named
            // obfuscated releases back to kind=other / blank title_key /
            // junk>=70 on any category edit, and the naming seam refuses
            // rows whose pre_title is already set, so nothing healed them.
            let rows: Vec<(i64, String, i64, bool, String, String)> = {
                let mut sel = tx.prepare_cached(&format!(
                    "SELECT id, COALESCE(NULLIF(pre_title,''), stem), total_bytes,
                            EXISTS(SELECT 1 FROM files
                                   WHERE release_id=releases.id AND {EXE_FILE_SQL}),
                            stem, grp
                     FROM releases WHERE id > ?1 ORDER BY id LIMIT 10000"
                ))?;
                sel.query_map([cursor], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                })?
                .collect::<rusqlite::Result<_>>()?
            };
            if rows.is_empty() {
                tx.execute("DELETE FROM kv WHERE k=?1", [cursor_key])?;
                tx.commit()?;
                break;
            }
            {
                let mut upd = tx.prepare_cached(
                    "UPDATE releases SET kind=?2, title_key=?3, junk=?4
                     WHERE id=?1 AND (kind<>?2 OR title_key<>?3 OR junk<>?4)",
                )?;
                for (id, name, bytes, has_exe, stem, grp) in &rows {
                    let mut p = self.classify(name);
                    crate::release::recover_media_kind(&mut p, name, stem);
                    // The group-aware half of the chain, for the same
                    // reason the media-kind recovery is here: this pass
                    // WRITES kind/title_key/junk, so anything ingest
                    // applies and this does not gets UNDONE the first
                    // time a user edits a category. Without these two
                    // lines a single category edit refiled every
                    // audiobook and magazine row the group prior had
                    // rescued back to an evidence-free movie at junk 60,
                    // and nothing would have healed them again - the
                    // fingerprint is already stamped, so the next call
                    // is a no-op. Custom rows are untouched by
                    // construction: both functions return early on any
                    // kind that is not Movie, and `apply_custom` has
                    // already made a matched row Custom.
                    crate::release::recover_kind_from_group(&mut p, grp, stem);
                    if !stem_obfuscated(stem, &p) {
                        crate::release::recover_episode_from_group(&mut p, grp, name);
                    }
                    changed += upd.execute(rusqlite::params![
                        id,
                        kind_str(&p.kind),
                        p.key,
                        junk_score(name, &p, *bytes as u64, *has_exe),
                    ])? as u64;
                }
            }
            cursor = rows.last().unwrap().0;
            tx.execute(
                "INSERT INTO kv(k, v) VALUES(?1, ?2) ON CONFLICT(k) DO UPDATE SET v=?2",
                rusqlite::params![cursor_key, cursor.to_string()],
            )?;
            tx.commit()?;
        }
        Ok(changed)
    }

    /// Canonical marks identity for a server: the lowercased host.
    /// Precise on purpose - even same-backbone resellers get their own
    /// rows, because nothing guarantees two spools share numbering.
    pub fn server_key(host: &str) -> String {
        host.trim().to_ascii_lowercase()
    }

    /// One-time adoption of single-server-era marks rows (server=''):
    /// they were built against whichever server was `servers[0]`, so the
    /// caller passes that host and the rows become its. A group that
    /// already has a row for this server keeps it (the fresher of the
    /// two); its legacy row is dropped either way. Idempotent - after
    /// the first call there are no '' rows left.
    pub fn adopt_legacy_marks(&self, host: &str) -> rusqlite::Result<()> {
        let server = Self::server_key(host);
        if server.is_empty() {
            return Ok(());
        }
        self.db.execute(
            "UPDATE marks SET server=?1
              WHERE server=''
                AND grp NOT IN (SELECT grp FROM marks WHERE server=?1)",
            [&server],
        )?;
        self.db.execute("DELETE FROM marks WHERE server=''", [])?;
        Ok(())
    }

    /// Deepest article this group's history has been scanned back to on
    /// `server` (0 = never recorded). The scan loop's auto-deepen
    /// extends this downward a bounded slice per pass.
    pub fn low_water(&self, grp: &str, server: &str) -> u64 {
        self.db
            .query_row(
                "SELECT low FROM marks WHERE grp=?1 AND server=?2",
                [grp, &Self::server_key(server)],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v as u64)
            .unwrap_or(0)
    }

    pub fn set_low_water(&self, grp: &str, server: &str, low: u64) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO marks(grp, server, high, low) VALUES(?1, ?2, 0, ?3)
             ON CONFLICT(grp, server) DO UPDATE SET low=excluded.low",
            rusqlite::params![grp, Self::server_key(server), low as i64],
        )?;
        Ok(())
    }

    pub fn high_water(&self, grp: &str, server: &str) -> u64 {
        self.db
            .query_row(
                "SELECT high FROM marks WHERE grp=?1 AND server=?2",
                [grp, &Self::server_key(server)],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v as u64)
            .unwrap_or(0)
    }

    pub fn set_high_water(&self, grp: &str, server: &str, high: u64) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO marks(grp, server, high) VALUES(?1, ?2, ?3)
             ON CONFLICT(grp, server) DO UPDATE SET high=excluded.high",
            rusqlite::params![grp, Self::server_key(server), high as i64],
        )?;
        Ok(())
    }

    /// Ingest one batch of OVER entries for `grp`. Returns releases whose
    /// completeness changed to complete in this batch.
    ///
    /// Runs `ingest_pass` until nothing is left over. A pass hands back
    /// the articles it could not place because they contradict ones it
    /// had already clustered - two generations of one release inside a
    /// single OVER window - and the next pass places them against the
    /// rows the previous one just committed. So the DATABASE is the only
    /// arbiter of which generation an article belongs to; the in-memory
    /// clustering only has to notice that it cannot decide.
    ///
    /// Terminates because each pass keeps at least one article per
    /// (cluster, file, part) slot, so the leftover set is strictly
    /// smaller every time. The cap is a backstop against untrusted
    /// input, not a load-bearing bound.
    pub fn ingest(&mut self, grp: &str, entries: &[OverEntry], now: i64) -> rusqlite::Result<u32> {
        let mut completed = 0u32;
        // Arrivals the installed watch wants told about, journalled once
        // every pass has committed (see the note at the bottom of the
        // pass loop).
        let mut hits: Vec<WatchHit> = Vec::new();
        // `hits` is the per-pass carrier only: each pass announces its
        // own after ITS commit, so this is empty by the time we return.
        let outcome = self.ingest_passes(grp, entries, now, &mut completed, &mut hits);
        debug_assert!(hits.is_empty(), "a pass kept watch hits past its commit");
        // C3 prototype: retire the title keys this batch touched, so the
        // wall's fast path is live again by the time the next request
        // arrives. Deliberately AFTER the passes have committed and in
        // its own transaction - the summaries are a read accelerator,
        // and an ingest must never fail because one could not be
        // rebuilt. The budget is a belt: a batch that dirtied more keys
        // than this leaves the rest for the next call (or the daemon's
        // maintenance tick), and until they are retired the wall simply
        // answers from the exact query.
        if self.summaries {
            let _ = self.drain_title_dirty(super::summaries::DRAIN_PER_BATCH);
        }
        outcome.map(|()| completed)
    }

    /// [`Self::ingest`]'s pass loop, split out so its early exits cannot
    /// skip the watch journalling above.
    fn ingest_passes(
        &mut self,
        grp: &str,
        entries: &[OverEntry],
        now: i64,
        completed: &mut u32,
        hits: &mut Vec<WatchHit>,
    ) -> rusqlite::Result<()> {
        let mut pass = 1u32;
        let mut gp = GenPasses {
            budget: MAX_GEN_PASSES.saturating_sub(pass),
            ..Default::default()
        };
        let mut deferred = self.ingest_pass(grp, entries, now, completed, hits, &mut gp)?;
        while !deferred.is_empty() {
            pass += 1;
            gp.budget = MAX_GEN_PASSES.saturating_sub(pass);
            let batch = std::mem::take(&mut deferred);
            deferred = self.ingest_pass(grp, &batch, now, completed, hits, &mut gp)?;
        }
        // Termination is now structural rather than argued: the last
        // pass runs at budget 0, where a pass defers nothing at all, so
        // the loop cannot reach a fifth pass whatever the input.
        //
        // The pass COUNT is unchanged - four passes, four IMMEDIATE
        // transactions, same as before. What changed is what they carry:
        // on the measured teevee shape passes 2-4 each re-drove ~23,000
        // leftovers to place ~194 and drop the rest at the end, and now
        // carry ~582/388/194. Measured on that shape (194 slots x 134
        // ids, 25,996 entries), median of 5 alternating runs of the two
        // binaries: ingest 95 ms -> 55 ms, and 776 rows either way - the
        // same rows, with the same message-ids in them.
        debug_assert!(
            deferred.is_empty(),
            "a zero-budget pass deferred articles it can never place"
        );
        if gp.dropped > 0 {
            // Level and site unchanged from the overflow warning this
            // replaces: the drop is the same drop, made in the pass that
            // can already prove it rather than three passes later, and
            // the depth is the number that names the cause.
            warn!(
                target: "index",
                "{grp}: {} articles dropped - their (file, part) slot carries more \
                 contradicting articles than {MAX_GEN_PASSES} generation passes can place \
                 (deepest slot: {} articles); they re-arrive on the next scan of this window",
                gp.dropped, gp.deepest
            );
        }
        // Once per batch, not once per pass: the row half is only
        // complete when the last pass has minted, and the counters are
        // per-group totals rather than per-pass events.
        gp.depth.record(self, grp, now)?;
        Ok(())
    }

    /// The in-memory half of one ingest pass: cluster a batch of
    /// articles by (poster, stem) and file, deciding along the way which
    /// ones this pass cannot place.
    ///
    /// Split out of [`Index::ingest_pass`] verbatim for the 500-line
    /// function ceiling. It touches no database - every read it would
    /// need happens after it returns, which is also why the generation
    /// clash below defers rather than resolves.
    fn cluster_batch(entries: &[OverEntry], now: i64, gp: &mut GenPasses) -> Clustered {
        // Cluster the batch in memory first: (poster, stem) → filename →
        // (total, parts: number → (msgid, bytes)).
        let mut clusters: HashMap<(String, String), ClusterFiles> = HashMap::new();
        // Earliest article Date per cluster → the release's upload time.
        let mut posted: HashMap<(String, String), i64> = HashMap::new();
        // Pesto family (TODO 131 red-team 5a): decoded counter range +
        // earliest clock per cluster, persisted so the tiny-PAR2 rung
        // can link a sidecar backward to its payload by counter. The
        // randomized Date header is NEVER used for this.
        let mut pesto: HashMap<(String, String), (i64, i64, i64)> = HashMap::new();
        // Posting-session tag: the leading "[037/209]" file-of-session
        // marker (13 Aug 2026 census). First parsed value per cluster
        // wins - a file has exactly one position in its session.
        let mut sess: HashMap<(String, String), (i64, i64)> = HashMap::new();
        // Articles this pass refuses to place - see the note at the
        // clash test below. Empty on every ordinary batch.
        let mut deferred: Vec<OverEntry> = Vec::new();
        // Per-slot deferral ledger (see `defer_fits_budget`). Only slots
        // that actually clash get an entry, so an ordinary batch never
        // allocates one.
        let mut slot_gen = SlotGens::new();
        let mut drops = DropCensus::default();
        let files_of_session = Self::session_totals_that_count_files(entries);
        for e in entries {
            let (base, part, total, open) = split_subject_at(&e.subject)
                .unwrap_or_else(|| (e.subject.clone(), 1, 1, usize::MAX));
            // A subject whose ONLY pair is the leading session tag has
            // no per-article part counter, so it is a one-segment file -
            // BUT ONLY when the batch proves the tag counts files.
            //
            // `split_subject` takes the rightmost pair and knows nothing
            // about session tags, so `[01/15] "track01.mp3" yEnc` with no
            // trailing `(1/1)` stored part=1, total_parts=15. Fifteen
            // MP3s became fifteen files each needing fifteen parts,
            // `RelAgg::complete` could never go true, and newznab, hunt's
            // local search and the album fold's complete-members gate all
            // stopped seeing them.
            //
            // Demoting every such subject to (1,1) unconditionally would
            // be the worse bug in the other direction: a poster who
            // genuinely LEADS with the part counter would have a 50-part
            // file stored as one complete segment, which is the garbage
            // `contradicts` exists to refuse. So the demotion needs
            // evidence, and the batch carries it - see
            // `session_totals_that_count_files`.
            let total = if total > 1
                && pair_is_leading(&e.subject, open)
                && files_of_session.contains(&(e.from.as_str(), total))
            {
                1
            } else {
                total
            };
            let part = if total == 1 { 1 } else { part };
            if e.message_id.is_empty() || part == 0 || total == 0 {
                drops.unparseable += 1;
                continue;
            }
            let Some(fname) = quoted_name(&base) else {
                drops.no_filename += 1;
                continue;
            };
            let stem = release_stem(&fname);
            if stem.is_empty() {
                drops.empty_stem += 1;
                continue;
            }
            let key = (e.from.clone(), stem);
            // The in-memory half of the generation split. `clusters`
            // merges by part number, so without this test an OVER window
            // holding BOTH generations of a release - a backfill leg
            // spanning the weeks between a post and its repost does that
            // routinely - silently discards one article per colliding
            // part before the database is ever consulted.
            //
            // A message-id is globally unique, so part N of file F of
            // one posting always carries the SAME id. An incoming part N
            // whose id differs from the one already clustered is
            // therefore PROOF of a second posting, not a heuristic. A
            // disagreeing `(x/y)` total is the same proof by the same
            // argument: a file's total does not change within a posting.
            //
            // The loser is deferred rather than resolved here. Deciding
            // in memory would mean guessing which of two article sets is
            // the generation the stored row already holds, and the next
            // pass can simply ask.
            if let Some((have_total, parts)) = clusters.get(&key).and_then(|c| c.get(&fname))
                && (*have_total != total
                    || parts
                        .get(&part)
                        .is_some_and(|(id, _)| norm_msgid(id) != norm_msgid(&e.message_id)))
            {
                let slot = (key.clone(), fname.clone(), part);
                if !defer_fits_budget(&mut slot_gen, slot, &e.message_id, gp) {
                    // Provably unplaceable within the pass budget.
                    drops.gen_depth += 1;
                    continue;
                }
                deferred.push(e.clone());
                continue;
            }
            if e.date > 0 {
                // Clamp a future Date: header to the scan time. A garbled or
                // hostile far-future date would otherwise pin the release to
                // the top of the "newest" sort forever AND make it immune to
                // age-retention pruning (first_posted < cutoff never holds).
                let d = e.date.min(now);
                let p = posted.entry(key.clone()).or_insert(d);
                *p = (*p).min(d);
            }
            if let Some(pid) = crate::pesto::parse_msgid(&e.message_id) {
                let (ctr, clock) = (pid.counter as i64, pid.clock.min(i64::MAX as u64) as i64);
                pesto
                    .entry(key.clone())
                    .and_modify(|(lo, hi, ck)| {
                        *lo = (*lo).min(ctr);
                        *hi = (*hi).max(ctr);
                        *ck = (*ck).min(clock);
                    })
                    .or_insert((ctr, ctr, clock));
            }
            if let Some(t) = session_tag(&e.subject) {
                sess.entry(key.clone()).or_insert(t);
            }
            clusters
                .entry(key)
                .or_default()
                .entry(fname)
                .or_insert_with(|| (total, BTreeMap::new()))
                .1
                .insert(part, (e.message_id.clone(), e.bytes));
        }
        Clustered {
            clusters,
            posted,
            pesto,
            sess,
            deferred,
            slot_gen,
            drops,
        }
    }

    /// `(poster, m)` pairs where a leading `[n/m]` demonstrably counts
    /// FILES rather than the parts of one file.
    ///
    /// The two readings of `[01/15]` are indistinguishable in a single
    /// subject, which is why this looks at the batch. Only subjects
    /// whose ONLY pair is the leading tag are considered, because a
    /// subject with a trailing counter already has its answer.
    ///
    /// The evidence is a SESSION SHAPE, and it is deliberately narrow -
    /// the cost of a false positive is a release advertised complete
    /// with a fraction of its data, so every ambiguous batch is left
    /// alone. All three arms must hold for `(poster, m)`:
    ///
    /// 1. **No filename under more than one `n`.** One filename seen at
    ///    two positions is positive proof that `m` counts the parts of
    ///    that file - a file has exactly one position in its session.
    ///    This is the arm the first cut of this function lacked: it kept
    ///    only the FIRST `n` per filename, so a backfill window opening
    ///    mid-file (file A from part 23, file B from part 1) looked like
    ///    two files at two session positions and demoted all 100
    ///    articles onto part 1.
    /// 2. **Every `n` distinct across the filenames.** A session
    ///    position is unique, so two files claiming position 1 are not a
    ///    session.
    /// 3. **At least three filenames.** Two lone articles - `[1/50]
    ///    "A.mkv"` and `[2/50] "B.mkv"` from one poster, two unrelated
    ///    releases in one window - satisfy 1 and 2 and are still far
    ///    more likely to be two 50-part files than a two-file session.
    ///    A real album session has many tracks, so the floor costs it
    ///    nothing.
    ///
    /// A genuine leading part counter over one file is the opposite
    /// shape by construction - one filename, many `n` - so it fails arms
    /// 1 and 3 and is left exactly as it was.
    ///
    /// WHAT THIS LEAVES UN-DEMOTED, by design: a session window
    /// carrying fewer than three of the session's files, which is what
    /// a batch boundary can cut an album down to. Those subjects keep
    /// `total_parts = m` and read incomplete until a later window that
    /// does carry three or more re-clusters them - the same
    /// under-reporting the demotion exists to fix, but bounded to a
    /// window rather than a poster, and never the over-reporting (a
    /// release complete on a fiftieth of its bytes) that a false
    /// demotion produces.
    fn session_totals_that_count_files(
        entries: &[OverEntry],
    ) -> std::collections::HashSet<(&str, u32)> {
        // (poster, m) → filename → EVERY n it was seen under. The full
        // set, not the first: arm 1 above is exactly the information the
        // first-seen-only version threw away.
        let mut seen: HashMap<(&str, u32), HashMap<String, std::collections::HashSet<u32>>> =
            HashMap::new();
        for e in entries {
            let Some((base, n, m, open)) = split_subject_at(&e.subject) else {
                continue;
            };
            if m <= 1 || !pair_is_leading(&e.subject, open) {
                continue;
            }
            let Some(fname) = quoted_name(&base) else {
                continue;
            };
            seen.entry((e.from.as_str(), m))
                .or_default()
                .entry(fname)
                .or_default()
                .insert(n);
        }
        seen.into_iter()
            .filter(|(_, by_name)| {
                // Arm 1: a filename at two positions vetoes the key.
                if by_name.values().any(|ns| ns.len() > 1) {
                    return false;
                }
                // Arm 3: too few files to read as a session.
                if by_name.len() < 3 {
                    return false;
                }
                // Arm 2: one position per file. Every set is a singleton
                // by arm 1, so this is "no two files share an n".
                let mut positions = std::collections::HashSet::new();
                by_name
                    .values()
                    .all(|ns| ns.iter().all(|n| positions.insert(*n)))
            })
            .map(|(k, _)| k)
            .collect()
    }

    /// One clustering-and-write pass over `entries`. Returns the
    /// articles it deliberately did not place - see [`Index::ingest`].
    fn ingest_pass(
        &mut self,
        grp: &str,
        entries: &[OverEntry],
        now: i64,
        completed: &mut u32,
        hits: &mut Vec<WatchHit>,
        gp: &mut GenPasses,
    ) -> rusqlite::Result<Vec<OverEntry>> {
        let Clustered {
            mut clusters,
            posted,
            pesto,
            sess,
            deferred,
            slot_gen,
            drops,
        } = Self::cluster_batch(entries, now, gp);
        // Generation-depth census (stage 1 of the generation-row
        // policy, 1 Sep 2026). Instrumentation only, first pass only,
        // and off the hot loop entirely - see `GenDepthCensus`.
        gp.observe_slots(&slot_gen);
        // Pre feed: ask the relay corpus what each clustered stem was
        // really called, BEFORE the gate runs. Order matters - a gate
        // like `{"kinds":["tv"]}` reads a name, and an obfuscated stem
        // has none to read, so gating first would discard exactly the
        // posts this feature exists to rescue. Done here rather than
        // inside the loop below because the transaction borrows `db`
        // mutably and these are reads.
        let mut named: HashMap<String, (String, String)> = HashMap::new();
        if self.predb {
            for (_, stem) in clusters.keys() {
                if named.contains_key(stem) {
                    continue;
                }
                if let Some(hit) = predb::predb_lookup(&self.db, stem) {
                    named.insert(stem.clone(), hit);
                }
            }
        }
        if let Some(gate) = &self.gate {
            clusters.retain(|(_, stem), _| {
                gate(named.get(stem).map_or(stem.as_str(), |(t, _)| t.as_str()))
            });
        }

        // IMMEDIATE, not the default DEFERRED. A deferred transaction takes
        // its write lock lazily, on the first write statement, and SQLite
        // does NOT apply the busy timeout to that upgrade - it returns
        // SQLITE_BUSY immediately. The `?` then aborts the whole scan pass
        // for that group until the next interval. Every group scan opens
        // its own Index and the shared handle is replaced after each pass,
        // so there is one vulnerable ingest per group per pass, forever.
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        // Generation-split traffic this pass, for the one-line summary
        // below - the per-cluster lines are debug level (see the note in
        // `pick_release_row`).
        let mut gen_minted = 0u32;
        let mut gen_dropped = 0u32;
        for ((poster, stem), files) in clusters {
            // Real upload time when the batch carried Dates; scan time
            // otherwise. MIN on conflict lets an older batch (backfill
            // runs newest-first) walk first_posted back to the truth.
            // Clamp to now + 1 day of clock skew: the Date comes from an
            // untrusted OVER header, and a far-future date would pin the release
            // atop every Latest/Posted view for years AND dodge both retention
            // prunes (they only delete rows OLDER than a cutoff).
            let up = posted
                .get(&(poster.clone(), stem.clone()))
                .copied()
                .unwrap_or(now)
                .min(now + 86_400);
            // Which of this triple's rows this batch belongs to, and the
            // file rows that row already holds - fetched once here and
            // reused by the merge below, so the common single-candidate
            // case costs no extra queries against `files`.
            let (known, poster_key, mut existing) =
                match pick_release_row(&tx, &stem, &poster, grp, &files)? {
                    RowPick::Adopt(known, key, existing) => (known, key, existing),
                    RowPick::Mint(key) => {
                        gen_minted += 1;
                        gp.note_gen_row(&poster, &stem);
                        (None, key, ExistingFiles::new())
                    }
                    RowPick::Saturated => {
                        gen_dropped += 1;
                        continue;
                    }
                };
            // One UNIQUE-index probe per cluster, not three. The pick
            // above reached its row through that index already, so when
            // it hands the id back the widening is a rowid update and
            // the upsert's own conflict probe never runs; when it does
            // not (a free triple, or a freshly minted marked key) the
            // insert takes it, and `RETURNING` carries the id out rather
            // than the re-SELECT that used to walk the index a third
            // time. Same writes either way - the DO UPDATE branch of the
            // upsert is exactly this UPDATE.
            let rid: i64 = match known {
                Some(rid) => {
                    tx.prepare_cached(
                        "UPDATE releases SET first_posted=MIN(first_posted, ?2) WHERE id=?1",
                    )?
                    .execute(rusqlite::params![rid, up])?;
                    rid
                }
                // `stem_fold` is written here and nowhere in the DO
                // UPDATE arm on purpose: `stem` is part of the conflict
                // key, so a row that already exists already carries the
                // fold of this very stem. See index/fold.rs - the
                // common answer is '', at the cost of one `is_ascii`
                // pass and no allocation.
                None => tx
                    .prepare_cached(
                        "INSERT INTO releases(stem, poster, grp, first_seen, first_posted,
                                              stem_fold)
                         VALUES(?1, ?2, ?3, ?4, ?5, ?6)
                         ON CONFLICT(stem, poster, grp) DO UPDATE SET
                           first_posted=MIN(first_posted, excluded.first_posted)
                         RETURNING id",
                    )?
                    .query_row(
                        rusqlite::params![stem, poster_key, grp, now, up, fold::stored(&stem)],
                        |r| r.get(0),
                    )?,
            };
            // Widen the persisted pesto counter/clock range with this
            // batch's articles. Monotonic (MIN/MAX over NULL via
            // COALESCE), so batches in any order converge on the same
            // range - the property the counter-containment link needs.
            if let Some((lo, hi, ck)) = pesto.get(&(poster.clone(), stem.clone())) {
                tx.prepare_cached(
                    "UPDATE releases SET
                       pesto_ctr_min = MIN(COALESCE(pesto_ctr_min, ?2), ?2),
                       pesto_ctr_max = MAX(COALESCE(pesto_ctr_max, ?3), ?3),
                       pesto_clock   = MIN(COALESCE(pesto_clock, ?4), ?4)
                     WHERE id=?1",
                )?
                .execute(rusqlite::params![rid, lo, hi, ck])?;
            }
            if let Some((si, st)) = sess.get(&(poster.clone(), stem.clone())) {
                // First writer wins: a file has one position in its
                // posting session, and a later disagreeing tag is a
                // different posting the generation split handles.
                tx.prepare_cached(
                    "UPDATE releases SET
                       sess_idx   = COALESCE(sess_idx, ?2),
                       sess_total = COALESCE(sess_total, ?3)
                     WHERE id=?1",
                )?
                .execute(rusqlite::params![rid, si, st])?;
            }
            // Baseline for the incremental aggregates (N8), plus the
            // naming carry-forwards, in one read. pre_title/pre_source
            // come back with `was` so a re-ingest cannot un-name a
            // release the retro sweep already named: this batch's lookup
            // wins when it found something, the stored value stands
            // otherwise. Without that, every later batch touching the
            // release would blank the name, and turning the feed off
            // would erase every name it had given. The aggregate columns
            // are trusted only when both counters are known (>= 0);
            // a -1 (pre-migration row, or a maintenance rewrite that
            // could not recompute) falls back to one full scan below.
            type Baseline = (bool, String, String, Option<RelAgg>);
            let (was, mut had_title, mut had_source, base): Baseline = tx
                .prepare_cached(
                    "SELECT complete, pre_title, pre_source, files, total_bytes,
                            has_par2, have_parts, need_parts, nfiles_complete, nfiles_exe
                       FROM releases WHERE id=?1",
                )?
                .query_row([rid], |r| {
                    let (ncomplete, nexe): (i64, i64) = (r.get(8)?, r.get(9)?);
                    let agg = (ncomplete >= 0 && nexe >= 0).then_some(RelAgg {
                        nfiles: r.get(3)?,
                        tbytes: r.get(4)?,
                        ncomplete,
                        has_par2: r.get(5)?,
                        have: r.get(6)?,
                        need: r.get(7)?,
                        nexe,
                    });
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, agg))
                })?;
            let mut manifest_touched = false;
            let mut agg = base;
            for (fname, (total, parts)) in files {
                // Merge with existing segments (batches split arbitrarily).
                // Already read by `pick_release_row` against this exact
                // row, and removed as it is consumed so the merge cannot
                // read a stale copy on a later iteration.
                let prev: Option<ExistingFile> = existing.remove(&fname);
                // The D3 backstop, kept as a second trip-wire rather than
                // as the mechanism. A file's "(x/y)" total does not change
                // within one posting, so a disagreement means two
                // postings reusing a filename - which `pick_release_row`
                // has already tested for and routed away from this row,
                // making this branch unreachable on any path that goes
                // through it. It stays because the cost of being wrong is
                // asymmetric: dropping the batch loses a file until a
                // rescan, while unioning two incompatible part sets
                // satisfies `nsegs >= total_parts` from both at once and
                // hands the user a "complete" download that extracts to
                // garbage. Pinned by the D3 regression test.
                if let Some(prev) = &prev
                    && prev.total > 0
                    && total > 0
                    && prev.total != total
                {
                    let prev_total = prev.total;
                    warn!(
                        target: "index",
                        "{fname}: ignoring a batch claiming {total} parts, \
                             already tracking {prev_total} - reused filename, different posting"
                    );
                    continue;
                }
                let mut merged: BTreeMap<u32, (String, u64)> = prev
                    .as_ref()
                    .map(|p| {
                        p.segs
                            .iter()
                            .map(|(n, id, b)| (*n, (id.clone(), *b)))
                            .collect()
                    })
                    .unwrap_or_default();
                // The row's previous aggregate contribution, captured
                // BEFORE the new parts land in `merged`. The effective
                // part count follows the stored formula: `nsegs` when
                // stamped, the parsed length for a pre-migration row
                // still carrying 0.
                let old_contrib = prev.as_ref().map(|p| {
                    let eff = if p.nsegs > 0 {
                        p.nsegs
                    } else {
                        merged.len() as i64
                    };
                    (eff, p.total, p.bytes)
                });
                merge_parts(&mut merged, parts);
                let bytes: u64 = merged.values().map(|v| v.1).sum();
                let seg_blob = segcodec::encode(
                    &merged
                        .iter()
                        .map(|(n, (id, b))| (*n, id.clone(), *b))
                        .collect::<Vec<_>>(),
                );
                tx.prepare_cached(
                    "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(release_id, filename) DO UPDATE SET
                       total_parts=excluded.total_parts, bytes=excluded.bytes,
                       segments=excluded.segments, nsegs=excluded.nsegs",
                )?
                .execute(rusqlite::params![
                    rid,
                    fname,
                    total,
                    bytes as i64,
                    seg_blob,
                    merged.len() as i64
                ])?;
                manifest_touched = true;
                // §131 identity substrate: key this file's lowest-part
                // message-ids for the reverse lookup (BTreeMap iterates
                // in part order). Append-only and idempotent, so a
                // batch that later reveals lower parts just adds keys.
                claims::msgid_map_insert(&tx, rid, merged.values().map(|(id, _)| id.as_str()))?;
                // Fold this write into the running aggregates (N8) -
                // exactly the values the UPSERT stored, so the result
                // matches what a full scan would say.
                if let Some(a) = agg.as_mut() {
                    a.apply_file(
                        &fname,
                        old_contrib,
                        merged.len() as i64,
                        total,
                        bytes as i64,
                    );
                }
            }
            // Release aggregates: carried incrementally through the
            // merge above when the stored counters were valid; one full
            // scan of the release's file rows otherwise, which heals the
            // row (the UPDATE below stamps the counters) so it pays this
            // scan once, not per chunk. A release is complete when every
            // file we've seen has all its parts - single-file posts are
            // legitimate (see `RelAgg::complete`; the old `nfiles >= 2`
            // rule froze 55% of a live teevee+moovee index).
            let agg = match agg {
                Some(a) => a,
                None => RelAgg::recompute(&tx, rid)?,
            };
            let complete = agg.complete();
            // kind/res parse once per touched cluster - cheap (pure text)
            // and idempotent, so re-ingest keeps them current. Runs
            // through the installed custom categories (24D) so a user
            // kind survives re-ingest touches. (Field access, not
            // self.classify - `tx` holds the &mut borrow of self.db.)
            //
            // Parsed from the FED name when there is one. That single
            // substitution is what turns a pre hit into a real result:
            // title_key lands the release on the right wall card, and
            // kind/res/codecs/junk all come out of a name that actually
            // says something instead of a random stem.
            // File-table triggers revoke exact external-NZB claims whenever
            // this batch changes a manifest. Do not restore the pre-trigger
            // snapshot in the aggregate UPDATE at the end of ingest.
            if manifest_touched && super::seed::is_external_nzb_pre_source(&had_source) {
                had_title.clear();
                had_source.clear();
            }
            let (pre_title, pre_source) =
                named.get(&stem).cloned().unwrap_or((had_title, had_source));
            let name = if pre_title.is_empty() {
                stem.as_str()
            } else {
                pre_title.as_str()
            };
            let mut p = crate::categories::classify(name, &self.custom);
            // The fed name is the better identity but it names the WORK:
            // a spot title drops the `.epub`/`.pdf` the stem carries, and
            // that marker is a book's only evidence.
            crate::release::recover_media_kind(&mut p, name, stem.as_str());
            // And when the name proves nothing either way, the group
            // it was posted to does: an audiobook folder in an
            // audiobook group is a book, not an evidence-free movie.
            crate::release::recover_kind_from_group(&mut p, grp, stem.as_str());
            // ...and in a group that vouches for VIDEO, the same
            // evidence reads the episode number out of a name that
            // carries one: "Bleach - 187 - Ichigo Rages!" is episode
            // 187, not a movie called the whole line.
            //
            // Asked only of a stem `stem_obfuscated` does not already
            // damn, and asked HERE because that answer has to be taken
            // BEFORE the pass runs: its second arm is guarded on
            // `p.season.is_none()`, so the season this rule records
            // would make the blob test more lenient than it was, and a
            // repost bot's "<blob> - 04 - <blob>" would buy its way out
            // of the very rule that hides it.
            if !stem_obfuscated(stem.as_str(), &p) {
                crate::release::recover_episode_from_group(&mut p, grp, name);
            }
            tx.prepare_cached(
                "UPDATE releases SET files=?2, total_bytes=?3, has_par2=?4, complete=?5,
                        kind=?6, res=?7, have_parts=?8, need_parts=?9,
                        title_key=?10, junk=?11, langs=?12,
                        vcodec=?13, acodec=?14, hdr=?15,
                        pre_title=?16, pre_source=?17, pre_at=?18,
                        nfiles_complete=?19, nfiles_exe=?20
                 WHERE id=?1",
            )?
            .execute(rusqlite::params![
                rid,
                agg.nfiles,
                agg.tbytes,
                agg.has_par2,
                complete,
                kind_str(&p.kind),
                p.res.as_deref().unwrap_or_default(),
                agg.have,
                agg.need,
                p.key,
                junk_score(name, &p, agg.tbytes.max(0) as u64, agg.nexe > 0),
                p.langs.join(" "),
                p.vcodec.as_deref().unwrap_or_default(),
                p.acodec.as_deref().unwrap_or_default(),
                p.hdr.as_deref().unwrap_or_default(),
                pre_title,
                pre_source,
                // Stamped whether or not the feed knew this one, so
                // the backlog sweep does not re-examine rows the
                // live path has already asked about.
                now,
                agg.ncomplete,
                agg.nexe
            ])?;
            if complete && !was {
                *completed += 1;
            }
            // Offer the release to the arrival watch. The predicate is
            // read as a FIELD, not through `self.note_watch`: `tx` holds
            // the &mut borrow of `self.db`, and a method taking `&self`
            // would borrow the whole struct. The hits themselves are
            // journalled after the commit, so a batch that fails to
            // commit announces nothing.
            if let Some(watch) = &self.watch
                && watch(name)
            {
                hits.push(WatchHit {
                    id: rid,
                    name: name.to_string(),
                    complete,
                });
            }
        }
        tx.commit()?;
        // Journalled only NOW, and only for the pass that committed: a
        // pass whose transaction rolled back has no rows to announce and
        // its ids may name nothing at all, so announcing them told a
        // watch about arrivals that do not exist (Fable sweep 15 Aug).
        // A later pass erroring still leaves THIS pass's hits announced,
        // which is the property 9bf3022e added them for.
        for h in std::mem::take(hits) {
            self.push_watch_hit(h);
        }
        if gen_minted > 0 || gen_dropped > 0 {
            warn!(
                target: "index",
                "{grp}: {gen_minted} reposted posting(s) indexed as generation rows, \
                 {gen_dropped} dropped at the {MAX_GEN_SIBLINGS}-sibling cap",
            );
        }
        drops.record(self)?;
        gp.dropped += drops.gen_depth;
        Ok(deferred)
    }

    // ---- the pre feed -------------------------------------------------
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::{dated_entry, entry, teardown};

    #[test]
    fn split_subject_conventions() {
        // Canonical (n/m).
        assert_eq!(
            split_subject(r#"x - "f.rar" yEnc (5/50)"#),
            Some((r#"x - "f.rar" yEnc"#.to_string(), 5, 50))
        );
        // Trailing parenthesized tag must not shadow the counter.
        assert_eq!(
            split_subject(r#"x - "f.rar" yEnc (5/50) (German)"#).map(|(_, n, m)| (n, m)),
            Some((5, 50))
        );
        assert_eq!(
            split_subject(r#"x - "f.rar" yEnc (5/50) (4.2 GB)"#).map(|(_, n, m)| (n, m)),
            Some((5, 50))
        );
        // Bracketed and "of" counters.
        assert_eq!(
            split_subject("Release.part01.rar yEnc [1/50]").map(|(_, n, m)| (n, m)),
            Some((1, 50))
        );
        assert_eq!(
            split_subject(r#"x - "f.rar" yEnc (1 of 50)"#).map(|(_, n, m)| (n, m)),
            Some((1, 50))
        );
        // No counter at all.
        assert_eq!(split_subject("just a subject (German)"), None);
    }

    /// A LEADING pair is told from a trailing one by POSITION, never by
    /// value: `[1/3] "x.mkv" yEnc (1/3)` carries the same numbers twice,
    /// so a value test reads the trailing part counter as the session
    /// tag and demotes a real three-part file to one segment.
    #[test]
    fn a_leading_pair_is_identified_by_position_not_by_value() {
        let at = |s: &str| split_subject_at(s).map(|(_, n, m, open)| (n, m, open));
        // The rightmost pair is taken, and it is NOT the leading one.
        let (n, m, open) = at(r#"[1/3] "x.mkv" yEnc (1/3)"#).unwrap();
        assert_eq!((n, m), (1, 3));
        assert!(
            !pair_is_leading(r#"[1/3] "x.mkv" yEnc (1/3)"#, open),
            "the trailing counter was read as the session tag"
        );
        // With no trailing counter, the leading tag IS what was taken.
        let (_, _, open) = at(r#"[01/15] "track01.mp3" yEnc"#).unwrap();
        assert!(pair_is_leading(r#"[01/15] "track01.mp3" yEnc"#, open));
        // Leading whitespace does not move the answer.
        let s = r#"   [01/15] "track01.mp3" yEnc"#;
        let (_, _, open) = at(s).unwrap();
        assert!(pair_is_leading(s, open));
    }

    /// `[NN/MM] "file.ext" yEnc` with no per-article counter: MM counts
    /// the session's FILES, so each file is a one-segment file.
    ///
    /// Fifteen tracks used to store `total_parts = 15` apiece, so every
    /// one of them needed fifteen parts it would never get:
    /// `RelAgg::complete` could not go true, and newznab, hunt's local
    /// search and the album fold all stopped seeing the post.
    #[test]
    fn a_leading_file_of_session_tag_is_not_the_part_count() {
        let subjects: Vec<String> = (1..=15)
            .map(|i| format!(r#"[{i:02}/15] "track{i:02}.mp3" yEnc"#))
            .collect();
        let entries: Vec<OverEntry> = subjects
            .iter()
            .enumerate()
            .map(|(i, s)| entry(s, "poster@h.tld", &format!("m{i}"), 1000))
            .collect();
        let files = Index::session_totals_that_count_files(&entries);
        assert!(
            files.contains(&(entries[0].from.as_str(), 15)),
            "fifteen distinct filenames under one poster did not prove 15 counts files"
        );
    }

    /// THE CONTROL ARM, and the reason the demotion needs evidence at
    /// all: a poster who genuinely LEADS with the part counter has ONE
    /// filename under many n, which is the opposite shape. Demoting it
    /// would store a 50-part file as one complete segment - the garbage
    /// `contradicts` exists to refuse.
    #[test]
    fn a_leading_part_counter_over_one_file_is_left_alone() {
        let subjects: Vec<String> = (1..=50)
            .map(|i| format!(r#"[{i}/50] "movie.mkv" yEnc"#))
            .collect();
        let entries: Vec<OverEntry> = subjects
            .iter()
            .enumerate()
            .map(|(i, s)| entry(s, "poster@h.tld", &format!("m{i}"), 1000))
            .collect();
        let files = Index::session_totals_that_count_files(&entries);
        assert!(
            files.is_empty(),
            "one filename under fifty part numbers was read as a file count"
        );
    }

    /// TWO UNRELATED RELEASES, ONE POSTER, ONE WINDOW - the shape that
    /// made the first cut of the demotion advertise a release complete
    /// on a fiftieth of its bytes.
    ///
    /// `[1/50] "Alpha.Movie.mkv"` and `[2/50] "Bravo.Movie.mkv"` are two
    /// distinct filenames under one poster at two different `n`, which
    /// is everything the first version tested for. Both demoted to
    /// (1, 1), landed in two releases (different stems), and each read
    /// COMPLETE holding one article. Two files is not a session: the
    /// three-filename floor is what refuses it.
    #[test]
    fn two_lone_articles_under_one_poster_are_not_a_session() {
        let entries = vec![
            entry(r#"[1/50] "Alpha.Movie.mkv" yEnc"#, "p@x", "a1", 1000),
            entry(r#"[2/50] "Bravo.Movie.mkv" yEnc"#, "p@x", "b1", 1000),
        ];
        assert!(
            Index::session_totals_that_count_files(&entries).is_empty(),
            "two unrelated 50-part files were read as a two-file session"
        );

        // And the same shape through the real ingest path, so the
        // verdict under test is `RelAgg::complete` and not the helper's
        // set: neither release may claim to be complete.
        let dir = std::env::temp_dir().join(format!("nzbfast-sessdemote-a-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        ix.ingest("alt.test", &entries, 1000).unwrap();
        let hits = ix.search("", 10).unwrap();
        assert_eq!(hits.len(), 2, "expected two releases, one per stem");
        for r in &hits {
            assert!(
                !r.complete,
                "{} read complete holding {} of {} parts",
                r.stem, r.have_parts, r.need_parts
            );
            assert_eq!((r.have_parts, r.need_parts), (1, 50), "{}", r.stem);
        }
        teardown(&dir, ix);
    }

    /// ARM 1, THE VETO: one filename under two `n` is positive proof
    /// that `m` counts the parts of that file, and it holds even when
    /// other filenames sit beside it in the batch.
    ///
    /// The first cut kept only the FIRST `n` per filename, so this batch
    /// looked like {movie: 1, sample: 3} - two names, differing n - and
    /// demoted all three articles onto part 1 of two one-segment files.
    #[test]
    fn one_filename_at_two_positions_vetoes_the_whole_key() {
        let entries = vec![
            entry(r#"[1/50] "Big.Movie.mkv" yEnc"#, "p@x", "a1", 1000),
            entry(r#"[2/50] "Big.Movie.mkv" yEnc"#, "p@x", "a2", 1000),
            entry(r#"[3/50] "Big.Sample.mkv" yEnc"#, "p@x", "s1", 1000),
        ];
        assert!(
            Index::session_totals_that_count_files(&entries).is_empty(),
            "a filename seen at two session positions did not veto the key"
        );
    }

    /// THE BACKFILL WINDOW, and the worst of the three: an OVER window
    /// that opens mid-file. File A is caught from part 23, file B from
    /// part 1, all under `[n/50]` with no trailing counter.
    ///
    /// First-seen-only saw {A: 23, B: 1} - two names, differing n - and
    /// demoted all 78 articles to (1, 1), collapsing 28 of A's parts and
    /// 50 of B's onto part 1 of a one-segment file apiece. Arm 1 vetoes
    /// on A alone. Left un-demoted, the truth survives: A holds 28 of
    /// its 50 parts and is incomplete, B holds all 50 and is not.
    #[test]
    fn a_window_opening_mid_file_does_not_demote_the_poster() {
        let mut entries: Vec<OverEntry> = (23..=50)
            .map(|n| {
                entry(
                    &format!(r#"[{n}/50] "Alpha.Movie.mkv" yEnc"#),
                    "p@x",
                    &format!("a{n}"),
                    1000,
                )
            })
            .collect();
        entries.extend((1..=50).map(|n| {
            entry(
                &format!(r#"[{n}/50] "Bravo.Movie.mkv" yEnc"#),
                "p@x",
                &format!("b{n}"),
                1000,
            )
        }));
        assert!(
            Index::session_totals_that_count_files(&entries).is_empty(),
            "a window opening mid-file was read as a two-file session"
        );

        let dir = std::env::temp_dir().join(format!("nzbfast-sessdemote-d-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        ix.ingest("alt.test", &entries, 1000).unwrap();
        let hits = ix.search("", 10).unwrap();
        assert_eq!(hits.len(), 2, "expected two releases, one per stem");
        let a = hits.iter().find(|r| r.stem.contains("Alpha")).unwrap();
        let b = hits.iter().find(|r| r.stem.contains("Bravo")).unwrap();
        assert_eq!((a.have_parts, a.need_parts), (28, 50));
        assert!(!a.complete, "a partly-caught 50-part file read complete");
        assert_eq!((b.have_parts, b.need_parts), (50, 50));
        assert!(b.complete, "a fully-caught 50-part file read incomplete");
        teardown(&dir, ix);
    }

    /// THE FLOOR IS EXACTLY THREE, and a session position is unique.
    /// Three tracks at three positions demote; the same three with two
    /// of them claiming position 1 are not a session and do not.
    #[test]
    fn three_files_at_distinct_positions_is_the_smallest_session() {
        let three: Vec<OverEntry> = [1, 2, 3]
            .iter()
            .map(|n| {
                entry(
                    &format!(r#"[{n}/12] "track{n:02}.mp3" yEnc"#),
                    "p@x",
                    &format!("t{n}"),
                    1000,
                )
            })
            .collect();
        assert!(
            Index::session_totals_that_count_files(&three).contains(&("p@x", 12)),
            "three tracks at three positions were not read as a session"
        );

        let collided: Vec<OverEntry> = [1, 1, 2]
            .iter()
            .enumerate()
            .map(|(i, n)| {
                entry(
                    &format!(r#"[{n}/12] "track{i:02}.mp3" yEnc"#),
                    "p@x",
                    &format!("c{i}"),
                    1000,
                )
            })
            .collect();
        assert!(
            Index::session_totals_that_count_files(&collided).is_empty(),
            "two files sharing session position 1 were read as a session"
        );
    }

    #[test]
    fn quoted_name_conventions() {
        // Quoted, with a decoy quoted run first.
        assert_eq!(
            quoted_name(r#""S01E01" - "Show.part01.rar" yEnc"#),
            Some("Show.part01.rar".to_string())
        );
        // Unquoted convention.
        assert_eq!(
            quoted_name("Release.Name.part01.rar yEnc"),
            Some("Release.Name.part01.rar".to_string())
        );
        assert_eq!(
            quoted_name("Backup.7z.001 yEnc"),
            Some("Backup.7z.001".to_string())
        );
        // Size fragments and version dots are not filenames.
        assert_eq!(quoted_name("Big Release 4.2GB yEnc"), None);
        assert_eq!(quoted_name("Release v1.0 done"), None);
        // T5: this reader calls `nzb::quoted_filename` DIRECTLY, not
        // `NzbFile::filename_hint`, so it inherits the agreeing-run pick
        // only because the rule lives at the pick. A header on the
        // N6-04 ambiguity class - two dotted quoted runs whose kinds
        // disagree, so the subject is `Data` - used to index the row
        // under the recovery-volume name, which is what release
        // grouping and the junk scorer then read. It indexes under the
        // payload name now, and this row is what would go red if the
        // rule were ever moved up to `filename_hint` and forked in two.
        assert_eq!(
            quoted_name(r#""label.vol000+50.par2" - "Movie.mkv" yEnc"#),
            Some("Movie.mkv".to_string())
        );
    }

    #[test]
    fn junk_v6_evidence_free_media_and_lecture_dumps() {
        let score = |stem: &str, bytes: u64| {
            let p = crate::release::parse_release(stem);
            junk_score(stem, &p, bytes, false)
        };
        // Course/lecture dumps (real leaks from a live teevee+moovee
        // index): numbered tracks and bare-words media files.
        assert!(score("003 - Estômago.mp4", 100 << 20) >= 50);
        assert!(score("056 - Ortografia II.mp4", 200 << 20) >= 50);
        assert!(score("aula.mp4", 700 << 20) >= 50);
        assert!(score("Configurando Dsers.mp4", 80 << 20) >= 50);
        assert!(score("misfits-wegedeutschensd", 100 << 20) >= 50);
        // Track prefix wins even when a year parses further in.
        assert!(score("065 - Estatística RLM 2019.mp4", 400 << 20) >= 50);
        // Bracket-hex repost spam - inner name parses real, still junk.
        assert!(
            score(
                "[3b9550c02c]_[newzNZB]_atlanta.s01e10.1080p.hdtv.x264-xpert",
                50 << 20
            ) >= 50
        );
        // Anime subgroup brackets are words, not hex - clean.
        assert!(score("[SubsPlease] Frieren - S01E01 (1080p) [ABCD1234]", 1 << 30) < 50);
        // Real releases with any single marker survive.
        assert!(score("Some.Documentary.2020.mp4", 2 << 30) < 50);
        assert!(
            score(
                "slings.and.arrows.s01e03.proper.dvdrip.xvid-nodlabs",
                300 << 20
            ) < 50
        );
        assert!(
            score(
                "Robin.Hood.2010.Theatrical.Cut.BluRay.1080p.DTS-X.7.1.AVC.HYBRID.REMUX-FraMeSToR.mkv",
                33 << 30
            ) < 50
        );
        // "24.S01E01" style: leading digits but a parsed episode - clean.
        assert!(score("24.S01E01.1080p.WEB.h264-GRP", 2 << 30) < 50);
        // Evidence-free software-ish name is hidden by the same rule.
        assert!(score("Topaz Video AI Pro 8.1.6", 500 << 20) >= 50);
        // Sub-200 MB "HD movie" posts are fakes; a real small movie
        // without an HD claim (old SD rip) survives, and TV stays
        // exempt (short-form episodes are legitimately tiny).
        assert!(score("Dont.Breathe.2016.1080p.WEB-DL.DD5.1.H264-FGT", 180 << 20) >= 50);
        assert!(score("Old.Short.Film.1962.DVDRip.XviD-GRP", 180 << 20) < 50);
        assert!(score("some.show.s01e04.720p.hdtv.x264-grp", 150 << 20) < 50);
    }

    #[test]
    fn dropped_articles_are_counted_not_silent() {
        // Commissioning memo rec 3: an article whose subject carries no
        // filename (the ngPost --obfuscate shape - the subject is a
        // bare token, no quotes, no name.ext) used to vanish without a
        // trace. The drop still happens; the COUNT no longer hides.
        let dir = std::env::temp_dir().join(format!("nzbfast-index-drop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.test",
            &[
                entry("aGVsbG8gb2JmdXNjYXRlZA (1/50)", "a@a", "d1", 700_000),
                entry("bm8gbmFtZSBoZXJlIGVpdGhlcg (2/50)", "b@b", "d2", 700_000),
                entry(
                    "\"Kept.Release.2026.1080p-GRP.mkv\" yEnc (1/1)",
                    "c@c",
                    "d3",
                    4 << 30,
                ),
            ],
            1_000,
        )
        .unwrap();
        let rows: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            rows, 1,
            "the named article placed, the obfuscated two did not"
        );
        assert_eq!(
            ix.kv_get("ingest_drop_no_filename").as_deref(),
            Some("2"),
            "both no-filename drops counted"
        );
        assert!(
            ix.kv_get("ingest_drop_unparseable").is_none(),
            "no unparseable drops on this batch"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_drop_census_reads_back_as_two_families_over_a_known_window() {
        // The counters existed for a day before anything read one. This
        // is the read side: the three outright drops in one family, the
        // pass-budget surplus in another (those articles come back on
        // the next scan of the window, so summing the two would be a
        // category error), and a window that says when counting began.
        let dir = std::env::temp_dir().join(format!("nzbfast-index-census-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.test",
            &[
                entry("aGVsbG8gb2JmdXNjYXRlZA (1/50)", "a@a", "d1", 700_000),
                entry("bm8gbmFtZSBoZXJlIGVpdGhlcg (2/50)", "b@b", "d2", 700_000),
                entry(
                    "\"Kept.Release.2026.1080p-GRP.mkv\" yEnc (1/1)",
                    "c@c",
                    "d3",
                    4 << 30,
                ),
            ],
            1_000,
        )
        .unwrap();
        let c = ix.ingest_drop_census().unwrap();
        assert_eq!(c["dropped"]["no_filename"], 2, "both no-filename drops");
        assert_eq!(
            c["dropped"]["empty_stem"], 0,
            "a counter that never fired reads as a zero, not as a missing field"
        );
        assert_eq!(c["dropped"]["unparseable"], 0);
        assert_eq!(c["dropped_total"], 2);
        assert_eq!(
            c["over_budget"]["gen_depth"], 0,
            "the surplus family is reported separately and is not in the total"
        );
        assert_eq!(c["unclassified"], serde_json::json!({}));
        assert_eq!(
            c["window_known"], true,
            "this index started counting on its first batch"
        );
        assert!(
            c["since"].as_i64().unwrap_or(0) > 1_700_000_000,
            "the window opens at a real clock, not zero: {}",
            c["since"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_census_that_was_already_counting_reports_an_unknown_window() {
        // An index that has been scanning for weeks carries millions of
        // drops counted before the window stamp existed (the measured
        // case was 5.8M). Stamping one NOW would date them to this
        // afternoon, so the stamp declines and the readout says so - an
        // unknown window is the honest answer, not a defect.
        //
        // The two decoy keys are the other half: an `ingest_drop_*` name
        // this build does not know must be REPORTED rather than dropped
        // (that is how the next counter avoids being invisible for a day
        // like these four were), and `_` being a LIKE wildcard, a key
        // that only matches with the wildcards live must not be scanned
        // at all.
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-census2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        ix.kv_set("ingest_drop_no_filename", "5000000").unwrap();
        ix.kv_set("ingest_drop_future_thing", "7").unwrap();
        ix.kv_set("ingestXdropY_bogus", "9").unwrap();
        ix.ingest(
            "alt.binaries.test",
            &[entry("aGVsbG8gb2JmdXNjYXRlZA (1/50)", "a@a", "d1", 700_000)],
            1_000,
        )
        .unwrap();
        assert!(
            ix.kv_get(super::DROP_SINCE_KEY).is_none(),
            "an index that was already counting is never stamped retroactively"
        );
        let c = ix.ingest_drop_census().unwrap();
        assert_eq!(c["window_known"], false);
        assert_eq!(c["since"], serde_json::Value::Null);
        assert_eq!(
            c["dropped"]["no_filename"], 5_000_001,
            "the batch adds to what was there"
        );
        assert_eq!(
            c["unclassified"]["ingest_drop_future_thing"], "7",
            "a counter this build does not know is reported under its own key, meaning unclaimed"
        );
        assert!(
            c["unclassified"].get("ingestXdropY_bogus").is_none(),
            "the `_` in the prefix is escaped, so the scan is a prefix and not a pattern"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn executable_content_junks_media_releases() {
        // M32 (Prowlarr#2329): an .exe inside a movie/TV-shaped release is
        // flagged past the default-hide line; Software releases keep their
        // normal score (executables are their content).
        let dir = std::env::temp_dir().join(format!("nzbfast-index-exe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                mk("Some.Movie.2026.1080p.BluRay.x264-GRP.exe", "a@a", "x1"),
                mk("Clean.Movie.2026.1080p.BluRay.x264-GRP.mkv", "b@b", "x2"),
            ],
            1_000,
        )
        .unwrap();
        // Both rows exist, but the junk ceiling hides the exe-carrying one.
        let (_, total_all) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(total_all, 2);
        let (rows, total) = ix
            .browse(&BrowseQuery {
                max_junk: Some(50),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 1, "exe-carrying movie must be junk-hidden: {rows:?}");
        assert!(rows[0].stem.contains("Clean.Movie"), "{rows:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sample_token_only_junks_sample_sized_posts() {
        // M32: a full-size release with "sample"
        // in its TITLE is not furniture; a tens-of-MB one is.
        let dir = std::env::temp_dir().join(format!("nzbfast-index-smp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.test",
            &[
                entry(
                    "\"The.Free.Sample.2026.1080p.BluRay.x264-GRP.mkv\" yEnc (1/1)",
                    "a@a",
                    "s1",
                    4 << 30,
                ),
                entry(
                    "\"Other.Movie.2026.1080p-GRP.sample.mkv\" yEnc (1/1)",
                    "b@b",
                    "s2",
                    60 << 20,
                ),
            ],
            1_000,
        )
        .unwrap();
        let (rows, total) = ix
            .browse(&BrowseQuery {
                max_junk: Some(50),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 1, "only the real sample is hidden: {rows:?}");
        assert!(rows[0].stem.contains("Free.Sample"), "{rows:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The arrivals counter lives in `kv`, and three separate code paths
    /// do `DELETE FROM kv WHERE k=...`. If that row ever went missing the
    /// trigger's `SELECT v FROM kv` yielded NULL, the `UPDATE releases
    /// SET arrival_seq=NULL` hit the NOT NULL constraint, and the whole
    /// ingest transaction rolled back - one mistyped key away from an
    /// index that can never be written to again. The fallback makes the
    /// worst case a duplicate cursor value, not a dead database.
    #[test]
    fn arrival_seq_trigger_survives_a_missing_counter_row() {
        let dir = std::env::temp_dir().join(format!("nzbfast-arrseq-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        ix.ingest(
            "alt.test",
            &[dated_entry(
                "\"Before.Wipe.S01E01.mkv\" yEnc (1/1)",
                "b1",
                91_000,
            )],
            100_000,
        )
        .unwrap();

        // Somebody's kv cleanup took the counter with it.
        ix.db
            .execute("DELETE FROM kv WHERE k='wall_arrival_seq'", [])
            .unwrap();

        ix.ingest(
            "alt.test",
            &[dated_entry(
                "\"After.Wipe.S02E02.mkv\" yEnc (1/1)",
                "a1",
                95_000,
            )],
            101_000,
        )
        .expect("a missing kv row must not take the ingest transaction down with it");

        // The release really landed, and it carries a usable cursor
        // value rather than the 0 that means "not yet claimed".
        let (n, seq): (i64, i64) = ix
            .db
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(arrival_seq), 0) FROM releases",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(n, 2, "both releases are in the table");
        assert!(
            seq > 0,
            "the fallback gave the new row a real cursor, got {seq}"
        );

        // An index that predates this fix carries the old trigger, so the
        // upgrade has to replace it - a database still running the
        // original definition is still fail-dead.
        let old: i64 = ix
            .db
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type='trigger' AND name='rel_arrival_seq_ai'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(old, 0, "the pre-fix trigger must be dropped on open");

        // And the counter heals itself on the next open, so the id
        // fallback stays a one-insert stopgap rather than the new normal.
        drop(ix);
        let ix = Index::open(&dir.join("index.db")).unwrap();
        let restored: i64 = ix
            .db
            .query_row(
                "SELECT CAST(v AS INTEGER) FROM kv WHERE k='wall_arrival_seq'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            restored, seq,
            "re-open restored the counter from MAX(arrival_seq)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ingest_cluster_search_synthesize() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        // Two batches split mid-file: merging must complete the release.
        let b1 = vec![
            entry("\"Show.S01E01.part1.rar\" yEnc (1/2)", "p@x", "a1", 1000),
            entry("\"Show.S01E01.part2.rar\" yEnc (1/1)", "p@x", "b1", 900),
            entry("\"Show.S01E01.par2\" yEnc (1/1)", "p@x", "c1", 100),
        ];
        let b2 = vec![entry(
            "\"Show.S01E01.part1.rar\" yEnc (2/2)",
            "p@x",
            "a2",
            1000,
        )];
        assert_eq!(ix.ingest("alt.test", &b1, 1000).unwrap(), 0); // part1 incomplete
        assert_eq!(ix.ingest("alt.test", &b2, 1001).unwrap(), 1); // now complete

        // Separator-insensitive, multi-term AND search: a dotted stem
        // must match a space-separated *arr query (and vice-versa).
        assert_eq!(ix.search("show.s01e01", 10).unwrap().len(), 1);
        assert_eq!(ix.search("show s01e01", 10).unwrap().len(), 1);
        assert_eq!(ix.search("SHOW", 10).unwrap().len(), 1);
        assert_eq!(ix.search("s01e01 show", 10).unwrap().len(), 1); // order-free
        assert_eq!(ix.search("show s09e09", 10).unwrap().len(), 0); // term absent
        assert_eq!(ix.search("", 10).unwrap().len(), 1); // empty = all

        let hits = ix.search("show.s01e01", 10).unwrap();
        assert_eq!(hits.len(), 1);
        let r = &hits[0];
        assert!(r.complete && r.has_par2);
        assert_eq!(r.files, 3);
        assert_eq!(r.total_bytes, 3000);

        // NZB synthesis parses and carries every segment.
        let nzb = ix.make_nzb(r.id).unwrap();
        let parsed = crate::nzb::Nzb::parse(nzb.as_bytes()).unwrap();
        assert_eq!(parsed.files.len(), 3);
        assert_eq!(
            parsed.files.iter().map(|f| f.segments.len()).sum::<usize>(),
            4
        );

        // High-water marks persist, independently per server (A8:
        // article numbers are per-server, message-ids are not).
        ix.set_high_water("alt.test", "News.EXAMPLE.com", 42)
            .unwrap();
        assert_eq!(ix.high_water("alt.test", "news.example.com"), 42);
        assert_eq!(ix.high_water("alt.test", "other.example.com"), 0);
        assert_eq!(ix.stats().unwrap(), (1, 1));
        teardown(&dir, ix);
    }
}

#[cfg(test)]
mod obfuscated_posts_are_unindexable {
    /// Why a header-scanning index cannot see a fully obfuscated release,
    /// however many groups it scans.
    ///
    /// Traced from a real one: Supergirl.2026.2160p, which downloaded
    /// perfectly and which DOGnzb lists, but which does not appear in our
    /// index. Every theory about coverage was wrong - the article range WAS
    /// scanned (1,933 neighbours from the same hour are stored), the
    /// neighbours ARE obfuscated so obfuscation alone is not disqualifying,
    /// and servers[0] DOES carry the articles.
    ///
    /// The nzb lies. Its <groups>, subject= and poster= are all indexer
    /// metadata, not what is on the wire. Fetched live from the provider,
    /// the same message-id carries:
    ///
    ///   Newsgroups: alt.binaries.encrypted   (nzb said alt.binaries.teevee)
    ///   Subject:    ZvbiaQJJpLvLZpY          (nzb said "30fb7ada….10" yEnc (1/260))
    ///   From:       wQXbPchc1NPZZqPmbWr5 …   (nzb said e24e6f0f… )
    ///
    /// So it is in a group nobody would index for TV, under a subject with
    /// no filename, no part marker and no relationship to the release. The
    /// indexers that list it are not scanning headers - they hold a
    /// message-id mapping from the uploader.
    #[test]
    fn a_real_obfuscated_subject_carries_nothing_to_index_on() {
        // What the nzb claims: parses fine, which is why this looked
        // indexable right up until the article itself was read.
        let claimed = "\"30fb7ada0c0b15e12135927afe355933.10\" yEnc (1/260)";
        let (base, part, total) =
            super::split_subject(claimed).unwrap_or_else(|| (claimed.to_string(), 1, 1));
        assert!(part != 0 && total != 0);
        assert!(
            super::quoted_name(&base).is_some(),
            "the nzb's version is parseable"
        );

        // What is actually on the wire. ingest() requires a quoted filename
        // and skips the entry without one, so this can never become a row -
        // no filename, no part marker, nothing to key a release on.
        let real = "ZvbiaQJJpLvLZpY";
        let (rbase, _, _) = super::split_subject(real).unwrap_or_else(|| (real.to_string(), 1, 1));
        assert!(
            super::quoted_name(&rbase).is_none(),
            "the real subject has no quoted filename, so ingest skips it"
        );
    }
}

#[cfg(test)]
mod multi_server_indexing {
    use crate::index::testutil::teardown;
    use crate::index::{BrowseQuery, Index};
    use crate::nntp::OverEntry;

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

    /// A8: a single-server-era marks table (PRIMARY KEY on grp alone)
    /// migrates to the (grp, server) shape with its coverage intact, and
    /// adopt_legacy_marks hands the '' rows to the historical primary
    /// without ever clobbering a row that server has since written.
    #[test]
    fn marks_migrate_to_per_server_and_adoption_never_clobbers() {
        let dir = std::env::temp_dir().join(format!("nzbfast-marksmig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("index.db");
        {
            // Build the old shape by hand, exactly as v1.0.10 left it.
            let db = rusqlite::Connection::open(&db_path).unwrap();
            db.execute_batch(
                "CREATE TABLE marks(grp TEXT PRIMARY KEY, high INTEGER NOT NULL);
                 ALTER TABLE marks ADD COLUMN low INTEGER NOT NULL DEFAULT 0;
                 INSERT INTO marks(grp, high, low) VALUES('alt.old', 500, 100);
                 INSERT INTO marks(grp, high, low) VALUES('spots:free.pt', 77, 0);",
            )
            .unwrap();
        }
        let ix = Index::open(&db_path).unwrap();
        // Migrated rows are visible to no server until adopted.
        assert_eq!(ix.high_water("alt.old", "news.first.example"), 0);
        ix.adopt_legacy_marks("News.FIRST.Example").unwrap();
        assert_eq!(ix.high_water("alt.old", "news.first.example"), 500);
        assert_eq!(ix.low_water("alt.old", "news.first.example"), 100);
        // Spot marks migrate the same way (they share the table).
        assert_eq!(ix.high_water("spots:free.pt", "news.first.example"), 77);
        // Adoption never clobbers what the server has since written: a
        // straggling legacy row for an already-claimed group is dropped.
        ix.set_high_water("alt.old", "news.first.example", 900)
            .unwrap();
        ix.db
            .execute(
                "INSERT INTO marks(grp, server, high, low) VALUES('alt.old', '', 1, 1)",
                [],
            )
            .unwrap();
        ix.adopt_legacy_marks("news.first.example").unwrap();
        assert_eq!(ix.high_water("alt.old", "news.first.example"), 900);
        // Idempotent: nothing legacy left.
        ix.adopt_legacy_marks("news.first.example").unwrap();
        // Per-server independence - the whole point of the migration.
        ix.set_high_water("alt.old", "other.example", 42).unwrap();
        assert_eq!(ix.high_water("alt.old", "other.example"), 42);
        assert_eq!(ix.high_water("alt.old", "news.first.example"), 900);
        // A fresh database gets the new shape directly (no rebuild): the
        // reopen must not have bumped anything - just prove reads work.
        drop(ix);
        let ix2 = Index::open(&db_path).unwrap();
        assert_eq!(ix2.high_water("alt.old", "news.first.example"), 900);
        teardown(&dir, ix2);
    }

    /// A8: two servers scanning the same group merge into one release -
    /// message-ids are portable, so a part the first server's spool
    /// never received completes the release when another backbone's
    /// headers land. Overlap must not double-count.
    #[test]
    fn coverage_scans_from_two_servers_merge_and_complete() {
        let dir = std::env::temp_dir().join(format!("nzbfast-covmerge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let grp = "alt.binaries.teevee";
        // Server A saw parts 1 and 2 of 3 (a propagation hole ate #3).
        let a = [
            entry(
                r#""Show.S01E02.720p-GRP.mkv" yEnc (1/3)"#,
                "p@x",
                "s1e2.p1",
                700_000,
            ),
            entry(
                r#""Show.S01E02.720p-GRP.mkv" yEnc (2/3)"#,
                "p@x",
                "s1e2.p2",
                700_000,
            ),
        ];
        ix.ingest(grp, &a, 1_000).unwrap();
        let (r, _) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(r.len(), 1);
        assert!(!r[0].complete, "two of three parts is incomplete");
        // Server B carries parts 2 and 3 - same message-ids for the
        // overlap, which must merge rather than duplicate.
        let b = [
            entry(
                r#""Show.S01E02.720p-GRP.mkv" yEnc (2/3)"#,
                "p@x",
                "s1e2.p2",
                700_000,
            ),
            entry(
                r#""Show.S01E02.720p-GRP.mkv" yEnc (3/3)"#,
                "p@x",
                "s1e2.p3",
                700_000,
            ),
        ];
        let flipped = ix.ingest(grp, &b, 1_000).unwrap();
        assert_eq!(flipped, 1, "the merge is what completes the release");
        let (r, _) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(r.len(), 1, "still one release, not one per server");
        assert!(r[0].complete);
        let nzb = ix.make_nzb(r[0].id).unwrap();
        let parsed = crate::nzb::Nzb::parse(nzb.as_bytes()).unwrap();
        assert_eq!(
            parsed.files.iter().map(|f| f.segments.len()).sum::<usize>(),
            3,
            "the overlapping part must not be emitted twice"
        );
        teardown(&dir, ix);
    }

    /// A re-scan on a second provider must not revise the byte count of
    /// a part already held down to that provider's own convention.
    ///
    /// `:bytes` is a per-server approximation of one article, and two
    /// backbones measurably state it two ways - the same article's line
    /// terminators counted as CRLF or as LF, ~0.77% apart (measured 31
    /// Aug 2026 across five providers; the body they deliver is
    /// byte-identical). `gapfill` re-scans an incomplete release on the
    /// SECONDARY provider by design, so a plain overwrite made
    /// `total_bytes` track whichever server was asked last: 28% of a
    /// banked 35,535-release census had moved three days later, 97.5% of
    /// them downward, and 27 of them across a `junk_score` size
    /// threshold. Both directions are pinned - the smaller count must
    /// not win, and it must not be able to win by arriving first either.
    #[test]
    fn a_second_provider_never_shrinks_a_part_it_already_shares() {
        let dir = std::env::temp_dir().join(format!("nzbfast-bytesconv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let grp = "alt.binaries.teevee";
        let subj = |n: u32| format!(r#""Show.S01E03.720p-GRP.mkv" yEnc ({n}/2)"#);
        // The measured pair, from one real article on two backbones.
        const CRLF: u64 = 740_327;
        const LF: u64 = 734_624;
        // Primary states the CRLF convention and holds part 1 only.
        ix.ingest(grp, &[entry(&subj(1), "p@x", "s1e3.p1", CRLF)], 1_000)
            .unwrap();
        // Gapfill on the secondary re-states part 1 lower, and carries
        // the part the primary never saw with an OVER byte field it
        // could not parse - which reaches `ingest` as 0.
        ix.ingest(
            grp,
            &[
                entry(&subj(1), "p@x", "s1e3.p1", LF),
                entry(&subj(2), "p@x", "s1e3.p2", 0),
            ],
            1_000,
        )
        .unwrap();
        let (r, _) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(r.len(), 1, "one release, not one per server");
        assert_eq!(
            r[0].total_bytes, CRLF,
            "the shared part keeps the larger count - this is the \
             assertion a plain overwrite fails"
        );
        // A stored 0 is healed by the next real count rather than
        // pinned. This is the assertion first-writer-wins fails, and it
        // is why the merge takes the larger count rather than the first.
        ix.ingest(grp, &[entry(&subj(2), "p@x", "s1e3.p2", LF)], 1_000)
            .unwrap();
        let (r, _) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(
            r[0].total_bytes,
            CRLF + LF,
            "a zero count is not a floor the row can never leave"
        );
        // Monotone, so the stored number converges: re-stating either
        // count in either order changes nothing. The value must not
        // depend on which provider was asked last - which is the whole
        // defect - nor on which was asked first.
        ix.ingest(
            grp,
            &[
                entry(&subj(1), "p@x", "s1e3.p1", CRLF),
                entry(&subj(2), "p@x", "s1e3.p2", LF),
            ],
            1_000,
        )
        .unwrap();
        let (r, _) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(
            r[0].total_bytes,
            CRLF + LF,
            "monotone: re-stating what is already stored changes nothing"
        );
        teardown(&dir, ix);
    }

    /// A8 gap-fill pick: only incomplete, junk-gated, settled releases
    /// are worth re-hunting, and the stamp rotates the pick.
    #[test]
    fn gapfill_pick_gates_and_rotates() {
        let dir = std::env::temp_dir().join(format!("nzbfast-gapfill-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let grp = "alt.binaries.teevee";
        let now = 1_000_000i64;
        let old = now - 100_000;
        // Eligible: incomplete, seen long ago.
        ix.ingest(
            grp,
            &[entry(
                r#""Old.Show.S01E01.720p-GRP.mkv" yEnc (1/2)"#,
                "p@x",
                "old.p1",
                300_000_000,
            )],
            old,
        )
        .unwrap();
        // Complete: nothing to hunt.
        ix.ingest(
            grp,
            &[entry(
                r#""Done.Show.S01E01.720p-GRP.mkv" yEnc (1/1)"#,
                "p@x",
                "done.p1",
                300_000_000,
            )],
            old,
        )
        .unwrap();
        // Too fresh: parts are usually still propagating.
        ix.ingest(
            grp,
            &[entry(
                r#""New.Show.S01E01.720p-GRP.mkv" yEnc (1/2)"#,
                "p@x",
                "new.p1",
                300_000_000,
            )],
            now - 60,
        )
        .unwrap();
        // Junk-hidden: must not eat the budget.
        ix.ingest(
            grp,
            &[entry(
                r#""Junky.Show.S01E01.720p-GRP.mkv" yEnc (1/2)"#,
                "p@x",
                "junk.p1",
                300_000_000,
            )],
            old,
        )
        .unwrap();
        ix.db
            .execute("UPDATE releases SET junk=90 WHERE stem LIKE 'Junky%'", [])
            .unwrap();
        let picks = ix.gapfill_pick(10, now).unwrap();
        assert_eq!(
            picks.len(),
            1,
            "only the settled incomplete release qualifies"
        );
        let (id, g, posted) = &picks[0];
        assert_eq!(g, grp);
        assert_eq!(*posted, old);
        assert!(!ix.is_complete(*id));
        // The stamp rotates: a marked release yields to unmarked ones.
        ix.ingest(
            grp,
            &[entry(
                r#""Also.Old.S01E01.720p-GRP.mkv" yEnc (1/2)"#,
                "p@x",
                "also.p1",
                300_000_000,
            )],
            old,
        )
        .unwrap();
        ix.gapfill_mark(*id, now).unwrap();
        let picks2 = ix.gapfill_pick(1, now).unwrap();
        assert_eq!(picks2.len(), 1);
        assert_ne!(picks2[0].0, *id, "the stamped release rotates to the back");
        teardown(&dir, ix);
    }
}
