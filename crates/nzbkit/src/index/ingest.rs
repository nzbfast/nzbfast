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

/// Is this stem obfuscation-SHAPED - a hash, a blob, a string that
/// carries no semantic content? This is deliberately narrower than
/// "junk_score >= 70": Kind::Other also scores 70 for stems that are
/// unparseable yet perfectly readable ("misfits-wegedeutschensd"), and
/// the correlation population gate must not guess a name for a post
/// that already SHOWS one (red-team 10 Aug 2026: junk>=70 alone is not
/// "obfuscated"). Extracted verbatim from junk_score so the two can
/// never drift.
pub fn stem_obfuscated(stem: &str, p: &crate::release::Parsed) -> bool {
    // Hash/blob names - parse_release can still guess a Kind for these,
    // so ask the obfuscation detector directly (sans a short extension
    // token, which would break its all-token rules).
    let bare = bare_stem(stem);
    if crate::release::looks_obfuscated(bare) {
        return true;
    }
    // Multi-token blobs the single-token detector misses
    // ("NGKzwg4lCQF_vMr95eoDx2X9NxbLi", "[ff63de8461]_[newzNZB]_…"):
    // a mixed-case-with-digits token ≥8 chars, or a ≥10-char hex run,
    // is no word from any title - but only damn a stem that parsed NO
    // real structure (year/season/resolution), so scene names with
    // hashes next to real markers survive.
    if p.year.is_none() && p.season.is_none() && p.res.is_none() {
        let blobbish = |t: &str| {
            let (up, lo, di) = t.chars().fold((false, false, false), |(u, l, d), c| {
                (
                    u || c.is_ascii_uppercase(),
                    l || c.is_ascii_lowercase(),
                    d || c.is_ascii_digit(),
                )
            });
            (t.len() >= 8 && t.chars().all(|c| c.is_ascii_alphanumeric()) && up && lo && di)
                || (t.len() >= 10 && di && t.chars().all(|c| c.is_ascii_hexdigit()))
                // Scattered internal caps, no digits ("gUSbVwIDqhrR") -
                // same signal as the single-token detector, per token.
                || (t.len() >= 9
                    && t.chars().all(|c| c.is_ascii_alphabetic())
                    && t.chars().skip(1).filter(|c| c.is_ascii_uppercase()).count() >= 3)
        };
        if bare
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(blobbish)
            // Nothing but digits and separators ("12895-1.11").
            || !bare.chars().any(|c| c.is_ascii_alphabetic())
        {
            return true;
        }
    }
    false
}

/// The strip now lives beside the detector it feeds, so the picks and
/// the claims apply-gate cannot drift apart again - see
/// `release::stem_is_a_name`. Re-exported because the byte-probe picks
/// reach it as `super::ingest::bare_stem`.
pub(super) use crate::release::bare_stem;

pub fn junk_score(stem: &str, p: &crate::release::Parsed, total_bytes: u64, has_exe: bool) -> i64 {
    use crate::release::Kind;
    let bare = bare_stem(stem);
    let mut s: i64 = match p.kind {
        // Unparseable stems.
        Kind::Other => 70,
        // Keygen/crack/app-spam markers.
        Kind::Software => 55,
        _ => 0,
    };
    if stem_obfuscated(stem, p) {
        s = s.max(70);
    }
    // junk_v6: evidence-free "media". A real scene/P2P post virtually
    // always carries at least one technical marker (year, S/E, res,
    // source, codec, remux). A media extension on bare words
    // ("aula.mp4", "misfits-wegedeutschensd") is a course rip, personal
    // file, or spam - nothing an indexer would list. The trailing
    // -group token deliberately does NOT count as evidence: any
    // "words-blob" name grows one for free.
    let no_evidence = p.year.is_none()
        && p.season.is_none()
        && p.episode.is_none()
        && p.res.is_none()
        && p.source.is_none()
        && p.vcodec.is_none()
        && p.acodec.is_none()
        && !p.remux;
    if no_evidence && matches!(p.kind, Kind::Movie | Kind::Tv) {
        s = s.max(60);
    }
    // junk_v6: numbered-lecture prefix ("003 - Estômago.mp4",
    // "056 - Ortografia II") - course/track dumps open with a short
    // track number; scene names never start "NNN - ". Fires even when a
    // stray year parses later in the name, but never on anything that
    // parsed a season/episode.
    if p.season.is_none() && p.episode.is_none() {
        let t = bare.trim_start();
        let nd = t.chars().take_while(|c| c.is_ascii_digit()).count();
        if (1..=3).contains(&nd) && t[nd..].trim_start_matches(' ').starts_with("- ") {
            s = s.max(60);
        }
    }
    // junk_v6: leading bracketed pure-hex tag ("[a1911f7bca]_[newzNZB]_
    // name") - repost-bot spam whose inner name looks real and would
    // otherwise pollute a genuine title's card. Anime subgroup brackets
    // ("[SubsPlease]") are words, not hex, and survive.
    if let Some(rest) = bare.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let tag = &rest[..end];
        if tag.len() >= 8 && tag.chars().all(|c| c.is_ascii_hexdigit()) {
            s = s.max(60);
        }
    }
    // junk_v6: a parsed MOVIE claiming HD on a sub-200 MB post is spam
    // or a fake repost - a real 720p+ feature is never that small.
    // Mid-uploads shed this as their parts arrive (scores recompute on
    // every ingest touch). TV is exempt: short-form episodes can be
    // legitimately tiny.
    if matches!(p.kind, Kind::Movie)
        && p.res.is_some()
        && total_bytes > 0
        && total_bytes < 200 << 20
    {
        s = s.max(55);
    }
    // Media-shaped title on a tiny post: indexer spam or nfo-only. A
    // parsed movie/episode name claiming <10 MB is never the media
    // itself - hide it outright (55 crosses the default-50 line). A
    // custom category is exempt in BOTH directions: its payloads can be
    // legitimately tiny (comics, podcasts), so tiny is not evidence of
    // anything there. Books and music are exempt for the same reason and
    // it is not a nicety: an epub is about a megabyte and a single
    // track a few, so scoring them by film sizes would have hidden the
    // whole lane the moment the parser started producing it.
    if total_bytes > 0 && total_bytes < 10 << 20 {
        s = match p.kind {
            Kind::Movie | Kind::Tv => s.max(55),
            Kind::Custom(_) | Kind::Music | Kind::Book => s,
            _ => s + 40,
        };
    }
    // Furniture posted as its own "release": nfo/srr/sfv/sample/subs
    // riding a real release's name. These filled the newest-first list
    // with 0.00 GB rows no indexer site would show.
    let lower = stem.to_ascii_lowercase();
    const FURNITURE: [&str; 8] = [
        ".nfo", ".srr", ".sfv", ".nzb", ".idx", ".sub", ".srt", ".sample",
    ];
    if FURNITURE.iter().any(|e| lower.ends_with(e)) {
        s = s.max(60);
    }
    // "sample"/"proof" as a NAME token is only furniture when the post is
    // sample-SIZED (M32: name-only matching wrongly damns
    // full releases with 'sample' in the title). Real samples are tens of
    // MB; past 300 MB the token is part of a title, not a role.
    if total_bytes < 300 << 20
        && lower
            .split(['.', '_', '-', ' '])
            .any(|t| t == "sample" || t == "proof")
    {
        s = s.max(60);
    }
    // M32 (Prowlarr#2329): an executable riding a media-shaped release is
    // the classic malware shape - no legitimate movie/episode/music post
    // carries an .exe. Software releases legitimately do, so only their
    // Kind escapes the hammer.
    if has_exe && !matches!(p.kind, Kind::Software) {
        s = s.max(85);
    }
    s.min(100)
}

/// `… "name" yEnc (n/m)` → (subject minus counter, n, m).
///
/// The counter is the RIGHTMOST group that actually parses as one:
/// `(n/m)`, `[n/m]`, or `(n of m)`. Taking the last `(` unconditionally
/// broke on trailing tags - `… (5/50) (German)` or `… (5/50) (4.2 GB)`
/// returned None, every part collapsed to (1,1), and a 50-part file
/// indexed as one segment yet counted "complete".
pub fn split_subject(subject: &str) -> Option<(String, u32, u32)> {
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
        return Some((base, n, m));
    }
    None
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
/// considered. A backstop, not a policy: the marked namespace holds the
/// reposts of ONE name by ONE poster in ONE group, so reaching this
/// would itself be the anomaly.
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
/// every time. Past the cap the cluster is dropped instead, but only
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
        // the cap - 166k of them on the live index, plus anything the
        // uncapped spot minting site pushes over - this batch's own
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
/// giving up on a batch. Three generations of one release inside a
/// single OVER window is already beyond anything observed; past that the
/// articles are dropped and re-arrive on the next scan of the window.
const MAX_GEN_PASSES: u32 = 4;

impl Index {
    /// Ingest-time parse: built-in classifier plus the installed custom
    /// categories. Every site that WRITES kind/title_key must call this,
    /// not `parse_release`, or custom rows would flap back to their
    /// built-in kind on the next re-ingest touch.
    fn classify(&self, stem: &str) -> crate::release::Parsed {
        crate::categories::classify(stem, &self.custom)
    }

    /// TODO 24D: chunked re-classification of stored rows after the
    /// category config changed. Same shape as the quality_v9 migration
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
            // cursor rather than restarting, exactly like quality_v9.
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
            // classification site reads (ingest_pass, the quality_v9
            // backfill): classifying the raw stem here rewrote pre-named
            // obfuscated releases back to kind=other / blank title_key /
            // junk>=70 on any category edit, and the naming seam refuses
            // rows whose pre_title is already set, so nothing healed them.
            let rows: Vec<(i64, String, i64, bool, String)> = {
                let mut sel = tx.prepare_cached(&format!(
                    "SELECT id, COALESCE(NULLIF(pre_title,''), stem), total_bytes,
                            EXISTS(SELECT 1 FROM files
                                   WHERE release_id=releases.id AND {EXE_FILE_SQL}),
                            stem
                     FROM releases WHERE id > ?1 ORDER BY id LIMIT 10000"
                ))?;
                sel.query_map([cursor], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
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
                for (id, name, bytes, has_exe, stem) in &rows {
                    let mut p = self.classify(name);
                    crate::release::recover_media_kind(&mut p, name, stem);
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
        let mut deferred = self.ingest_pass(grp, entries, now, completed, hits)?;
        let mut pass = 1u32;
        while !deferred.is_empty() {
            if pass >= MAX_GEN_PASSES {
                warn!(
                    target: "index",
                    "{grp}: {} articles still contradict after {MAX_GEN_PASSES} generation \
                     passes - dropping them; they re-arrive on the next scan of this window",
                    deferred.len()
                );
                break;
            }
            pass += 1;
            let batch = std::mem::take(&mut deferred);
            deferred = self.ingest_pass(grp, &batch, now, completed, hits)?;
        }
        Ok(())
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
    ) -> rusqlite::Result<Vec<OverEntry>> {
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
        for e in entries {
            let (base, part, total) =
                split_subject(&e.subject).unwrap_or_else(|| (e.subject.clone(), 1, 1));
            if e.message_id.is_empty() || part == 0 || total == 0 {
                continue;
            }
            let Some(fname) = quoted_name(&base) else {
                continue;
            };
            let stem = release_stem(&fname);
            if stem.is_empty() {
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
            let (was, had_title, had_source, base): Baseline = tx
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
