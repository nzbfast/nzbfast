//! Junk scoring: is this posted stem worth listing at all?
//!
//! Pure functions over a stem and its [`crate::release::Parsed`] reading,
//! reaching nothing but `release`. They lived in `index::ingest` until the
//! nzbkit-base cut on 3 Sep 2026, which is the same finding lane 1 made
//! about `release_stem`: a name-grammar rule sitting inside the 42k-line
//! `index` module, with `release`'s own test table reaching UP for it.
//! `index::ingest` re-exports both, so every `nzbkit::index::junk_score`
//! caller - and every `super::ingest::` path inside the indexer - is
//! unchanged.

use crate::release::bare_stem;

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
        // A parsed DATE is at least as much of a technical marker as the
        // year this list already counts, and on a periodical it is
        // strictly better: it is the identity of the issue. Added 2 Sep
        // 2026 with the masthead date reading - a dated post gives its
        // year token up to the date, so "The New York Times - 15 August
        // 2026" posted somewhere with no media prior went from a
        // year-bearing 0 to an evidence-free 60 purely because the
        // parser got BETTER at it.
        && p.date.is_none()
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
    // `.m3u`, `.cue` and `.log` joined 2 Sep 2026: a scene-named
    // playlist ("00-artist-album-cd-flac-2012.m3u") parses as MUSIC
    // through the format marker and scored 0, so every album in
    // alt.binaries.sounds.flac put a 1.5 KB "album" card beside its
    // tracks. A playlist is never the content.
    let lower = stem.to_ascii_lowercase();
    const FURNITURE: [&str; 11] = [
        ".nfo", ".srr", ".sfv", ".nzb", ".idx", ".sub", ".srt", ".sample", ".m3u", ".cue", ".log",
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
