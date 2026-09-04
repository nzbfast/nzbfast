//! What a newsgroup actually carries, sampled from its newest articles.
//!
//! `LIST ACTIVE` gives a name, a posting flag and an article count, and
//! that is all the group browser had to rank 111k groups with. An article
//! count is a poor proxy for "is this group worth scanning": a group with
//! 175M articles that stopped moving in 2019 outranks a live one, and
//! nothing in the catalogue says whether those articles are 700 MB movies
//! or 40 KB book chapters.
//!
//! One `OVER` over the newest few hundred articles answers all of it in a
//! single round trip per group: sizes, the newest post's date, the rate
//! implied by the sample's own time span, and what the subjects look like.
//! Those are the four things a person actually chooses a group on, so
//! they become sort keys.
//!
//! Everything here is derived from Usenet-controlled text and must not
//! trust it: subjects are attacker-chosen, dates are frequently wrong or
//! absent, and article numbers can be sparse.

use std::collections::HashMap;
use std::path::Path;

/// What the posts in a group look like. Deliberately coarse - the useful
/// question is "is this group video, music, books, or packed archives I
/// cannot see into", not a precise taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Video,
    Audio,
    Books,
    Images,
    /// Packed and unidentifiable: rar/par2/7z whose release name gives
    /// nothing away. The honest answer for most obfuscated binaries.
    Packed,
    Other,
}

impl Kind {
    pub const ALL: [Kind; 6] = [
        Kind::Video,
        Kind::Audio,
        Kind::Books,
        Kind::Images,
        Kind::Packed,
        Kind::Other,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Kind::Video => "video",
            Kind::Audio => "audio",
            Kind::Books => "books",
            Kind::Images => "images",
            Kind::Packed => "packed",
            Kind::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.key() == s)
    }

    fn index(self) -> usize {
        Kind::ALL
            .iter()
            .position(|k| *k == self)
            .expect("Kind::ALL covers every variant")
    }
}

/// Media extensions that identify a post outright, when the subject names
/// a file we can read. Checked longest-first so `.tar.gz` style suffixes
/// cannot be shadowed by a shorter match.
const EXT_KIND: &[(&str, Kind)] = &[
    ("mkv", Kind::Video),
    ("mp4", Kind::Video),
    ("avi", Kind::Video),
    ("m4v", Kind::Video),
    ("mov", Kind::Video),
    ("wmv", Kind::Video),
    ("mpg", Kind::Video),
    ("mpeg", Kind::Video),
    ("m2ts", Kind::Video),
    ("ts", Kind::Video),
    ("vob", Kind::Video),
    ("divx", Kind::Video),
    ("webm", Kind::Video),
    ("iso", Kind::Video),
    ("mp3", Kind::Audio),
    ("flac", Kind::Audio),
    ("m4a", Kind::Audio),
    ("aac", Kind::Audio),
    ("ogg", Kind::Audio),
    ("wav", Kind::Audio),
    ("ape", Kind::Audio),
    ("wma", Kind::Audio),
    ("opus", Kind::Audio),
    ("epub", Kind::Books),
    ("mobi", Kind::Books),
    ("azw3", Kind::Books),
    ("pdf", Kind::Books),
    ("cbz", Kind::Books),
    ("cbr", Kind::Books),
    ("djvu", Kind::Books),
    ("azw", Kind::Books),
    ("jpg", Kind::Images),
    ("jpeg", Kind::Images),
    ("png", Kind::Images),
    ("gif", Kind::Images),
    ("bmp", Kind::Images),
    ("webp", Kind::Images),
];

/// Extensions that mean "this is a piece of a packed set" and therefore
/// say nothing about the content on their own.
const PACKED_EXT: &[&str] = &[
    "rar", "par2", "7z", "zip", "001", "002", "003", "nfo", "sfv", "srr", "srs",
];

/// Release-name tokens that betray the content of a packed set. Only
/// consulted when the extension itself was uninformative.
const HINT: &[(&str, Kind)] = &[
    ("1080p", Kind::Video),
    ("2160p", Kind::Video),
    ("720p", Kind::Video),
    ("x264", Kind::Video),
    ("x265", Kind::Video),
    ("h264", Kind::Video),
    ("hevc", Kind::Video),
    ("bluray", Kind::Video),
    ("bdrip", Kind::Video),
    ("dvdrip", Kind::Video),
    ("webrip", Kind::Video),
    ("web-dl", Kind::Video),
    ("hdtv", Kind::Video),
    ("xvid", Kind::Video),
    ("remux", Kind::Video),
    ("flac", Kind::Audio),
    ("mp3", Kind::Audio),
    ("320kbps", Kind::Audio),
    ("discography", Kind::Audio),
    ("vinyl", Kind::Audio),
    ("cdrip", Kind::Audio),
    ("epub", Kind::Books),
    ("retail", Kind::Books),
    ("audiobook", Kind::Books),
];

/// Pull the last `.ext` off a filename-looking token in a subject.
///
/// Subjects are wildly inconsistent - `[01/42] - "Foo.part01.rar" yEnc`,
/// bare `Foo.mkv`, or a quoted name with spaces - so this scans for the
/// longest run that looks like a filename and takes its final extension.
/// Bounded work per subject: subjects are capped by the caller.
fn extension_of(subject: &str) -> Option<String> {
    // Prefer a quoted filename when there is one; that is the yEnc
    // convention and it is unambiguous.
    let candidate = subject
        .split('"')
        .nth(1)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            subject
                .split_whitespace()
                .filter(|t| t.contains('.'))
                .max_by_key(|t| t.len())
                .map(str::to_string)
        })?;
    let ext: String = candidate
        .rsplit('.')
        .next()?
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    (!ext.is_empty() && ext.len() <= 5).then_some(ext)
}

/// Classify one subject line.
pub fn classify_subject(subject: &str) -> Kind {
    let lower = subject.to_ascii_lowercase();
    if let Some(ext) = extension_of(subject) {
        if let Some((_, k)) = EXT_KIND.iter().find(|(e, _)| *e == ext) {
            return *k;
        }
        if PACKED_EXT.contains(&ext.as_str()) {
            // A packed set whose release name still gives it away.
            if let Some((_, k)) = HINT.iter().find(|(h, _)| lower.contains(*h)) {
                return *k;
            }
            return Kind::Packed;
        }
    }
    if let Some((_, k)) = HINT.iter().find(|(h, _)| lower.contains(*h)) {
        return *k;
    }
    Kind::Other
}

/// One group's sampled profile.
#[derive(Debug, Clone, Default)]
pub struct GroupStats {
    pub sampled_at: i64,
    /// Articles the sample actually covered.
    pub sample_n: u32,
    /// Mean article size across the sample.
    pub avg_bytes: u64,
    /// avg_bytes x the catalogue's article count. An estimate of how much
    /// the group holds, and explicitly labelled as one in the UI - the
    /// sample is of the NEWEST articles, so a group whose posting habits
    /// changed will skew.
    pub est_bytes: u64,
    /// Newest Date: header seen. 0 when the server gave us none we could
    /// parse.
    pub last_post: i64,
    /// Articles per day implied by the sample's own time span.
    pub per_day: f64,
    /// Counts per Kind, indexed by `Kind::index`.
    pub kinds: [u32; 6],
    /// A few of the newest subjects verbatim, so the browser can show
    /// what is actually being posted rather than only statistics about
    /// it. Usenet-controlled text: sanitised on the way in (see
    /// `clean_subject`) and escaped again on the way out by the UI.
    pub samples: Vec<String>,
}

/// How many subjects a profile keeps, and how long each may be. Small on
/// purpose - this rides in a cache file for every sampled group.
const KEEP_SAMPLES: usize = 6;
const SAMPLE_MAX_CHARS: usize = 120;

/// Make a subject safe to store in a TSV field and to sit in JSON.
///
/// Strips the field and record separators the cache format relies on,
/// and anything else in the C0 range: a subject is attacker-controlled
/// and has no business carrying control characters into a log, a
/// terminal or a cache line. Truncates on a CHARACTER boundary, so a
/// multi-byte subject cannot be cut into invalid UTF-8.
fn clean_subject(s: &str) -> String {
    s.chars()
        .map(|c| {
            if (c as u32) < 0x20 || c == '\u{7f}' || c == '\u{1f}' {
                ' '
            } else {
                c
            }
        })
        .take(SAMPLE_MAX_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

impl GroupStats {
    /// Build from an OVER sample of the newest articles.
    ///
    /// `posts` is the catalogue's article count, used only to scale
    /// `avg_bytes` into `est_bytes`.
    pub fn from_sample(
        sampled_at: i64,
        posts: u64,
        entries: &[nzbkit::nntp::OverEntry],
    ) -> GroupStats {
        let mut s = GroupStats {
            sampled_at,
            sample_n: entries.len() as u32,
            ..Default::default()
        };
        if entries.is_empty() {
            return s;
        }
        // Saturating throughout: byte counts come off the wire and a
        // hostile or broken server can claim u64::MAX per article.
        let total: u64 = entries.iter().fold(0u64, |a, e| a.saturating_add(e.bytes));
        s.avg_bytes = total / entries.len() as u64;
        s.est_bytes = s.avg_bytes.saturating_mul(posts);
        for e in entries {
            s.kinds[classify_subject(&e.subject).index()] += 1;
        }
        // Newest first: the tail of an OVER range is the newest end.
        s.samples = entries
            .iter()
            .rev()
            .map(|e| clean_subject(&e.subject))
            .filter(|x| !x.is_empty())
            .take(KEEP_SAMPLES)
            .collect();
        // Dates: ignore unparseable (0) and anything implausibly far in
        // the future, which is common enough in real headers to matter.
        let horizon = sampled_at.saturating_add(7 * 86_400);
        let mut dates: Vec<i64> = entries
            .iter()
            .map(|e| e.date)
            .filter(|d| *d > 0 && *d <= horizon)
            .collect();
        if dates.is_empty() {
            return s;
        }
        dates.sort_unstable();
        s.last_post = *dates.last().expect("non-empty");
        let span = s.last_post - dates[0];
        // A busy group really does put 200 articles on the wire in under
        // a minute, and refusing to extrapolate from that hid the rate on
        // exactly the groups where it matters most (measured: 201
        // articles of alt.binaries.teevee spanned seconds, and the
        // hour-minimum this used to impose reported "no data" for the
        // busiest group on the server).
        //
        // The real hazard is dividing by a span so short that clock
        // granularity dominates - Date headers are whole seconds, so a
        // span of 0 or 1 is noise, not a measurement. Require 30 s and
        // extrapolate honestly above that.
        if span >= 30 {
            s.per_day = dates.len() as f64 * 86_400.0 / span as f64;
        }
        s
    }

    /// Replace the sample-span rate estimate with one measured over a far
    /// wider baseline.
    ///
    /// The newest 200 articles of a busy group can span seconds, which is
    /// too short to divide by: alt.binaries.teevee measured a 0 s span and
    /// so reported no rate at all, on the busiest group on the server. A
    /// single article fetched tens of thousands of numbers back gives a
    /// baseline of days instead, and `articles / elapsed` is then a real
    /// measurement rather than an extrapolation from a burst.
    ///
    /// Ignored unless the baseline is both older than the newest post and
    /// at least an hour wide, so a bad Date header cannot invent a rate.
    pub fn set_rate_from_baseline(&mut self, articles: u64, older: i64) {
        if self.last_post <= 0 || older <= 0 {
            return;
        }
        let elapsed = self.last_post - older;
        if elapsed < 3_600 || articles == 0 {
            return;
        }
        self.per_day = articles as f64 * 86_400.0 / elapsed as f64;
    }

    /// The Kind that most of the sample fell into.
    ///
    /// Other is excluded from the contest so that a group of mostly
    /// unreadable subjects still reports its readable minority - but if
    /// there is no readable minority at all, the answer is Other rather
    /// than None. That distinction is the whole point: None means "we
    /// have not looked at this group", Other means "we looked and the
    /// names are scrambled", and the second is genuinely useful when
    /// choosing a group. Measured on a real provider, the newest 201
    /// articles of alt.binaries.teevee were bare 32-character hex with no
    /// filename at all.
    pub fn dominant(&self) -> Option<Kind> {
        if self.sample_n == 0 {
            return None;
        }
        // Reversed so a TIE resolves to the FIRST kind in ALL order
        // (max_by_key keeps the last maximum): a 50/50 video-packed
        // sample must report Video, not Packed - ties toward the least
        // informative kind excluded half-video groups from kind=video,
        // against this function's own stated intent.
        Kind::ALL
            .into_iter()
            .filter(|k| *k != Kind::Other)
            .rev()
            .max_by_key(|k| self.kinds[k.index()])
            .filter(|k| self.kinds[k.index()] > 0)
            .or(Some(Kind::Other))
    }
}

/// Sampled stats for the catalogue, keyed by group name.
#[derive(Debug, Clone, Default)]
pub struct StatsCache {
    pub map: HashMap<String, GroupStats>,
}

/// How long a sample stays fresh before the background pass will redo it.
pub const SAMPLE_TTL_SECS: i64 = 7 * 86_400;

impl StatsCache {
    pub fn get(&self, name: &str) -> Option<&GroupStats> {
        self.map.get(name)
    }

    pub fn is_stale(&self, name: &str, now: i64) -> bool {
        match self.map.get(name) {
            None => true,
            Some(s) => now.saturating_sub(s.sampled_at) > SAMPLE_TTL_SECS,
        }
    }

    /// TSV beside the catalogue. Same write-then-rename discipline as
    /// `Catalog::save`, so a crash mid-write cannot leave a torn file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut out = String::with_capacity(self.map.len() * 64);
        out.push_str("#nzbfast-groupstats\t1\n");
        for (name, s) in &self.map {
            // Subjects are joined by US (0x1f), which clean_subject
            // strips from the subjects themselves, so the field cannot be
            // broken by hostile content.
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{}\t{}\n",
                name,
                s.sampled_at,
                s.sample_n,
                s.avg_bytes,
                s.est_bytes,
                s.last_post,
                s.per_day,
                s.kinds
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                s.samples.join("\u{1f}"),
            ));
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, out)?;
        std::fs::rename(&tmp, path)
    }

    pub fn load(path: &Path) -> Option<StatsCache> {
        let data = std::fs::read_to_string(path).ok()?;
        let mut lines = data.lines();
        if !lines.next()?.starts_with("#nzbfast-groupstats") {
            return None;
        }
        let mut map = HashMap::new();
        for line in lines {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 8 {
                continue;
            }
            let mut kinds = [0u32; 6];
            for (i, v) in f[7].split(',').take(6).enumerate() {
                kinds[i] = v.parse().unwrap_or(0);
            }
            map.insert(
                f[0].to_string(),
                GroupStats {
                    sampled_at: f[1].parse().unwrap_or(0),
                    sample_n: f[2].parse().unwrap_or(0),
                    avg_bytes: f[3].parse().unwrap_or(0),
                    est_bytes: f[4].parse().unwrap_or(0),
                    last_post: f[5].parse().unwrap_or(0),
                    per_day: f[6].parse().unwrap_or(0.0),
                    kinds,
                    // Field 8 arrived after the first cache format; an
                    // older line simply has no samples.
                    samples: f
                        .get(8)
                        .map(|s| {
                            s.split('\u{1f}')
                                .filter(|x| !x.is_empty())
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default(),
                },
            );
        }
        Some(StatsCache { map })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nzbkit::nntp::OverEntry;

    fn oe(subject: &str, bytes: u64, date: i64) -> OverEntry {
        OverEntry {
            number: 1,
            subject: subject.into(),
            from: "poster@example.invalid".into(),
            message_id: "<x@y>".into(),
            bytes,
            date,
        }
    }

    #[test]
    fn extension_wins_when_the_subject_names_a_file() {
        assert_eq!(
            classify_subject(r#"[01/42] - "Some.Film.mkv" yEnc (1/500)"#),
            Kind::Video
        );
        assert_eq!(
            classify_subject(r#"[1/9] - "album - 01 track.flac" yEnc"#),
            Kind::Audio
        );
        assert_eq!(
            classify_subject(r#""A Novel.epub" yEnc (1/2)"#),
            Kind::Books
        );
        assert_eq!(classify_subject(r#""holiday.JPG" yEnc"#), Kind::Images);
    }

    #[test]
    fn packed_sets_fall_back_to_release_name_hints() {
        // The extension says nothing; the release name says plenty.
        assert_eq!(
            classify_subject(r#"[03/55] - "Movie.2024.1080p.BluRay.x264.part02.rar" yEnc"#),
            Kind::Video
        );
        assert_eq!(
            classify_subject(r#""Artist-Album-FLAC-2024.par2" yEnc"#),
            Kind::Audio
        );
        // Nothing to go on: honest answer is "packed", not a guess.
        assert_eq!(
            classify_subject(r#"[01/20] - "a7f3b91c2d.part01.rar" yEnc"#),
            Kind::Packed
        );
    }

    #[test]
    fn fully_obfuscated_subjects_are_other() {
        assert_eq!(classify_subject("a7f3b91c2d8e4f5a6b7c"), Kind::Other);
        assert_eq!(classify_subject(""), Kind::Other);
    }

    /// Subjects are Usenet-controlled: nothing here may panic or hang.
    #[test]
    fn hostile_subjects_are_survivable() {
        for s in [
            "\"\"",
            "...",
            "....................",
            "\"unclosed",
            "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p",
            "\u{1f600}.\u{1f600}",
            "x.",
            ".rar",
            "\"\".mkv",
        ] {
            let _ = classify_subject(s);
        }
        // A pathological subject must not be slow either.
        let long = "a.".repeat(20_000);
        let _ = classify_subject(&long);
    }

    #[test]
    fn sample_yields_size_rate_and_mix() {
        let day = 86_400;
        let t0 = 1_700_000_000;
        let entries: Vec<OverEntry> = (0..10)
            .map(|i| oe(r#""Film.1080p.x264.mkv" yEnc"#, 500_000, t0 + i * day / 10))
            .collect();
        let s = GroupStats::from_sample(t0 + day, 1_000, &entries);
        assert_eq!(s.avg_bytes, 500_000);
        assert_eq!(s.est_bytes, 500_000_000);
        assert_eq!(s.dominant(), Some(Kind::Video));
        assert_eq!(s.last_post, t0 + 9 * day / 10);
        // 10 articles across 0.9 of a day.
        assert!((s.per_day - 11.1).abs() < 0.2, "per_day was {}", s.per_day);
    }

    /// A busy group genuinely posts hundreds of articles a minute, and
    /// that IS its rate - refusing to extrapolate hid the number on the
    /// busiest groups on the server. Only a span short enough that
    /// whole-second Date granularity dominates is rejected.
    #[test]
    fn short_but_real_spans_still_yield_a_rate() {
        let t0 = 1_700_000_000;
        // 200 articles across 49 s: fast, but measured over enough
        // seconds to mean something.
        let entries: Vec<OverEntry> = (0..200)
            .map(|i| oe(r#""x.mkv""#, 1000, t0 + i / 4))
            .collect();
        let s = GroupStats::from_sample(t0 + 100, 200, &entries);
        assert!(
            s.per_day > 100_000.0,
            "a genuinely busy group has a rate: {}",
            s.per_day
        );
    }

    #[test]
    fn a_span_too_short_to_measure_yields_no_rate() {
        let t0 = 1_700_000_000;
        // Every article stamped within the same couple of seconds: the
        // clock's resolution, not a measurement.
        let entries: Vec<OverEntry> = (0..200)
            .map(|i| oe(r#""x.mkv""#, 1000, t0 + i % 2))
            .collect();
        let s = GroupStats::from_sample(t0 + 100, 200, &entries);
        assert_eq!(
            s.per_day, 0.0,
            "a 1 s span is clock granularity, not a rate"
        );
    }

    #[test]
    fn subjects_are_kept_newest_first_and_defanged() {
        let t0 = 1_700_000_000;
        let entries = vec![
            oe("oldest", 10, t0),
            oe("carries\u{1f}a separator and \u{7} a bell", 10, t0 + 1),
            oe("newest", 10, t0 + 2),
        ];
        let s = GroupStats::from_sample(t0 + 10, 3, &entries);
        assert_eq!(s.samples[0], "newest", "newest subject must lead");
        // The cache's own field separator cannot survive in a subject, or
        // a hostile poster could forge extra fields on reload.
        assert!(
            !s.samples[1].contains('\u{1f}'),
            "separator survived: {:?}",
            s.samples[1]
        );
        assert!(!s.samples[1].contains('\u{7}'), "control char survived");
        assert!(s.samples.len() <= KEEP_SAMPLES);
    }

    /// A subject built to break the TSV cache must come back as one
    /// subject, not as extra fields.
    #[test]
    fn a_hostile_subject_cannot_forge_cache_fields() {
        let mut c = StatsCache::default();
        c.map.insert(
            "a.b".into(),
            GroupStats {
                sampled_at: 1,
                sample_n: 1,
                samples: vec![clean_subject("evil\u{1f}9999\t8888\nnext.group\t1")],
                ..Default::default()
            },
        );
        let dir = std::env::temp_dir().join(format!("nzbfast-gsx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("groupstats.tsv");
        c.save(&p).unwrap();
        let back = StatsCache::load(&p).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(back.map.len(), 1, "a subject must not inject extra groups");
        assert_eq!(back.get("a.b").unwrap().samples.len(), 1);
    }

    #[test]
    fn absurd_sizes_and_dates_do_not_overflow_or_leak_into_rates() {
        let t0 = 1_700_000_000;
        let entries = vec![
            oe(r#""a.mkv""#, u64::MAX, t0),
            oe(r#""b.mkv""#, u64::MAX, t0 + 5 * 86_400),
            // Far-future date: a real and common header defect.
            oe(r#""c.mkv""#, 10, 4_000_000_000),
        ];
        let s = GroupStats::from_sample(t0 + 5 * 86_400, u64::MAX, &entries);
        assert!(s.est_bytes > 0, "saturating multiply must not wrap to zero");
        assert!(
            s.last_post <= t0 + 5 * 86_400,
            "a date beyond the horizon must not become last_post"
        );
    }

    #[test]
    fn empty_sample_is_harmless() {
        let s = GroupStats::from_sample(1000, 500, &[]);
        assert_eq!(
            (s.sample_n, s.avg_bytes, s.per_day, s.dominant()),
            (0, 0, 0.0, None)
        );
    }

    #[test]
    fn cache_roundtrips_through_tsv() {
        let mut c = StatsCache::default();
        c.map.insert(
            "alt.binaries.teevee".into(),
            GroupStats {
                sampled_at: 1000,
                sample_n: 200,
                avg_bytes: 700_000,
                est_bytes: 7_000_000_000,
                last_post: 999,
                per_day: 1234.5,
                kinds: [180, 5, 0, 0, 15, 0],
                samples: vec!["a\tb".into(), "plain".into()],
            },
        );
        let dir = std::env::temp_dir().join(format!("nzbfast-gs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("groupstats.tsv");
        c.save(&p).unwrap();
        let back = StatsCache::load(&p).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        let g = back
            .get("alt.binaries.teevee")
            .expect("group survived the roundtrip");
        assert_eq!(
            (g.sample_n, g.avg_bytes, g.est_bytes),
            (200, 700_000, 7_000_000_000)
        );
        assert!((g.per_day - 1234.5).abs() < 0.01);
        assert_eq!(g.dominant(), Some(Kind::Video));
    }

    #[test]
    fn staleness_drives_resampling() {
        let mut c = StatsCache::default();
        c.map.insert(
            "a.b".into(),
            GroupStats {
                sampled_at: 1_000_000,
                ..Default::default()
            },
        );
        assert!(!c.is_stale("a.b", 1_000_000 + SAMPLE_TTL_SECS - 1));
        assert!(c.is_stale("a.b", 1_000_000 + SAMPLE_TTL_SECS + 1));
        assert!(c.is_stale("never.sampled", 1_000_000));
    }

    /// "Not sampled" and "sampled, and the names are scrambled" are
    /// different answers and the browser shows them differently.
    #[test]
    fn unreadable_is_distinguished_from_unsampled() {
        let t0 = 1_700_000_000;
        let entries: Vec<OverEntry> = (0..5)
            .map(|i| oe("62a453c96e904a87a509e1f0cf573aec", 10, t0 + i * 60))
            .collect();
        let s = GroupStats::from_sample(t0, 5, &entries);
        assert_eq!(
            s.dominant(),
            Some(Kind::Other),
            "a looked-at group reports Other"
        );
        assert_eq!(
            GroupStats::default().dominant(),
            None,
            "an unsampled group reports nothing"
        );
    }

    /// A wide baseline replaces the burst estimate; a narrow or backwards
    /// one is refused rather than inventing a rate.
    #[test]
    fn rate_baseline_needs_a_real_span() {
        let t0 = 1_700_000_000;
        let mut s = GroupStats {
            last_post: t0,
            per_day: 0.0,
            ..Default::default()
        };
        s.set_rate_from_baseline(50_000, t0 - 86_400);
        assert!(
            (s.per_day - 50_000.0).abs() < 1.0,
            "one day of baseline: {}",
            s.per_day
        );
        // Too narrow to divide by.
        let mut s2 = GroupStats {
            last_post: t0,
            ..Default::default()
        };
        s2.set_rate_from_baseline(50_000, t0 - 60);
        assert_eq!(s2.per_day, 0.0);
        // Baseline newer than the newest post: nonsense, refuse it.
        let mut s3 = GroupStats {
            last_post: t0,
            ..Default::default()
        };
        s3.set_rate_from_baseline(50_000, t0 + 86_400);
        assert_eq!(s3.per_day, 0.0);
    }
}
