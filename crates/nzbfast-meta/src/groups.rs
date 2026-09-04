//! Newsgroup discovery catalogue: the full `LIST ACTIVE` group list from
//! the primary server, cached on disk, classified into browse categories
//! and searchable by name, description and category synonyms. Powers the
//! dashboard's "Find newsgroups" browser so a scan group can be picked
//! from a list instead of typed from memory.

use std::path::Path;

/// One catalogued group.
#[derive(Debug, Clone)]
pub struct CatGroup {
    pub name: String,
    /// Article count the server reports (high - low): the "how busy is
    /// this group" signal, and the default sort.
    pub posts: u64,
    /// One-line description from LIST NEWSGROUPS (often empty on binary
    /// providers).
    pub desc: String,
    pub cat: Category,
    /// Posting status from LIST ACTIVE: 'y' open, 'n' read-only, 'm'
    /// moderated. Parsed all along and then discarded - Claws is the only
    /// surveyed client that shows it, and "you cannot post here" is worth
    /// knowing before you subscribe.
    pub status: char,
    /// When a refresh first saw this group appear on the server
    /// (unix secs). 0 = it predates our first fetch - only groups that
    /// APPEAR while we watch count as "new", so the initial 100k-group
    /// import doesn't flag everything.
    pub first_seen: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Movies,
    Tv,
    Music,
    Books,
    Comics,
    Games,
    Software,
    Anime,
    Sports,
    Adult,
    Other,
}

impl Category {
    pub fn key(self) -> &'static str {
        match self {
            Category::Movies => "movies",
            Category::Tv => "tv",
            Category::Music => "music",
            Category::Books => "books",
            Category::Comics => "comics",
            Category::Games => "games",
            Category::Software => "software",
            Category::Anime => "anime",
            Category::Sports => "sports",
            Category::Adult => "adult",
            Category::Other => "other",
        }
    }
    pub fn parse(s: &str) -> Option<Category> {
        Some(match s {
            "movies" => Category::Movies,
            "tv" => Category::Tv,
            "music" => Category::Music,
            "books" => Category::Books,
            "comics" => Category::Comics,
            "games" => Category::Games,
            "software" => Category::Software,
            "anime" => Category::Anime,
            "sports" => Category::Sports,
            "adult" => Category::Adult,
            "other" => Category::Other,
            _ => return None,
        })
    }
}

/// Keyword tables: a group lands in the FIRST category whose keyword
/// matches a dot-separated segment of its name (or a word of its
/// description). Segment matching, not substring: "manga" must not put
/// alt.binaries.mangled in Comics. The same tables drive search-synonym
/// expansion, so a search for "car" also surfaces rec.autos.* - each
/// entry is (category, &[keywords]).
const CATS: &[(Category, &[&str])] = &[
    // Anime before TV/Movies: alt.binaries.anime is more specifically
    // anime than it is "video".
    (Category::Anime, &["anime", "manga", "hentai-free-zone"]),
    (
        Category::Adult,
        &[
            "erotica",
            "erotic",
            "sex",
            "porn",
            "xxx",
            "adult",
            "nude",
            "hentai",
            "pictures.erotica",
        ],
    ),
    (
        Category::Sports,
        &[
            "sport",
            "sports",
            "motorsports",
            "motorsport",
            "racing",
            "f1",
            "formula1",
            "nascar",
            "wrestling",
            "ufc",
            "mma",
            "boxing",
            "soccer",
            "football",
            "nfl",
            "nba",
            "nhl",
            "mlb",
            "cricket",
            "rugby",
            "golf",
            "cycling",
            "darts",
            "tennis",
            "autos",
            "auto",
            "cars",
            "car",
            "moto",
            "motorcycles",
            "motorbikes",
            "automobiles",
        ],
    ),
    (
        Category::Comics,
        &["comics", "comic", "cbr", "graphic-novels"],
    ),
    (
        Category::Books,
        &[
            "ebook",
            "ebooks",
            "e-book",
            "e-books",
            "book",
            "books",
            "audiobook",
            "audiobooks",
            "magazines",
            "mags",
            "textbooks",
        ],
    ),
    (
        Category::Music,
        &[
            "music",
            "mp3",
            "flac",
            "lossless",
            "sounds",
            "audio",
            "karaoke",
            "vinyl",
            "opera",
            "jazz",
            "metal",
            "country",
            "classical",
        ],
    ),
    (
        Category::Games,
        &[
            "games",
            "game",
            "gaming",
            "nintendo",
            "playstation",
            "psx",
            "ps2",
            "ps3",
            "ps4",
            "ps5",
            "xbox",
            "x-box",
            "wii",
            "gamecube",
            "dreamcast",
            "emulators",
            "roms",
            "switch",
            "steam",
        ],
    ),
    (
        Category::Tv,
        &[
            "teevee",
            "tv",
            "hdtv",
            "television",
            "series",
            "shows",
            "documentaries",
            "docus",
        ],
    ),
    (
        Category::Movies,
        &[
            "moovee", "movies", "movie", "film", "films", "dvd", "dvdr", "dvd-r", "divx", "x264",
            "x265", "hevc", "bluray", "blu-ray", "bd", "uhd", "cinema", "vcd", "svcd", "kino",
        ],
    ),
    (
        Category::Software,
        &[
            "software",
            "apps",
            "applications",
            "warez",
            "win",
            "windows",
            "mac",
            "linux",
            "ubuntu",
            "iso",
            "isos",
            "cd",
            "cdr",
            "programs",
            "os",
        ],
    ),
];

/// Hierarchies that actually carry binaries. NewsBin's own figures:
/// ~3000 active binary groups out of 150k+ total, and their "Binaries"
/// checkbox alone cuts 100k+ to under ten thousand. `alt.binaries` is the
/// bulk of it; the rest are the historic binary trees still in use.
const BINARY_PREFIXES: &[&str] = &[
    "alt.binaries.",
    "alt.bin.",
    "a.b.",
    "free.binaries.",
    "dk.binaer.",
    "de.alt.binaries.",
    "nl.binaries.",
    "fr.binaires.",
    "it.binari.",
    "es.binarios.",
    "pl.binaria.",
    "alt.sources.",
    "comp.binaries.",
    "rec.games.bolo.binaries.",
    "binaries.",
];

/// Does this group live in a binary-carrying hierarchy?
pub fn is_binary(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    BINARY_PREFIXES.iter().any(|p| l.starts_with(p)) || l.contains(".binaries.")
}

/// Expand a dotted abbreviation into a per-segment prefix test:
/// `a.b.mo` matches alt.binaries.movies, `co.sy.ma` matches
/// comp.sys.mac. Lifted from MT-NewsWatcher, whose manual calls out
/// `co.sy.ma.co` jumping to comp.sys.mac.comm - it is the single most
/// loved trick in the whole newsreader survey and costs almost nothing.
/// Only fires for queries that actually look like an abbreviation (a dot
/// with short segments), so it never hijacks an ordinary word search.
pub fn abbrev_matches(query: &str, name: &str) -> bool {
    let q: Vec<&str> = query.split('.').filter(|s| !s.is_empty()).collect();
    if q.len() < 2 || q.iter().any(|s| s.len() > 4) {
        return false;
    }
    let segs: Vec<&str> = name.split('.').collect();
    if segs.len() < q.len() {
        return false;
    }
    q.iter().zip(&segs).all(|(a, b)| b.starts_with(a))
}

/// Glob match supporting `*` and `?`, anchored to the whole name -
/// slrn's `L <wildmat>` and tin's `S`/`U` both take a pattern, and a
/// pattern that REDUCES the set beats a filter that highlights within a
/// rendered 111k rows.
///
/// Comparison is byte-wise and ASCII-case-insensitive, so `?` spans one
/// BYTE. Group names are ASCII, and matching bytes keeps this off the
/// UTF-8 decode path for the ~200k calls a single query makes.
///
/// Two-pointer with a single backtrack point, NOT the recursive
/// `go(rest, n) || go(p, rest)` this started as. That form re-explored
/// the same (pattern, name) pair once per path that reached it, so a
/// pattern alternating `*` and `?` cost ~5x per added pair: `*?` ten
/// times over took 29 s against ONE name, and the matcher runs over
/// every group in the catalogue (twice - see match_group's implicit
/// `*t*`). A search box that any authenticated user can type into is not
/// a place to keep an exponential algorithm.
///
/// The greedy form is exact, not an approximation: `*` is the only
/// construct that can consume a variable amount, and consecutive stars
/// collapse into one, so there is never more than ONE live decision -
/// the most recent star's split point. On a mismatch, giving that star
/// one more byte and resuming re-tries every possibility the recursion
/// did. Worst case O(n*m); linear on the patterns people actually type.
pub fn glob_matches(pat: &str, name: &str) -> bool {
    let (p, n) = (pat.as_bytes(), name.as_bytes());
    let (mut pi, mut ni) = (0usize, 0usize);
    // Where to resume the pattern after the most recent `*`, and how much
    // of the name that star has been given so far. None = no star seen,
    // so a mismatch is final.
    let mut after_star: Option<usize> = None;
    let mut star_ate = 0usize;
    while ni < n.len() {
        if pi < p.len() && p[pi] == b'*' {
            // Coalesce a run: `**` can match nothing more than `*` can,
            // and collapsing it keeps one backtrack point rather than one
            // per star.
            while pi < p.len() && p[pi] == b'*' {
                pi += 1;
            }
            if pi == p.len() {
                return true; // trailing star takes the whole remainder
            }
            after_star = Some(pi);
            star_ate = ni;
        } else if pi < p.len() && (p[pi] == b'?' || p[pi].eq_ignore_ascii_case(&n[ni])) {
            // `?` is tested BEFORE the literal compare, and `*` above it,
            // so a name containing a literal `*` or `?` can never make
            // the pattern's wildcard match as an ordinary character.
            pi += 1;
            ni += 1;
        } else if let Some(resume) = after_star {
            // Hand the star one more byte and try the rest again.
            star_ate += 1;
            pi = resume;
            ni = star_ate;
        } else {
            return false;
        }
    }
    // Name exhausted: what is left of the pattern must be stars only
    // (which may match nothing) - a `?` or a literal still needs a byte.
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Classify a group by name segments (dot- and dash-split), then by
/// description words.
pub fn classify(name: &str, desc: &str) -> Category {
    let lname = name.to_ascii_lowercase();
    let segs: Vec<&str> = lname.split(['.', '-']).collect();
    for (cat, words) in CATS {
        if words.iter().any(|w| segs.contains(w)) {
            return *cat;
        }
    }
    if !desc.is_empty() {
        let ldesc = desc.to_ascii_lowercase();
        let words: Vec<&str> = ldesc
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|w| !w.is_empty())
            .collect();
        for (cat, kws) in CATS {
            if kws.iter().any(|w| words.contains(w)) {
                return *cat;
            }
        }
    }
    Category::Other
}

/// Synonym expansion: extra search terms implied by a query term, so
/// "car" finds rec.autos.* and "film" finds alt.binaries.moovee. Both
/// directions are curated by hand - table-driven expansion over the
/// category keyword lists would make "cd" match every Sports group.
const SYNONYMS: &[(&str, &[&str])] = &[
    (
        "car",
        &["auto", "autos", "cars", "motorsports", "racing", "formula1"],
    ),
    ("cars", &["auto", "autos", "car", "motorsports", "racing"]),
    ("auto", &["autos", "cars", "car", "motorsports", "racing"]),
    ("racing", &["f1", "nascar", "motorsports", "autos", "moto"]),
    ("motor", &["moto", "motorsports", "autos", "motorcycles"]),
    ("movie", &["moovee", "movies", "film", "dvd", "divx"]),
    ("movies", &["moovee", "movie", "film", "dvd", "divx"]),
    ("film", &["moovee", "movies", "movie", "dvd", "kino"]),
    ("tv", &["teevee", "hdtv", "television"]),
    ("show", &["teevee", "tv", "series", "shows"]),
    ("series", &["teevee", "tv", "shows"]),
    ("music", &["mp3", "flac", "sounds", "lossless", "audio"]),
    ("song", &["mp3", "flac", "sounds", "music"]),
    ("songs", &["mp3", "flac", "sounds", "music"]),
    ("book", &["ebook", "ebooks", "books", "audiobook"]),
    ("books", &["ebook", "ebooks", "book", "audiobook"]),
    (
        "game",
        &["games", "roms", "nintendo", "playstation", "xbox"],
    ),
    (
        "games",
        &["game", "roms", "nintendo", "playstation", "xbox"],
    ),
];

/// How a group matched the query - better kinds sort first under the
/// relevance sort.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum Hit {
    NamePrefix,
    NameSegment,
    NameSubstring,
    Description,
    Synonym,
}

fn match_group(g: &CatGroup, terms: &[String]) -> Option<Hit> {
    let lname = g.name.to_ascii_lowercase();
    // A query carrying wildcards IS the pattern - match the whole name
    // against it and skip the word logic entirely (an implicit `*x*` is
    // applied so `*.mp3` and `mp3*` both behave as users expect).
    if terms.iter().any(|t| t.contains('*') || t.contains('?')) {
        return terms
            .iter()
            .all(|t| glob_matches(t, &lname) || glob_matches(&format!("*{t}*"), &lname))
            .then_some(Hit::NameSegment);
    }
    // Dotted abbreviation: a.b.mo -> alt.binaries.movies.
    if terms.len() == 1 && abbrev_matches(&terms[0], &lname) {
        return Some(Hit::NamePrefix);
    }
    // Every literal term must hit name or description (AND semantics);
    // the hit kind is the WORST kind among them.
    let mut worst = Hit::NamePrefix;
    for t in terms {
        let kind = if lname.starts_with(t.as_str()) {
            Hit::NamePrefix
        } else if lname.split(['.', '-']).any(|s| s == t) {
            Hit::NameSegment
        } else if lname.contains(t.as_str()) {
            Hit::NameSubstring
        } else if !g.desc.is_empty() && g.desc.to_ascii_lowercase().contains(t.as_str()) {
            Hit::Description
        } else {
            // Literal miss: a synonym of THIS term may still hit. This
            // term's own synonyms only - the old parameter was the union
            // over every term, and consulting the union let one term's synonym
            // satisfy a DIFFERENT term, so every multi-term query
            // degenerated toward OR whenever any term had a synonym list
            // ("auto tv" matched motorsports groups with no tv hit).
            let own: Vec<&str> = SYNONYMS
                .iter()
                .filter(|(k, _)| *k == t.as_str())
                .flat_map(|(_, v)| v.iter().copied())
                .collect();
            if own.iter().any(|s| {
                lname.split(['.', '-']).any(|seg| seg == *s)
                    || (!g.desc.is_empty() && g.desc.to_ascii_lowercase().contains(s))
            }) {
                Hit::Synonym
            } else {
                return None;
            }
        };
        worst = worst.max(kind);
    }
    Some(worst)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    /// Most posts first (the default); with a query, relevance breaks
    /// posts ties per hit-kind bucket.
    Posts,
    Name,
    /// Estimated bytes held, from the sampled mean article size. Groups
    /// with no sample yet sort last whichever direction is asked for -
    /// see the sample-derived `key` closure in `Catalog::query`, which
    /// returns None for them, and the test that pins both directions,
    /// `unprofiled_groups_sort_last_in_both_directions`.
    Size,
    /// Articles per day, from the sample's own time span.
    Activity,
    /// Newest post seen. The single most useful signal for "is this
    /// group alive", and invisible in a raw article count: a group can
    /// carry 175M articles and not have moved since 2019.
    Fresh,
    /// Mean article size. Distinguishes a group of 700 MB films from one
    /// of 40 KB book chapters at the same article count.
    AvgSize,
}

impl Sort {
    pub fn parse(s: &str) -> Sort {
        match s {
            "name" => Sort::Name,
            "size" => Sort::Size,
            "activity" => Sort::Activity,
            "fresh" => Sort::Fresh,
            "avgsize" => Sort::AvgSize,
            _ => Sort::Posts,
        }
    }
}

pub struct Query<'a> {
    pub q: &'a str,
    /// Only groups first seen in the last NEW_WINDOW_SECS.
    pub new_only: bool,
    /// Binary-carrying hierarchies only. NewsBin's headline filter: it
    /// takes a 111k-group server down to the few thousand that actually
    /// carry binaries, which is the only part most users want.
    pub binaries_only: bool,
    /// Drop groups with fewer than this many articles - the long tail of
    /// dead and near-dead groups is most of the list by count.
    pub min_posts: u64,
    /// Restrict to this set of names ("only groups I scan"). Must be a
    /// filter INSIDE the query: post-filtering the returned page would
    /// only ever see the first `limit` rows, so a subscribed group
    /// outside the top page silently vanished.
    pub only: Option<&'a std::collections::HashSet<String>>,
    pub cat: Option<Category>,
    /// Sampled profiles, when the caller has them. The content and
    /// freshness filters below need them and are no-ops without them.
    pub stats: Option<&'a crate::groupstats::StatsCache>,
    /// Only groups whose sample is mostly this kind of content.
    pub kind: Option<crate::groupstats::Kind>,
    /// Only groups with a post newer than this many days ago. 0 = off.
    /// The filter people actually reach for: "show me groups that are
    /// still alive".
    pub active_days: u32,
    /// Only groups that have a description to search.
    pub with_desc: bool,
    pub sort: Sort,
    pub desc_order: bool,
    pub offset: usize,
    pub limit: usize,
}

impl Query<'_> {
    /// Does this group pass the sample-derived filters?
    ///
    /// An unsampled group is EXCLUDED once one of these filters is on.
    /// The first cut let unsampled groups through, on the reasoning that
    /// an unknown group is not a group known to be wrong - which sounds
    /// principled and was useless in practice: asking for video groups
    /// returned 111,318 of the server's 111,330, because almost nothing
    /// had been profiled yet. A filter has to filter. The browser says
    /// how many groups are profiled so the short list is explicable
    /// rather than mysterious.
    fn stats_allow(&self, name: &str, now: i64) -> bool {
        if self.kind.is_none() && self.active_days == 0 {
            return true;
        }
        let Some(sc) = self.stats else { return true };
        let Some(s) = sc.get(name) else { return false };
        if let Some(k) = self.kind
            && s.dominant() != Some(k)
        {
            return false;
        }
        if self.active_days > 0 {
            // last_post == 0 means the server gave us no usable dates,
            // which is not evidence the group is dead.
            let cutoff = now - i64::from(self.active_days) * 86_400;
            if s.last_post > 0 && s.last_post < cutoff {
                return false;
            }
        }
        true
    }
}

/// How long a group keeps its "newly added" badge after it first
/// appears on the server.
pub const NEW_WINDOW_SECS: i64 = 30 * 86400;

/// The in-memory catalogue.
#[derive(Default)]
pub struct Catalog {
    pub fetched_at: i64,
    pub groups: Vec<CatGroup>,
}

impl Catalog {
    /// Search + filter + sort + page. Returns (total matches, page).
    pub fn query(&self, q: &Query) -> (usize, Vec<&CatGroup>) {
        let terms: Vec<String> =
            q.q.to_ascii_lowercase()
                .split_whitespace()
                .map(str::to_string)
                .filter(|t| !t.is_empty())
                .collect();
        // Wall-clock now, NOT fetched_at: "active in the last N days"
        // measured against the catalogue's fetch time let a 10-day-old
        // catalogue answer "last 1 day" with groups whose newest sampled
        // post was 11 days old.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0);
        let mut hits: Vec<(Hit, &CatGroup)> = self
            .groups
            .iter()
            .filter(|g| q.cat.is_none_or(|c| g.cat == c))
            .filter(|g| {
                !q.new_only
                    || (g.first_seen > 0 && self.fetched_at - g.first_seen < NEW_WINDOW_SECS)
            })
            .filter(|g| !q.binaries_only || is_binary(&g.name))
            .filter(|g| g.posts >= q.min_posts)
            // Case-insensitive to match how the scan list itself is
            // maintained (interests.rs merges/removes with
            // eq_ignore_ascii_case): a hand-typed ALT.BINARIES.FOO is
            // scanned, so it must not vanish from the subscribed-only
            // view. The set is the user's own scan list (tens of rows),
            // so the linear probe costs nothing that matters.
            .filter(|g| {
                q.only
                    .is_none_or(|set| set.iter().any(|n| n.eq_ignore_ascii_case(&g.name)))
            })
            .filter(|g| !q.with_desc || !g.desc.is_empty())
            .filter(|g| q.stats_allow(&g.name, now))
            .filter_map(|g| {
                if terms.is_empty() {
                    Some((Hit::NamePrefix, g))
                } else {
                    match_group(g, &terms).map(|h| (h, g))
                }
            })
            .collect();
        match q.sort {
            Sort::Posts => {
                // Posts first, hit kind only as tie-break. Relevance
                // bucketing looked right on paper but failed on real
                // data: "auto" put autodesk.autocad.* (name-prefix,
                // 44k posts) above alt.binaries.multimedia.motorsports
                // (synonym, 175M) - for binaries discovery, popularity
                // among the matches IS the relevance signal.
                hits.sort_by(|a, b| {
                    let ord = if q.desc_order {
                        b.1.posts.cmp(&a.1.posts)
                    } else {
                        a.1.posts.cmp(&b.1.posts)
                    };
                    ord.then(a.0.cmp(&b.0))
                });
            }
            Sort::Name => {
                hits.sort_by(|a, b| {
                    let ord = a.1.name.cmp(&b.1.name);
                    if q.desc_order { ord.reverse() } else { ord }
                });
            }
            // Sample-derived orderings. An unsampled group has no key, and
            // sorting it as zero would bury every unsampled group at one
            // end - which, early on, is nearly all of them. So the key is
            // Option and unsampled groups are pushed to the END in BOTH
            // directions: reversing "smallest first" should not promote
            // the groups we know nothing about to the top of the page.
            s => {
                let key = |g: &CatGroup| -> Option<u64> {
                    let st = q.stats?.get(&g.name)?;
                    Some(match s {
                        // Bytes per day: average post size times the
                        // measured rate. Not est_bytes, which scaled by
                        // the server's high-low article range and so
                        // counted decades of expired article numbers.
                        Sort::Size => (st.per_day * st.avg_bytes as f64) as u64,
                        Sort::AvgSize => st.avg_bytes,
                        Sort::Fresh => st.last_post.max(0) as u64,
                        // Rates are small and fractional; scale so the
                        // integer compare keeps two decimals of it.
                        _ => (st.per_day * 100.0) as u64,
                    })
                };
                hits.sort_by(|a, b| {
                    match (key(a.1), key(b.1)) {
                        (Some(x), Some(y)) => {
                            let ord = if q.desc_order { y.cmp(&x) } else { x.cmp(&y) };
                            // Article count breaks ties so equal-keyed
                            // groups (very common at avg_bytes 0) keep a
                            // stable, sensible order.
                            ord.then(b.1.posts.cmp(&a.1.posts))
                        }
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (None, None) => b.1.posts.cmp(&a.1.posts),
                    }
                });
            }
        }
        let total = hits.len();
        let page = hits
            .into_iter()
            .skip(q.offset)
            .take(q.limit.clamp(1, 500))
            .map(|(_, g)| g)
            .collect();
        (total, page)
    }

    /// Build from a LIST ACTIVE + LIST NEWSGROUPS pair. `prev` is the
    /// catalogue this fetch replaces: names it already knew keep their
    /// first_seen stamp, names it didn't are newly created groups and
    /// get stamped now. No prev (very first fetch) stamps nothing -
    /// the whole feed existing already isn't news.
    pub fn build(
        fetched_at: i64,
        active: Vec<nzbkit::nntp::ActiveGroup>,
        descs: Vec<(String, String)>,
        prev: Option<&Catalog>,
    ) -> Catalog {
        let dmap: std::collections::HashMap<String, String> = descs.into_iter().collect();
        let known: std::collections::HashMap<&str, i64> = prev
            .map(|p| {
                p.groups
                    .iter()
                    .map(|g| (g.name.as_str(), g.first_seen))
                    .collect()
            })
            .unwrap_or_default();
        let mut groups: Vec<CatGroup> = active
            .into_iter()
            .map(|a| {
                // Some providers answer LIST NEWSGROUPS with the group
                // name echoed as its own "description" - worthless, drop.
                let desc = dmap
                    .get(&a.name)
                    .filter(|d| !d.eq_ignore_ascii_case(&a.name))
                    .cloned()
                    .unwrap_or_default();
                let cat = classify(&a.name, &desc);
                let first_seen = match prev {
                    None => 0,
                    Some(_) => known.get(a.name.as_str()).copied().unwrap_or(fetched_at),
                };
                CatGroup {
                    posts: a.high.saturating_sub(a.low),
                    status: a.status,
                    name: a.name,
                    desc,
                    cat,
                    first_seen,
                }
            })
            .collect();
        groups.sort_by(|a, b| a.name.cmp(&b.name));
        groups.dedup_by(|a, b| a.name == b.name);
        Catalog { fetched_at, groups }
    }

    /// Persist as TSV next to the index db: `name \t posts \t desc`, one
    /// header line carrying the fetch time. Tabs/newlines can't appear in
    /// group names (ASCII-checked at parse) and are stripped from
    /// descriptions.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut out = String::with_capacity(self.groups.len() * 48);
        out.push_str(&format!("#nzbfast-groups\t3\t{}\n", self.fetched_at));
        for g in &self.groups {
            let desc: String = g
                .desc
                .chars()
                .map(|c| {
                    if c == '\t' || c == '\n' || c == '\r' {
                        ' '
                    } else {
                        c
                    }
                })
                .collect();
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                g.name, g.posts, g.first_seen, g.status, desc
            ));
        }
        // Write-then-rename so a crash mid-save never leaves a torn file.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, out)?;
        std::fs::rename(&tmp, path)
    }

    pub fn load(path: &Path) -> Option<Catalog> {
        let data = std::fs::read_to_string(path).ok()?;
        let mut lines = data.lines();
        let head = lines.next()?;
        let mut hf = head.split('\t');
        if hf.next() != Some("#nzbfast-groups") {
            return None;
        }
        let ver = hf.next().unwrap_or("1");
        let (v2, v3) = (ver == "2" || ver == "3", ver == "3");
        let fetched_at = hf.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let mut groups = Vec::new();
        for line in lines {
            let mut f = line.splitn(
                if v3 {
                    5
                } else if v2 {
                    4
                } else {
                    3
                },
                '\t',
            );
            let (Some(name), Some(posts)) = (f.next(), f.next()) else {
                continue;
            };
            let Ok(posts) = posts.parse::<u64>() else {
                continue;
            };
            let first_seen = if v2 {
                f.next().and_then(|s| s.parse().ok()).unwrap_or(0)
            } else {
                0
            };
            // v3 carries posting status between first_seen and desc.
            let status = if v3 {
                f.next().and_then(|s| s.chars().next()).unwrap_or('y')
            } else {
                'y'
            };
            let desc = f.next().unwrap_or("").to_string();
            let cat = classify(name, &desc);
            groups.push(CatGroup {
                name: name.to_string(),
                posts,
                desc,
                cat,
                first_seen,
                status,
            });
        }
        Some(Catalog { fetched_at, groups })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cg(name: &str, posts: u64, desc: &str) -> CatGroup {
        CatGroup {
            name: name.into(),
            posts,
            desc: desc.into(),
            cat: classify(name, desc),
            first_seen: 0,
            status: 'y',
        }
    }
    /// Query with every filter off - tests name only what they exercise.
    fn q<'a>(query: &'a str) -> Query<'a> {
        Query {
            q: query,
            new_only: false,
            binaries_only: false,
            min_posts: 0,
            only: None,
            cat: None,
            stats: None,
            kind: None,
            active_days: 0,
            with_desc: false,
            sort: Sort::Posts,
            desc_order: true,
            offset: 0,
            limit: 50,
        }
    }

    fn sample() -> Catalog {
        Catalog {
            fetched_at: 1700000000,
            groups: vec![
                cg("alt.binaries.teevee", 900_000, ""),
                cg("alt.binaries.moovee", 800_000, ""),
                cg("alt.binaries.multimedia.motorsports", 40_000, ""),
                cg("rec.autos.sport.f1", 5_000, "Formula 1 motor racing."),
                cg("alt.binaries.sounds.mp3", 700_000, "Music binaries."),
                cg("alt.binaries.e-books", 60_000, ""),
                cg("alt.binaries.mangled", 10, ""),
                cg("alt.binaries.anime", 300_000, ""),
                cg("uk.rec.cars.classic", 2_000, "Classic car discussion."),
            ],
        }
    }

    #[test]
    fn classify_by_segment_not_substring() {
        assert_eq!(classify("alt.binaries.anime", ""), Category::Anime);
        assert_eq!(classify("alt.binaries.mangled", ""), Category::Other);
        assert_eq!(
            classify("alt.binaries.multimedia.motorsports", ""),
            Category::Sports
        );
        assert_eq!(classify("alt.binaries.e-books", ""), Category::Books);
        assert_eq!(classify("rec.autos.sport.f1", ""), Category::Sports);
    }

    #[test]
    fn gary_types_auto_and_finds_motor_racing() {
        let c = sample();
        let (total, page) = c.query(&Query {
            cat: None,
            sort: Sort::Posts,
            desc_order: true,
            ..q("auto")
        });
        let names: Vec<&str> = page.iter().map(|g| g.name.as_str()).collect();
        assert!(names.contains(&"rec.autos.sport.f1"), "{names:?}");
        // Synonym expansion pulls in motorsports + cars groups too.
        assert!(
            names.contains(&"alt.binaries.multimedia.motorsports"),
            "{names:?}"
        );
        assert!(names.contains(&"uk.rec.cars.classic"), "{names:?}");
        assert_eq!(total, names.len());
    }

    #[test]
    fn description_matches_count() {
        let c = sample();
        let (_, page) = c.query(&Query {
            cat: None,
            sort: Sort::Posts,
            desc_order: true,
            ..q("formula")
        });
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].name, "rec.autos.sport.f1");
    }

    #[test]
    fn category_filter_and_posts_sort() {
        let c = sample();
        let (total, page) = c.query(&Query {
            cat: Some(Category::Sports),
            sort: Sort::Posts,
            desc_order: true,
            ..q("")
        });
        assert_eq!(total, 3);
        assert_eq!(page[0].name, "alt.binaries.multimedia.motorsports");
    }

    #[test]
    fn posts_rank_matches_regardless_of_hit_kind() {
        let c = sample();
        let (_, page) = c.query(&Query {
            cat: None,
            sort: Sort::Posts,
            desc_order: true,
            ..q("auto")
        });
        // The busiest matching group tops the list even when it matched
        // via a synonym - measured on real data, popularity among the
        // matches beats lexical closeness (autodesk.* vs motorsports).
        assert_eq!(page[0].name, "alt.binaries.multimedia.motorsports");
    }

    #[test]
    fn refresh_stamps_only_newly_appeared_groups() {
        use nzbkit::nntp::ActiveGroup;
        let ag = |n: &str| ActiveGroup {
            name: n.into(),
            high: 100,
            low: 1,
            status: 'y',
        };
        // First fetch: nothing is "new" (no prev).
        let first = Catalog::build(1000, vec![ag("a.one"), ag("a.two")], vec![], None);
        assert!(first.groups.iter().all(|g| g.first_seen == 0));
        // Refresh: a.three appears -> stamped; the others keep 0.
        let second = Catalog::build(
            2000,
            vec![ag("a.one"), ag("a.two"), ag("a.three")],
            vec![],
            Some(&first),
        );
        let by = |n: &str| second.groups.iter().find(|g| g.name == n).unwrap();
        assert_eq!(by("a.three").first_seen, 2000);
        assert_eq!(by("a.one").first_seen, 0);
        // new_only shows exactly the newcomer.
        let (total, page) = second.query(&Query {
            new_only: true,
            ..q("")
        });
        assert_eq!((total, page[0].name.as_str()), (1, "a.three"));
        // A third refresh keeps a.three's stamp.
        let third = Catalog::build(
            3000,
            vec![ag("a.one"), ag("a.two"), ag("a.three")],
            vec![],
            Some(&second),
        );
        let t3 = third.groups.iter().find(|g| g.name == "a.three").unwrap();
        assert_eq!(t3.first_seen, 2000);
    }

    #[test]
    fn binaries_only_and_min_posts_reduce_the_set() {
        let c = sample();
        let (bin, _) = c.query(&Query {
            binaries_only: true,
            ..q("")
        });
        // rec.autos.*, uk.rec.cars.* and it.* are not binary hierarchies.
        assert!(bin < c.groups.len(), "binaries filter did nothing");
        let (_, page) = c.query(&Query {
            binaries_only: true,
            ..q("")
        });
        assert!(
            page.iter()
                .all(|g| g.name.contains(".binaries.") || g.name.starts_with("alt.binaries.")),
            "{page:?}"
        );
        let (big, _) = c.query(&Query {
            min_posts: 500_000,
            ..q("")
        });
        let (all, _) = c.query(&q(""));
        assert!(big < all, "min_posts did nothing");
    }

    #[test]
    fn wildcards_match_whole_names() {
        assert!(glob_matches("alt.binaries.*", "alt.binaries.teevee"));
        assert!(glob_matches("*.mp3", "alt.binaries.sounds.mp3"));
        assert!(!glob_matches("alt.binaries.*", "rec.autos.sport.f1"));
        assert!(glob_matches("alt.?inaries.teevee", "alt.binaries.teevee"));
        let c = sample();
        let (_, page) = c.query(&q("*sounds*"));
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].name, "alt.binaries.sounds.mp3");
    }

    /// The exact matcher contract, pinned case by case. Written against
    /// the original backtracking implementation and left unchanged when
    /// that was replaced by the linear two-pointer one, so it is the
    /// proof the rewrite is behaviour-preserving.
    #[test]
    fn glob_semantics_are_pinned() {
        // Anchored to the whole name, and the empty pattern matches only
        // the empty name.
        assert!(glob_matches("", ""));
        assert!(!glob_matches("", "x"));
        assert!(!glob_matches("alt", "alt.binaries"));
        assert!(!glob_matches("binaries", "alt.binaries"));
        assert!(glob_matches("alt.binaries", "alt.binaries"));

        // `*` spans anything, including nothing, anywhere in the pattern.
        assert!(glob_matches("*", ""));
        assert!(glob_matches("*", "alt.binaries.teevee"));
        assert!(glob_matches("alt.*", "alt."));
        assert!(glob_matches("a*b*c", "abc"));
        assert!(glob_matches("a*b*c", "aXXbYYc"));
        assert!(!glob_matches("a*b*c", "acb"));
        assert!(glob_matches("*.*", "a.b"));
        assert!(!glob_matches("*.*", "ab"));
        // Runs of stars behave as one star.
        assert!(glob_matches("a**b", "ab"));
        assert!(glob_matches("a***b", "aXb"));
        assert!(glob_matches("**", ""));
        // A star must not be consumed as a literal when the NAME also
        // holds a star - it is always the wildcard.
        assert!(glob_matches("*x", "*ax"));

        // `?` is exactly one byte, never zero and never two...
        assert!(!glob_matches("?", ""));
        assert!(glob_matches("?", "a"));
        assert!(!glob_matches("?", "ab"));
        assert!(glob_matches("a?c", "abc"));
        assert!(!glob_matches("a?c", "ac"));
        assert!(glob_matches("alt.?inaries.teevee", "alt.binaries.teevee"));
        // ...a BYTE, so a two-byte character needs two of them. Group
        // names are ASCII in practice; this pins what happens if one
        // is not, rather than endorsing it.
        assert!(!glob_matches("?", "é"));
        assert!(glob_matches("??", "é"));

        // Literals compare ASCII-case-insensitively, in both directions.
        assert!(glob_matches("ALT.Binaries.*", "alt.binaries.teevee"));
        assert!(glob_matches("alt.binaries.TEEVEE", "ALT.BINARIES.teevee"));
        assert!(glob_matches("*MP3", "alt.binaries.sounds.mp3"));
        assert!(!glob_matches("alt.binaries.*", "rec.autos.sport.f1"));
    }

    /// Exhaustive equivalence against the original recursive matcher over
    /// every pattern of length ≤ 4 from {a, b, *, ?} and every name of
    /// length ≤ 4 from {a, A, b} - ~112k pairs, which covers the tangled
    /// star/?-interleavings a hand-written case list would miss.
    #[test]
    fn glob_agrees_with_the_reference_matcher() {
        /// The implementation that shipped before the rewrite. Correct,
        /// but exponential on adversarial patterns - which is why it is
        /// now confined to this test.
        fn reference(pat: &str, name: &str) -> bool {
            fn go(p: &[u8], n: &[u8]) -> bool {
                match p.first() {
                    None => n.is_empty(),
                    Some(b'*') => go(&p[1..], n) || (!n.is_empty() && go(p, &n[1..])),
                    Some(b'?') => !n.is_empty() && go(&p[1..], &n[1..]),
                    Some(c) => {
                        !n.is_empty() && n[0].eq_ignore_ascii_case(c) && go(&p[1..], &n[1..])
                    }
                }
            }
            go(pat.as_bytes(), name.as_bytes())
        }
        /// Every string of length ≤ `max` over `alpha`.
        fn words(alpha: &[char], max: usize) -> Vec<String> {
            let mut out = vec![String::new()];
            let mut frontier = vec![String::new()];
            for _ in 0..max {
                let mut next = Vec::new();
                for w in &frontier {
                    for c in alpha {
                        let mut s = w.clone();
                        s.push(*c);
                        next.push(s);
                    }
                }
                out.extend(next.iter().cloned());
                frontier = next;
            }
            out
        }
        let pats = words(&['a', 'b', '*', '?'], 4);
        let names = words(&['a', 'A', 'b'], 4);
        for p in &pats {
            for n in &names {
                assert_eq!(
                    glob_matches(p, n),
                    reference(p, n),
                    "glob_matches({p:?}, {n:?}) diverged from the reference"
                );
            }
        }
    }

    /// BUG (MEDIUM): the matcher used to backtrack exponentially, so a
    /// short pattern alternating `*` and `?` - which any authenticated
    /// user can type into the group search box - pinned a core for a very
    /// long time over the ~100k-group catalogue. Measured on the old
    /// implementation against a SINGLE name: 1.5 s at 8 `*?` pairs, 7 s
    /// at 9, 29 s at 10. This runs 24 pairs against a whole sample
    /// catalogue and must finish in milliseconds.
    #[test]
    fn adversarial_patterns_do_not_blow_up() {
        let c = sample();
        let pat = "*?".repeat(24) + "zzz"; // matches nothing: the full search
        let t = std::time::Instant::now();
        for g in &c.groups {
            assert!(!glob_matches(&pat, &g.name));
            // match_group's implicit `*t*` wrapping, which doubles the work.
            assert!(!glob_matches(&format!("*{pat}*"), &g.name));
        }
        // Two orders of magnitude of headroom over the ~1 ms this takes,
        // so a loaded CI box cannot flake it - anything exponential is
        // still hundreds of seconds away from passing.
        let el = t.elapsed();
        assert!(
            el < std::time::Duration::from_secs(2),
            "matcher took {el:?} - backtracking?"
        );
    }

    #[test]
    fn dotted_abbreviations_jump_to_the_group() {
        // MT-NewsWatcher's trick: a.b.te -> alt.binaries.teevee.
        assert!(abbrev_matches("a.b.te", "alt.binaries.teevee"));
        assert!(abbrev_matches("re.au", "rec.autos.sport.f1"));
        // Not an abbreviation: ordinary words must not trigger it, or
        // every dotted search would match half the server.
        assert!(!abbrev_matches("sounds", "alt.binaries.sounds.mp3"));
        assert!(!abbrev_matches("movies.hd", "alt.binaries.moovee"));
        let c = sample();
        let (_, page) = c.query(&q("a.b.te"));
        assert_eq!(page[0].name, "alt.binaries.teevee");
    }

    #[test]
    fn posting_status_survives_a_cache_roundtrip() {
        use nzbkit::nntp::ActiveGroup;
        let active = vec![
            ActiveGroup {
                name: "a.open".into(),
                high: 90,
                low: 1,
                status: 'y',
            },
            ActiveGroup {
                name: "a.readonly".into(),
                high: 90,
                low: 1,
                status: 'n',
            },
            ActiveGroup {
                name: "a.moderated".into(),
                high: 90,
                low: 1,
                status: 'm',
            },
        ];
        let c = Catalog::build(1000, active, vec![], None);
        let dir = std::env::temp_dir().join(format!("nzbfast-gstatus-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("groups.tsv");
        c.save(&p).unwrap();
        let back = Catalog::load(&p).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        let st = |n: &str| back.groups.iter().find(|g| g.name == n).unwrap().status;
        assert_eq!(
            (st("a.open"), st("a.readonly"), st("a.moderated")),
            ('y', 'n', 'm')
        );
    }

    #[test]
    fn only_filter_pages_correctly_past_the_limit_clamp() {
        // Regression: the subscribed-only view used to post-filter a page
        // that query() had already clamped to 500 rows, so a subscribed
        // group outside the top page vanished. The restriction has to be
        // applied INSIDE the query.
        let mut groups: Vec<CatGroup> = (0..600)
            .map(|i| cg(&format!("alt.binaries.g{i:04}"), 1_000_000 - i as u64, ""))
            .collect();
        // The one we care about is the LEAST posted, so a clamped page
        // sorted by posts desc could never contain it.
        groups.push(cg("alt.binaries.zzz.rare", 1, ""));
        let c = Catalog {
            fetched_at: 1000,
            groups,
        };
        let mine: std::collections::HashSet<String> =
            ["alt.binaries.zzz.rare".to_string()].into_iter().collect();
        let (total, page) = c.query(&Query {
            only: Some(&mine),
            ..q("")
        });
        assert_eq!(
            total, 1,
            "subscribed group outside the top page was dropped"
        );
        assert_eq!(page[0].name, "alt.binaries.zzz.rare");
    }

    #[test]
    fn save_load_roundtrip() {
        let c = sample();
        let dir = std::env::temp_dir().join(format!("nzbfast-groups-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("groups.tsv");
        c.save(&p).unwrap();
        let back = Catalog::load(&p).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(back.fetched_at, c.fetched_at);
        assert_eq!(back.groups.len(), c.groups.len());
        let f1 = back
            .groups
            .iter()
            .find(|g| g.name == "rec.autos.sport.f1")
            .unwrap();
        assert_eq!(f1.desc, "Formula 1 motor racing.");
        assert_eq!(f1.cat, Category::Sports);
    }

    /// A content filter must actually filter. The first implementation
    /// let unsampled groups through, which returned essentially the whole
    /// server for "video only" because almost nothing was profiled.
    #[test]
    fn content_filters_exclude_unprofiled_groups() {
        use crate::groupstats::{GroupStats, Kind, StatsCache};
        let c = sample();
        let mut sc = StatsCache::default();
        // Only one group has been looked at, and it is video.
        sc.map.insert(
            "alt.binaries.teevee".into(),
            GroupStats {
                sample_n: 10,
                kinds: [10, 0, 0, 0, 0, 0],
                ..Default::default()
            },
        );
        let (total, page) = c.query(&Query {
            stats: Some(&sc),
            kind: Some(Kind::Video),
            ..q("")
        });
        assert_eq!(total, 1, "unprofiled groups must not pass a content filter");
        assert_eq!(page[0].name, "alt.binaries.teevee");

        // With no filter on, every group is still listed.
        let (all, _) = c.query(&Query {
            stats: Some(&sc),
            ..q("")
        });
        assert_eq!(all, c.groups.len());
    }

    /// Reversing a sample-derived sort must not promote the groups we
    /// know nothing about to the top of the first page.
    #[test]
    fn unprofiled_groups_sort_last_in_both_directions() {
        use crate::groupstats::{GroupStats, StatsCache};
        let c = sample();
        let mut sc = StatsCache::default();
        sc.map.insert(
            "alt.binaries.e-books".into(),
            GroupStats {
                sample_n: 5,
                est_bytes: 10,
                ..Default::default()
            },
        );
        for desc in [true, false] {
            let (_, page) = c.query(&Query {
                stats: Some(&sc),
                sort: Sort::Size,
                desc_order: desc,
                ..q("")
            });
            assert_eq!(
                page[0].name, "alt.binaries.e-books",
                "the only profiled group must lead whichever way we sort (desc={desc})"
            );
        }
    }
}
