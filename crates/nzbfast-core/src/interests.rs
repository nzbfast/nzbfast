//! What the user asked the indexer to look for.
//!
//! The indexer indexes NOTHING until it is told to: `index_groups` ships
//! empty and an empty list means no scan. What was missing was a way to
//! say what you want without already knowing newsgroup names - and the
//! one shortcut that existed ("Start indexing TV & movies") picked two
//! groups on the user's behalf, which is exactly the shape of default
//! nobody asked for.
//!
//! An interest is the user's own words - "sport", "Linux ISOs" - and it
//! resolves to a SHORT, NAMED, AUDITABLE list of groups. Not a keyword
//! search, not "the busiest groups in this category": both of those pull
//! in obfuscated dump groups (the ".golf" family alone is billions of
//! posts of scrambled names) and neither can be shown to the user before
//! they agree to it. Every UI that offers an interest can therefore
//! print the exact groups it will scan, and does.
//!
//! Choosing nothing means nothing is indexed. That is not a default with
//! a trick in it - there is no fallback list anywhere behind it.
//!
//! Resolution keeps only the groups the user's own provider carries, so
//! a preset can never subscribe the scan loop to something that will
//! never answer.

/// One offered interest: a stable key (stored in settings, never
/// translated) and the groups it stands for.
pub struct Interest {
    /// Stored value. Lowercase, stable across releases and locales.
    pub key: &'static str,
    /// The groups this interest subscribes, most useful first. Curated by
    /// name rather than discovered by keyword, because the busiest match
    /// for almost every topic is an obfuscated dump group: "sport" ranked
    /// by volume is `alt.binaries.wtfnzb.golf` (4.5 billion posts of
    /// unreadable names) long before `alt.binaries.multimedia.sports`.
    /// A short honest list the user can read beats a long clever one.
    pub groups: &'static [&'static str],
    /// The same interest said in newznab's category numbers - the
    /// standard top-level thousands, so a subcategory is covered by its
    /// parent. This is what an interest means to a REFERENCE indexer,
    /// where we cannot ask by group: [`newznab_cats`] screens the seed
    /// lane's newest-listing sweep with it.
    ///
    /// It lives on the same struct as `groups` on purpose. They are two
    /// renderings of one answer, and kept in separate tables they would
    /// drift the first time an interest was added.
    ///
    /// 6000 (XXX) and 8000 (Other) are on no line here, and that is the
    /// point rather than an omission: neither has an interest that
    /// stands for it, so no spelling of the setting can ask for them.
    /// Read only by the indexer feature; the table itself is one
    /// answer and stays whole in a build without it, rather than
    /// growing ten `#[cfg]`s inside the literals below.
    ///
    /// It carried `#[cfg_attr(not(feature = "indexer"), expect(dead_code))]`
    /// while this module was part of the bin. That waiver DIED at the
    /// crate-split step 2 cut and nothing noticed until step 3 read a
    /// slim build's warnings: `dead_code` cannot fire on a `pub` field of
    /// a LIBRARY crate in any configuration, so the expectation was
    /// unfulfilled in the one build it was written for, which is what
    /// the FIFTEENTH gate's rule says to answer by deleting rather than
    /// by reverting. Nothing replaces it - there is no lint left to
    /// waive.
    pub cats: &'static [u32],
}

/// The offered set. Order is display order: the freely-distributable
/// option comes first because it is the one that needs no caveats.
pub const INTERESTS: &[Interest] = &[
    Interest {
        key: "linux",
        // Freely redistributable by licence. `alt.binaries.warez.linux`
        // is deliberately absent - it is a warez group that happens to
        // have "linux" in the name, and a keyword search would take it.
        groups: &[
            "alt.binaries.linux.iso",
            "a.b.cd.image.linux",
            "alt.binaries.cd.image.linux",
            "alt.binaries.linux",
        ],
        // PC: where a distribution image is filed. 8000 (Other)
        // would also carry some, and is deliberately not asked for -
        // it is the catch-all that would re-admit everything.
        cats: &[4000],
    },
    Interest {
        key: "movies",
        groups: &[
            "alt.binaries.moovee",
            "alt.binaries.movies",
            "alt.binaries.x264",
        ],
        cats: &[2000],
    },
    Interest {
        key: "tv",
        groups: &[
            "alt.binaries.teevee",
            "alt.binaries.tv",
            "alt.binaries.hdtv.x264",
            "alt.binaries.tvseries",
        ],
        cats: &[5000],
    },
    Interest {
        key: "sports",
        groups: &[
            "alt.binaries.multimedia.sports",
            "alt.binaries.sports",
            "alt.binaries.multimedia.motorsports",
            "alt.binaries.formula1",
            "alt.binaries.mma",
            "alt.binaries.pro-wrestling",
            "alt.binaries.multimedia.sports.boxing",
        ],
        // Sport is 5060, a TV subcategory.
        cats: &[5000],
    },
    Interest {
        key: "music",
        // Curated against MEASURED yield 2 Sep 2026, not group size
        // (research/INTEREST-PRESETS-BOOKS-MUSIC-ANIME-2026-09-02.md
        // sections 3 and 4). `complete_cd` was added and
        // `alt.binaries.music` dropped; the numbers are rows per 220,001
        // headers on one wire probe, then rows/visible over four scan
        // laps on a scratch index:
        //
        //   sounds.mp3.complete_cd   the group the census's 86%-readable
        //                            figure measured, 88% quoted, and
        //                            album-per-post rather than
        //                            one-card-per-track. Was absent.
        //   sounds.mp3               11.5 rows/1k; 5,610 rows, 63.8% visible
        //   sounds.lossless           0.9 rows/1k;   847 rows, 34.5% visible
        //   sounds.flac               0.0 rows/1k;    92 rows, 82.6% visible
        //   alt.binaries.music        0.0 rows/1k;     1 row,   0% readable
        //
        // `sounds.flac` READS as a dump on the wire (91% bare
        // single-token subjects) and is kept anyway, because the two
        // columns disagree and the right one is the second: it is
        // low-VOLUME, not unreadable, and the few rows it yields are the
        // best in this interest. Cutting it on the wire number alone
        // would be reading the wrong column. `alt.binaries.music` is the
        // opposite - 220,000 headers a lap for one row nothing could
        // read - so it goes.
        groups: &[
            "alt.binaries.sounds.mp3",
            "alt.binaries.sounds.mp3.complete_cd",
            "alt.binaries.sounds.flac",
            "alt.binaries.sounds.lossless",
        ],
        cats: &[3000],
    },
    Interest {
        key: "books",
        // The last two were missing until 16 Aug and are among the
        // biggest the interest can offer: on a live provider's own group
        // list `alt.binaries.mp3.abooks` carries 132M articles and
        // `alt.binaries.e-book.magazines` 76M, against 127M for the
        // headline `alt.binaries.e-book`. Named, not keyword-matched,
        // like every other line here.
        //
        // THAT WAS AN ARTICLE COUNT, AND THE YIELD IS A DIFFERENT
        // NUMBER. Measured 2 Sep 2026 over four scan laps: `abooks`
        // 1,570 rows of which 29 read as names and 0.0% clear the
        // wall's hide line, and `e-book.technical` 598 rows, 1.5%
        // readable, 0.7% visible. Both are hash-named. `e-book` itself
        // is 93.7% readable and 80.7% visible for comparison, so the two
        // are costing a lap 220,000 headers each for approximately
        // nothing today.
        //
        // They stay anyway, and the distinction is the reason. Hash-
        // NAMED is not the same as encrypted: these are real books whose
        // names a predb sweep or a spot promotion can still recover, and
        // dropping them would make that recovery unreachable for anyone
        // who picked this interest. The two anime groups dropped in the
        // same commit were `.enc` payloads, which no naming pass will
        // ever reach. Re-measure before revisiting; do not re-derive the
        // article count and conclude they are fine.
        groups: &[
            "alt.binaries.e-book",
            "alt.binaries.ebook",
            "alt.binaries.e-book.technical",
            "alt.binaries.e-book.magazines",
            "alt.binaries.audiobooks",
            "alt.binaries.mp3.audiobooks",
            "alt.binaries.mp3.abooks",
        ],
        cats: &[7000],
    },
    Interest {
        key: "comics",
        groups: &[
            "alt.binaries.comics",
            "alt.binaries.comics.dcp",
            "alt.binaries.pictures.comic-strips",
        ],
        // Comics is 7030, under Books.
        cats: &[7000],
    },
    Interest {
        key: "anime",
        // Two of the three offered groups were dumps and produced
        // nothing at all, measured 2 Sep 2026 over 220,001 headers each:
        // `alt.binaries.anime` is `<uuid>.7z.enc` posts (5 rows, 0%
        // readable) and `alt.binaries.multimedia.anime` is a hash dump
        // (1 row, 0% readable). Both dropped. They are not the same case
        // as a hash-NAMED group, which a later naming pass can still
        // light up: an encrypted payload has no name to recover.
        //
        // `highspeed` is the whole interest and carries it: 99.3%
        // readable, 77.7% below the wall's hide line once the fansub and
        // dashed-episode readings landed the same day.
        groups: &["alt.binaries.multimedia.anime.highspeed"],
        // Anime is 5070, under TV.
        cats: &[5000],
    },
    Interest {
        key: "games",
        groups: &["alt.binaries.games", "alt.binaries.games.xbox360"],
        // Console titles are 1000; PC games are 4050, under PC.
        cats: &[1000, 4000],
    },
    Interest {
        key: "apps",
        // Applications the user already licenses. `alt.binaries.warez`
        // and the pw-required/encrypted dumps are left out for the same
        // reason as above: an interest must be defensible in public.
        groups: &[
            "alt.binaries.software",
            "alt.binaries.apps",
            "alt.binaries.applications",
        ],
        cats: &[4000],
    },
];

/// Look one up by stored key.
pub fn get(key: &str) -> Option<&'static Interest> {
    INTERESTS.iter().find(|i| i.key == key)
}

/// Parse the stored `index_interests` value: a comma list of keys.
/// Unknown keys are DROPPED rather than rejected - a settings file
/// written by a newer build (or hand-edited) must not wedge startup, and
/// silently indexing something the user did not choose is the one
/// outcome this feature exists to prevent. Order and duplicates are
/// normalized to the offered order, so the value is comparable.
pub fn parse(s: &str) -> Vec<String> {
    let picked: Vec<&str> = s
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .collect();
    INTERESTS
        .iter()
        .filter(|i| picked.iter().any(|k| k.eq_ignore_ascii_case(i.key)))
        .map(|i| i.key.to_string())
        .collect()
}

/// Every group the chosen interests stand for, in order, without
/// duplicates. This is the FULL list, before any provider check - what a
/// UI shows when it says "these are the groups this will scan".
pub fn groups(keys: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for k in keys {
        let Some(i) = get(k) else { continue };
        for g in i.groups {
            if !out.iter().any(|o| o == g) {
                out.push((*g).to_string());
            }
        }
    }
    out
}

/// The chosen interests said in newznab category numbers, in
/// [`INTERESTS`] order, without duplicates.
///
/// The stored value can only ever SHRINK this. The walk is over the
/// built-in table filtered by `keys`, never over `keys` itself, so no
/// settings value - hand-edited, or written by a build that offers an
/// interest this one does not - can ADD a category to what a caller
/// asks a reference indexer for. That is the `SCOREBOARD_CATEGORIES`
/// discipline, for the same reason: these calls spend the user's own
/// API quota, and a stored string must not be able to spend more.
///
/// An empty result means "no screen", not "no categories": every
/// caller sends `cat=` only when this is non-empty, so an unanswered
/// or unrecognised setting leaves the request exactly as wide as it
/// was before the screen existed. Narrowing a user who never chose is
/// the one outcome this file exists to avoid.
#[cfg(feature = "indexer")]
pub fn newznab_cats(keys: &[String]) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    for i in INTERESTS {
        if !keys.iter().any(|k| k.eq_ignore_ascii_case(i.key)) {
            continue;
        }
        for c in i.cats {
            if !out.contains(c) {
                out.push(*c);
            }
        }
    }
    out
}

/// The groups to actually subscribe: those the user's provider carries.
/// `carried` answers "does this server have this group?" - resolution
/// against a catalogue the daemon already holds. A preset that named
/// four groups on a provider carrying one subscribes one, never four
/// dead names the scan loop would retry forever.
#[cfg(feature = "indexer")]
pub fn resolve(keys: &[String], carried: impl Fn(&str) -> bool) -> Vec<String> {
    groups(keys).into_iter().filter(|g| carried(g)).collect()
}

/// Add `resolved` to the groups already being scanned, preserving order
/// and never dropping one the user picked by hand. Returns the new list
/// and how many were added.
///
/// Test-only now: [`reconcile`] inlines this same add loop because it
/// also has to track which groups it owns, so nothing in the daemon
/// calls this. The tests below still pin the semantics through it.
#[cfg(test)]
#[cfg(feature = "indexer")]
pub fn merge(existing: &[String], resolved: &[String]) -> (Vec<String>, usize) {
    let mut out = existing.to_vec();
    let before = out.len();
    for g in resolved {
        if !out.iter().any(|e| e.eq_ignore_ascii_case(g)) {
            out.push(g.clone());
        }
    }
    let added = out.len() - before;
    (out, added)
}

/// Drop `unwanted` from the scan list. The mirror of the add loop in
/// [`reconcile`]: ticking
/// an interest starts scanning its groups, unticking stops. Only groups
/// the de-selected interest actually named are removed, so a group the
/// user typed in by hand survives unless it was also part of what they
/// just switched off.
#[cfg(feature = "indexer")]
pub fn remove(existing: &[String], unwanted: &[String]) -> (Vec<String>, usize) {
    let before = existing.len();
    let out: Vec<String> = existing
        .iter()
        .filter(|g| !unwanted.iter().any(|u| u.eq_ignore_ascii_case(g)))
        .cloned()
        .collect();
    let dropped = before - out.len();
    (out, dropped)
}

/// Reconstruct preset provenance for an install that predates it.
///
/// `reconcile` only removes groups it can prove a preset added, which is
/// right - it must never delete a group the user typed in themselves.
/// But installs created before provenance was recorded have an EMPTY
/// owned list, so unticking a preset removed nothing, and re-ticking did
/// not repair it either (an already-present group is skipped, so it never
/// enters the owned set). The feature was simply dead for them.
///
/// The reconstruction is deliberately conservative: a group counts as
/// preset-owned only if an applied preset resolves to it AND it is
/// actually being indexed. Anything else stays unowned, so the error
/// direction is "keeps a group the user might have wanted removed",
/// never "deletes a group they added by hand".
pub fn backfill_owned(applied_keys: &[String], indexed: &[String]) -> Vec<String> {
    groups(applied_keys)
        .into_iter()
        .filter(|g| indexed.iter().any(|h| h.eq_ignore_ascii_case(g)))
        .collect()
}

/// Apply an interest delta while preserving provenance. `owned` contains
/// only groups a previous interest merge actually appended; a group that
/// was already in `existing` was hand-picked and must survive when an
/// overlapping preset is unticked.
#[cfg(feature = "indexer")]
pub fn reconcile(
    existing: &[String],
    owned: &[String],
    stale: &[String],
    resolved: &[String],
) -> (Vec<String>, Vec<String>, usize, usize) {
    let removable: Vec<String> = stale
        .iter()
        .filter(|g| owned.iter().any(|o| o.eq_ignore_ascii_case(g)))
        .cloned()
        .collect();
    let (mut groups, dropped) = remove(existing, &removable);
    let mut next_owned: Vec<String> = owned
        .iter()
        .filter(|g| !removable.iter().any(|r| r.eq_ignore_ascii_case(g)))
        .cloned()
        .collect();
    let before = groups.len();
    for g in resolved {
        if groups.iter().any(|e| e.eq_ignore_ascii_case(g)) {
            continue;
        }
        groups.push(g.clone());
        next_owned.push(g.clone());
    }
    let added = groups.len() - before;
    (groups, next_owned, dropped, added)
}

#[cfg(test)]
mod tests {

    /// The screen the seed sweep sends is the user's own answer and
    /// nothing else: unknown keys drop, the order is the offered one so
    /// the request is comparable, and an unanswered setting asks for no
    /// screen at all rather than for nothing.
    #[cfg(feature = "indexer")]
    #[test]
    fn the_category_screen_can_only_ever_shrink() {
        use super::{newznab_cats, parse};
        assert_eq!(newznab_cats(&parse("movies,tv")), vec![2000, 5000]);
        // Offered order, not typed order, and duplicates collapse.
        assert_eq!(newznab_cats(&parse("tv,movies,tv")), vec![2000, 5000]);
        // A stored value cannot ADD a category: the walk is over the
        // built-in table, so junk that never reaches `parse` - a
        // hand-edited file, a key from a newer build - is still ignored.
        assert!(newznab_cats(&["6000".into(), "adult".into(), "xxx".into()]).is_empty());
        // Empty means NO SCREEN, and every caller sends `cat=` only for
        // a non-empty list. Narrowing a user who never chose is the one
        // outcome this must not have.
        assert!(newznab_cats(&parse("")).is_empty());
        assert!(newznab_cats(&parse("aliens")).is_empty());
        // Nothing on offer stands for 6000 (XXX) or 8000 (Other), so no
        // combination of interests can ask for either. 48% of the
        // unscreened sweep was 6000 (research/SEED-LANE-LIVE-2026-09-02.md
        // section 6c), and this is what makes that unreachable rather
        // than merely unasked-for.
        let every: Vec<String> = super::INTERESTS.iter().map(|i| i.key.to_string()).collect();
        let all = newznab_cats(&every);
        assert!(!all.is_empty(), "the interests must map to something");
        assert!(!all.contains(&6000) && !all.contains(&8000), "{all:?}");
        // And every interest says something, or it is invisible to the
        // screen while still subscribing groups.
        for i in super::INTERESTS {
            assert!(!i.cats.is_empty(), "interest {:?} names no category", i.key);
        }
    }

    /// Unticking a preset was dead on every install that predated
    /// provenance tracking: `owned` was empty, so `reconcile` found
    /// nothing removable, and re-ticking did not repair it either.
    #[cfg(feature = "indexer")]
    #[test]
    fn backfill_claims_preset_groups_but_never_hand_added_ones() {
        let keys = parse("tv");
        assert!(
            !keys.is_empty(),
            "the tv preset must exist for this test to mean anything"
        );
        let preset_groups = groups(&keys);
        assert!(!preset_groups.is_empty());

        // Indexing one preset group plus a group the user typed in.
        let mine = "alt.binaries.something.i.added".to_string();
        let indexed = vec![preset_groups[0].clone(), mine.clone()];
        let owned = backfill_owned(&keys, &indexed);

        assert!(
            owned.iter().any(|g| g == &preset_groups[0]),
            "preset group must be claimed"
        );
        assert!(
            !owned.iter().any(|g| g == &mine),
            "a hand-added group must never be claimed as preset-owned - claiming it \
             would let an untick delete something the user chose themselves"
        );

        // And with provenance restored, an untick now actually removes it.
        let (groups_after, _next_owned, dropped, _added) =
            reconcile(&indexed, &owned, &[preset_groups[0].clone()], &[]);
        assert_eq!(
            dropped, 1,
            "unticking must remove the preset group once owned is known"
        );
        assert!(
            groups_after.contains(&mine),
            "and must leave the hand-added one alone"
        );

        // The pre-backfill state is the bug: empty owned removes nothing.
        let (_, _, dropped_before, _) = reconcile(&indexed, &[], &[preset_groups[0].clone()], &[]);
        assert_eq!(
            dropped_before, 0,
            "this is what every upgrading install did"
        );
    }
    use super::*;

    #[test]
    fn keys_are_stable_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for i in INTERESTS {
            assert!(seen.insert(i.key), "duplicate interest key {}", i.key);
            assert!(!i.groups.is_empty(), "{} offers nothing", i.key);
            assert!(
                i.key.chars().all(|c| c.is_ascii_lowercase()),
                "{} must be a stable lowercase key",
                i.key
            );
        }
        // The freely-distributable option leads.
        assert_eq!(INTERESTS[0].key, "linux");
    }

    /// No interest may quietly subscribe a warez or obfuscated dump
    /// group: every offered list has to be defensible in public, and the
    /// UI prints it verbatim before the user agrees.
    #[test]
    fn offered_groups_are_defensible() {
        for i in INTERESTS {
            for g in i.groups {
                for bad in ["warez", "pw-required", "encrypt", "erotica", "xxx", "hack"] {
                    assert!(!g.contains(bad), "{} offers {g}", i.key);
                }
            }
        }
    }

    #[test]
    fn parsing_is_opt_in_only() {
        // Nothing chosen is the whole point: no fallback, no default.
        assert!(parse("").is_empty());
        assert!(parse("   ").is_empty());
        assert!(groups(&parse("")).is_empty());
        // An unknown key contributes nothing rather than wedging or,
        // worse, resolving to something.
        assert!(parse("not-a-thing").is_empty());
        assert_eq!(parse("sports,not-a-thing"), ["sports"]);
        // Case and spacing are forgiving; order and duplicates normalize
        // to the offered order so the value compares equal.
        assert_eq!(parse("TV, linux ,tv"), ["linux", "tv"]);
        assert_eq!(parse("tv,linux"), parse("linux,tv"));
    }

    #[cfg(feature = "indexer")]
    #[test]
    fn resolution_keeps_only_what_the_provider_carries() {
        let keys = parse("linux,sports");
        let all = groups(&keys);
        assert!(all.contains(&"alt.binaries.linux.iso".to_string()));
        assert!(all.contains(&"alt.binaries.multimedia.sports".to_string()));
        // A provider with two of them subscribes two.
        let carried = |g: &str| {
            matches!(
                g,
                "alt.binaries.linux.iso" | "alt.binaries.multimedia.sports"
            )
        };
        assert_eq!(
            resolve(&keys, carried),
            ["alt.binaries.linux.iso", "alt.binaries.multimedia.sports"]
        );
        // A provider carrying none subscribes none - never a dead name.
        assert!(resolve(&keys, |_| false).is_empty());
    }

    /// Unticking an interest stops scanning what it started, and
    /// nothing else. Without the second half of this, the only way to
    /// undo a choice would be to edit the group list by hand - and the
    /// point of the setting is that the user never has to.
    #[cfg(feature = "indexer")]
    #[test]
    fn unticking_removes_exactly_what_it_added() {
        let mine = vec!["alt.binaries.mine".to_string()];
        let (with_sport, _) = merge(&mine, &resolve(&parse("sports"), |_| true));
        assert!(with_sport.contains(&"alt.binaries.mma".to_string()));
        // Switching sport off leaves the hand-picked group alone.
        let (back, dropped) = remove(&with_sport, &groups(&parse("sports")));
        assert_eq!(back, mine);
        assert!(dropped >= 1);
        // Removing an interest that was never on changes nothing.
        let (same, dropped) = remove(&mine, &groups(&parse("comics")));
        assert_eq!(same, mine);
        assert_eq!(dropped, 0);
    }

    #[cfg(feature = "indexer")]
    #[test]
    fn merging_never_drops_a_hand_picked_group() {
        let mine = vec![
            "alt.binaries.mine".to_string(),
            "alt.binaries.linux.iso".to_string(),
        ];
        let (out, added) = merge(
            &mine,
            &["alt.binaries.linux.iso".into(), "alt.binaries.tv".into()],
        );
        assert_eq!(added, 1);
        assert_eq!(
            out,
            [
                "alt.binaries.mine",
                "alt.binaries.linux.iso",
                "alt.binaries.tv"
            ]
        );
        // Idempotent: applying the same resolution twice adds nothing.
        let (again, added) = merge(&out, &["alt.binaries.tv".into()]);
        assert_eq!(added, 0);
        assert_eq!(again, out);
        // Case differences are the same group to a news server.
        let (_, added) = merge(&out, &["ALT.BINARIES.TV".into()]);
        assert_eq!(added, 0);
    }

    #[cfg(feature = "indexer")]
    #[test]
    fn preset_provenance_spares_an_overlapping_manual_group() {
        let manual = vec!["alt.binaries.teevee".to_string()];
        let tv = resolve(&parse("tv"), |_| true);
        let (with_tv, owned, _, added) = reconcile(&manual, &[], &[], &tv);
        assert!(added > 0);
        assert!(
            !owned.contains(&manual[0]),
            "pre-existing group is not preset-owned"
        );
        let (after, owned, dropped, _) = reconcile(&with_tv, &owned, &groups(&parse("tv")), &[]);
        assert_eq!(after, manual);
        assert!(owned.is_empty());
        assert_eq!(dropped, added);
    }
}
