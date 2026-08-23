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
    },
    Interest {
        key: "movies",
        groups: &[
            "alt.binaries.moovee",
            "alt.binaries.movies",
            "alt.binaries.x264",
        ],
    },
    Interest {
        key: "tv",
        groups: &[
            "alt.binaries.teevee",
            "alt.binaries.tv",
            "alt.binaries.hdtv.x264",
            "alt.binaries.tvseries",
        ],
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
    },
    Interest {
        key: "music",
        groups: &[
            "alt.binaries.sounds.mp3",
            "alt.binaries.sounds.flac",
            "alt.binaries.sounds.lossless",
            "alt.binaries.music",
        ],
    },
    Interest {
        key: "books",
        // The last two were missing until 16 Aug and are among the
        // biggest the interest can offer: on a live provider's own group
        // list `alt.binaries.mp3.abooks` carries 132M articles and
        // `alt.binaries.e-book.magazines` 76M, against 127M for the
        // headline `alt.binaries.e-book`. Named, not keyword-matched,
        // like every other line here.
        groups: &[
            "alt.binaries.e-book",
            "alt.binaries.ebook",
            "alt.binaries.e-book.technical",
            "alt.binaries.e-book.magazines",
            "alt.binaries.audiobooks",
            "alt.binaries.mp3.audiobooks",
            "alt.binaries.mp3.abooks",
        ],
    },
    Interest {
        key: "comics",
        groups: &[
            "alt.binaries.comics",
            "alt.binaries.comics.dcp",
            "alt.binaries.pictures.comic-strips",
        ],
    },
    Interest {
        key: "anime",
        groups: &[
            "alt.binaries.anime",
            "alt.binaries.multimedia.anime",
            "alt.binaries.multimedia.anime.highspeed",
        ],
    },
    Interest {
        key: "games",
        groups: &["alt.binaries.games", "alt.binaries.games.xbox360"],
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
