//! Composing a DISAMBIGUATING tag onto an output name that is already
//! at the caps.
//!
//! [`super::sanitize_out_name`] caps every component at
//! [`super::MAX_COMPONENT`] and the whole name at [`super::MAX_TOTAL`],
//! so a long posted name comes back at EXACTLY the component cap -
//! capping is what produced it. Four sites then take that output, a
//! name two claimants both want, and make it LONGER to tell the two
//! apart. Measured on APFS 31 Aug 2026: a 255-byte component creates
//! and 256 is `ENAMETOOLONG` for both `mkdir` and `create`, so a
//! 4-byte `007-` on a name at the cap is a name that cannot be
//! written at all.
//!
//! In a child file rather than inline in `relpath.rs` for the ordinary
//! size-gate reason (that file sits inside 3% of its ceiling), and the
//! tests come with it.

/// The disambiguated spelling of an out-relative `name` that another
/// claimant already holds: `{slot:03}-{name}`, or
/// `{slot:03}-{retry}-{name}` for the `retry`'th further attempt -
/// CAPPED, so what comes back is a name the filesystem will create.
///
/// # The convention, in ONE place
///
/// Three sites spelled this `format!` by hand - the PAR2
/// verified-name publish's claim map, the extractor's own output-name
/// claim, and the journal's `S`-line destination - and a user looking
/// at a finished directory has to see ONE convention whichever path
/// renamed the file. They were hand-copied siblings, which is how the
/// missing cap below came to be missing in all three at once.
///
/// # Why the CAP goes here and not at the write
///
/// Each of these strings is an IDENTITY KEY as much as a path: the
/// claim map, the journal's `used_names` and the extractor's
/// `names_taken` all compare it, and the reload path runs
/// [`super::sanitize_out_name`] over the journal's copy again. Capping
/// at the write shortens the PATH and not the KEY, so the two names
/// part - and two names that resolve to one file stop being seen as
/// one, race on the pool, and each verifies only its own CRC over
/// interleaved bytes. The cap therefore belongs where the composed
/// name is BUILT, which is here, and the result is a fixed point of
/// [`super::sanitize_out_name`] so every later reader computes the
/// same string.
///
/// # Why not [`super::cap_shared_stem`]
///
/// It is the door for this SHAPE - cap a stem, holding back room for
/// what the caller will compose onto it - and it does not fit this
/// caller, for two reasons that are both about the UNPREFIXED name.
///
///  * The bare `name` is returned unchanged when it is free, and it is
///    the canonical name the post gives the file. A reserve would
///    shorten it too, renaming files that work today - where
///    `smart::filing`'s sidecars, the shared-stem caller, WANT every
///    composed name to share one shortened stem, because the pairing
///    IS the shared prefix.
///  * `retry` is unbounded, so "the longest tail" is not a quantity
///    this caller has.
///
/// # It changes no name that works today
///
/// [`super::sanitize_out_name`] is idempotent (pinned in
/// `no_component_of_any_output_can_exceed_the_cap`, which the journal
/// already depends on by construction), so for a composed name inside
/// both caps this is the plain `format!` byte for byte. Only a name
/// the write would have refused moves.
///
/// # Termination, which the callers' loops rest on
///
/// Successive `retry` values must give distinct strings or a claim
/// loop spins. They do, and by construction rather than by hash:
/// [`super::cap_component`] truncates the TAIL and keeps the FRONT,
/// its budget never falls below 225 bytes, and the prefix is at bytes
/// 0..=5 - so `001-` and `001-1-` survive every shortening this can
/// apply. The flatten fallback maps separators to `_` and is
/// front-preserving too.
pub fn disambiguated_out_name(name: &str, slot: usize, retry: usize) -> String {
    let composed = if retry == 0 {
        format!("{slot:03}-{name}")
    } else {
        format!("{slot:03}-{retry}-{name}")
    };
    super::sanitize_out_name(&composed)
}

#[cfg(test)]
mod tests {
    use super::super::{MAX_COMPONENT, MAX_TOTAL, sanitize_out_name};
    use super::*;

    /// The whole point: a name at the cap plus a prefix is a name no
    /// filesystem will create, and this is the door that stops it
    /// leaving here that way.
    #[test]
    fn a_prefix_on_a_name_already_at_the_cap_stays_within_it() {
        let at_cap = sanitize_out_name(&"y".repeat(400));
        assert_eq!(at_cap.len(), MAX_COMPONENT, "the premise moved");
        for retry in [0usize, 1, 9, 10, 4096] {
            let out = disambiguated_out_name(&at_cap, 7, retry);
            assert!(
                out.len() <= MAX_TOTAL,
                "retry {retry} -> {} bytes in all",
                out.len()
            );
            for c in out.split('/') {
                assert!(
                    c.len() <= MAX_COMPONENT,
                    "retry {retry} -> component of {} bytes",
                    c.len()
                );
            }
        }
    }

    /// The prefix lands on the FIRST component, so a tree name
    /// disambiguates by moving its whole subtree - and the leaf and the
    /// depth are untouched however long the first component was.
    #[test]
    fn a_tree_name_keeps_its_tree_and_its_leaf() {
        let tree = sanitize_out_name(&format!("{}/child.bin", "y".repeat(400)));
        let (first, rest) = tree.split_once('/').expect("the premise moved");
        assert_eq!(first.len(), MAX_COMPONENT);
        assert_eq!(rest, "child.bin");
        let out = disambiguated_out_name(&tree, 1, 0);
        let (of, or) = out.split_once('/').expect("the tree was flattened");
        assert!(of.starts_with("001-"));
        assert!(of.len() <= MAX_COMPONENT, "{} bytes", of.len());
        assert_eq!(or, "child.bin", "the leaf must not move");
    }

    /// Nothing that works today changes: inside both caps this is the
    /// plain `format!`, byte for byte, which is what keeps every
    /// ordinary post's disambiguated name exactly what it always was.
    #[test]
    fn an_ordinary_name_is_the_plain_format_byte_for_byte() {
        for name in ["movie.mkv", "VIDEO_TS/VTS_01_1.VOB", "a/b/c.bin"] {
            assert_eq!(disambiguated_out_name(name, 0, 0), format!("000-{name}"));
            assert_eq!(disambiguated_out_name(name, 12, 3), format!("012-3-{name}"));
        }
    }

    /// A claim loop increments `retry` until the name is free, so two
    /// retries must never spell one name - including once the cap has
    /// truncated both.
    #[test]
    fn every_retry_of_one_name_is_a_distinct_string() {
        let at_cap = sanitize_out_name(&"y".repeat(400));
        let tree = sanitize_out_name(&format!("{}/{}", "y".repeat(400), "z".repeat(400)));
        for base in [&at_cap, &tree] {
            let mut seen = std::collections::HashSet::new();
            for retry in 0..64usize {
                assert!(
                    seen.insert(disambiguated_out_name(base, 3, retry)),
                    "retry {retry} repeats an earlier name, so a claim loop spins"
                );
            }
            // And a different SLOT is a different name too - the claim
            // maps are shared across slots.
            assert_ne!(
                disambiguated_out_name(base, 3, 0),
                disambiguated_out_name(base, 4, 0)
            );
        }
    }

    /// The result is a fixed point of the sanitizer, which is what lets
    /// the journal write it into an `S` record and re-read it through
    /// `sanitize_out_name` on load without the name moving.
    #[test]
    fn the_result_is_a_fixed_point_so_a_reloaded_record_does_not_move() {
        for base in [
            "movie.mkv".to_string(),
            sanitize_out_name(&"y".repeat(400)),
            sanitize_out_name(&format!("{}/child.bin", "y".repeat(400))),
            sanitize_out_name(&format!("a/{}/{}", "y".repeat(600), "z".repeat(600))),
        ] {
            for retry in [0usize, 2] {
                let out = disambiguated_out_name(&base, 5, retry);
                assert_eq!(out, sanitize_out_name(&out), "{base:?} retry {retry}");
            }
        }
    }

    /// Not a byte count in the abstract: the filesystem takes it. This
    /// is the assertion that fails on the tree this door was written
    /// for, where the composed name reached `renameat`/`openat` raw.
    #[test]
    fn the_filesystem_creates_every_name_this_hands_back() {
        let root = std::env::temp_dir().join(format!(
            "nzbfast-disambig-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        for (i, base) in [
            sanitize_out_name(&"y".repeat(400)),
            sanitize_out_name(&format!("{}/child.bin", "y".repeat(400))),
            sanitize_out_name(&format!("{}/{}", "y".repeat(400), "z".repeat(400))),
        ]
        .into_iter()
        .enumerate()
        {
            // A root PER CASE, because the cases collide with each other
            // by construction and that collision is not what is being
            // measured here: every one of them caps the same 400-byte
            // stem, so case 0 wants `009-<stem>` to be a FILE and cases
            // 1 and 2 want it to be a DIRECTORY. That topology is real -
            // it is W4-17 - and the claim maps are what resolve it; this
            // test asks only whether the filesystem takes each name.
            let root = root.join(format!("case{i}"));
            std::fs::create_dir_all(&root).unwrap();
            for retry in [0usize, 7] {
                let out = disambiguated_out_name(&base, 9, retry);
                let path = super::super::prepare_out_path(&root, &out).unwrap();
                std::fs::write(&path, b"x")
                    .unwrap_or_else(|e| panic!("{out:?} is unwritable: {e}"));
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
