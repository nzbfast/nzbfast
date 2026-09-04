//! Giving every recovery-set target a destination no other target
//! shares - and SAYING SO when a declared name is the one that has to
//! move (wave-4 rows M4-99 and M4-80, 31 Aug 2026).
//!
//! Its own file, and the reason is the size gate: par2repair.rs sat at
//! 2,992 of its flat 3,000-line ceiling on 31 Aug 2026, so the eight
//! lines free there would not carry the report this row is about.
//! Hoisted whole rather than half, so the claim map and the naming that
//! reads it stay in one place. Reachable through `super::*` like every
//! other child here.

use super::*;

/// Give every colliding target a distinct path.
///
/// Two distinct FileDescs can sanitize to the SAME path (`a/b.bin` and
/// `a_b.bin` both land at `a_b.bin`; `movie.mkv.` and `movie.mkv` do
/// too - see the naming note below). Sharing a destination is silent
/// data loss: verifying, repairing, or landing the second removes the
/// first's (possibly intact) bytes and renames over them, yet the set
/// can still report `Repaired`. So a destination is never shared, and
/// each descriptor is verified and landed against its own file.
///
/// Claims are keyed by filesystem IDENTITY, not by string: on
/// macOS/Windows two descriptors that differ only in case name ONE
/// object, so an exact path compare would leave both undisambiguated
/// and let the second land over the first - the very loss this exists
/// to prevent.
///
/// WHY IT ALSO TALKS, which is the half that is new and the whole of
/// M4-99/M4-80. Those two rows are the TRAILING end of the trim M4-66
/// fixed at the leading end: `sanitize_filename` strips trailing dots
/// and trailing whitespace (ASCII space and U+00A0 alike) because
/// Windows FOLDS them - `evil. ` and `evil` are one file there - so two
/// FileDescs `Movie.mkv.` and `Movie.mkv`, or `Movie.mkv\u{a0}` and
/// `Movie.mkv`, arrive here as one canonical name. Unlike M4-66 that
/// cannot be repaired by making the sanitizer injective: mapping the
/// trailing run to `_` the way the leading run maps would yield
/// `Movie.mkv_`, an extension no `*arr` imports, which is worse than
/// the disambiguated name. `disk::tests::
/// the_trailing_trim_is_untouched_by_the_leading_dot_mapping` pins that
/// asymmetry deliberately.
///
/// So the collapse is unavoidable and the loop below is what stands
/// between it and a lost payload - MEASURED 31 Aug 2026 on a two-member
/// no-RAR post with one corrupt article, both rows: both payloads
/// survive, the bare twin keeps the canonical name and the decorated
/// twin lands on `<name>.dup-<fid>`. The rows predicted an overwrite
/// and there is none.
///
/// What there was none of either was any ACCOUNT of it. That name
/// appeared nowhere in the job log, at rc=0 - and worse, the log's own
/// story was left false: `[extract] renamed <posted> → Movie.mkv` was
/// printed while the file was still there, and this loop then moved it
/// aside without a word, so the last thing the log says about that
/// payload names a path it is not at. A user reading it has no way to
/// learn that a name they can see declared in the set could not be
/// honoured, or which file wears the machine name their `*arr` will
/// skip. That is M4-67's harm in a second form (the log telling the
/// same lie the listing does) and it is what this reports.
///
/// The report is CAPPED. A crafted set can declare many colliding
/// descriptors and a line each would bury the rest of the job's log, so
/// the first [`REPORT_CAP`] are named and the remainder counted.
///
/// STATED LIMIT: it is one line per collision per PASS, and a job that
/// repairs a set twice therefore prints it twice - measured 31 Aug 2026
/// at exactly two on the `e2e_norar3` damaged twins, one for the
/// individually-verified publish pass and one for the repair proper.
/// Deduplicating inside this function cannot fix that (each pass builds
/// its own `targets` and neither can see the other) and a process-global
/// latch would be wrong for a second reason: it is per-directory state
/// living for the life of the process, so a second job colliding on the
/// same name would be reported once between them.
///
/// SAID ONCE, NOW, BY THE CALLER (1 Sep 2026): `repair-report-name-vs-path-render`
/// closed the gap this paragraph used to end on. `nzbfast::repair::nativepass`
/// reads exactly the pair this paragraph names - [`RepairReport::path`]
/// beside `name` on each [`FileRepair`] - off every pass's report,
/// dedupes by content (two passes over one set agree on every entry,
/// X-8), and `get::settle::repair::disk_repair_declined_sets` renders the
/// result once the whole call for that set has returned, regardless of
/// how many passes it took. That is where a HUMAN reads this now.
///
/// This function's own line is downgraded to [`debug!`] rather than
/// deleted, for the reason its neighbour `report`'s doc comment gives:
/// it is nzbkit's own log and the caller above is not its only reader -
/// `examples/par2_repair_dir.rs` calls `repair_dir` directly with no
/// nzbfast in front of it, and at `warn!` that caller got the identical
/// double-print this paragraph used to describe with nothing above it to
/// collapse the two. `RUST_LOG=debug` still surfaces the per-pass detail
/// (which claimant this set itself made) that the once-per-job line does
/// not carry. The e2e pins now assert the CALLER'S line, exactly once;
/// see `e2e_norar3::assert_twin_survived`.
pub(super) fn disambiguate_colliding_targets(
    targets: &mut [Target],
    contested: &HashSet<String>,
    fold: bool,
    dir: &Path,
) {
    // Identity key → the name the descriptor holding it declared, so a
    // collision can name BOTH sides rather than only the one that moved.
    // A map and not a set for that reason alone; membership is
    // unchanged, which is why the insert is guarded by `contains_key`
    // rather than written as `insert(..).is_none()` - a `HashMap`
    // insert REPLACES where `HashSet::insert` leaves the original
    // alone, and which declaration is reported has to be the first one.
    let mut claimed: HashMap<PathBuf, String> = HashMap::new();
    let mut moved: Vec<(String, String, Option<String>)> = Vec::new();
    for t in targets.iter_mut() {
        // A name some OTHER set in this directory claims for DIFFERENT
        // content is disambiguated on its first appearance here, not
        // just on a repeat. The loop only ever sees one set - `want`
        // dropped every foreign packet long before this - so two sets
        // each declaring a file that sanitizes to `a_b.bin` both chose
        // that path, the second renamed its verified rebuild over the
        // first's verified bytes, and both verdicts still came back
        // green. Keyed by file_id, so the two sets independently agree
        // on who gets which path and a retried attempt picks the same
        // one again.
        let contested = contested.contains(&name_identity_key(fold, &t.file.name));
        let here = path_identity_key(fold, &t.path);
        // Who took this path first, for the message. `None` is the
        // CONTESTED case and only that case: nothing in this set ever
        // claimed the name, so there is no second declaration to print -
        // the descriptor holding it belongs to a different set in the
        // same directory, which this pass never sees.
        //
        // Read here rather than after the branch so the claim below and
        // the message read ONE lookup, and because `holder.is_none()` is
        // the membership test the claim needs anyway.
        let holder = claimed.get(&here).cloned();
        if !contested && holder.is_none() {
            claimed.insert(here, t.file.name.clone());
            continue;
        }
        // Composed onto the out-RELATIVE name and re-capped, not pushed
        // onto the joined path: `t.path`'s leaf is a `sanitize_out_name`
        // result and is routinely AT the 255-byte component cap -
        // capping is what produced it - so a raw 17-byte `.dup-<fid>`
        // yields a 272-byte component no filesystem here will create,
        // and the repaired file has nowhere to land. The cap goes on the
        // COMPOSED name because this path is also the claim key
        // (`claimed` is keyed on it and the verify pass reads it back);
        // shortening it at the write would split the two. Distinctness
        // across `suffix` rests on `cap_component`'s hash tag, which is
        // exactly what that function's tag is for - the tail is what
        // truncation removes here, where a prefix survives it.
        let base = crate::disk::out_name_of(dir, &t.path);
        let mut suffix = 0u32;
        loop {
            let fid: String = t
                .file
                .file_id
                .iter()
                .take(6)
                .map(|b| format!("{b:02x}"))
                .collect();
            let tag = if suffix == 0 {
                format!(".dup-{fid}")
            } else {
                format!(".dup-{fid}-{suffix}")
            };
            let alt = crate::disk::join_out_name(
                dir,
                &crate::disk::sanitize_out_name(&format!("{base}{tag}")),
            );
            let key = path_identity_key(fold, &alt);
            if let std::collections::hash_map::Entry::Vacant(e) = claimed.entry(key) {
                e.insert(t.file.name.clone());
                moved.push((
                    t.file.name.clone(),
                    crate::disk::out_name_of(dir, &alt),
                    holder,
                ));
                t.path = alt;
                break;
            }
            suffix += 1;
        }
    }
    report(&moved, dir);
}

/// How many colliding descriptors are named individually before the
/// rest are counted. Eight is the same order as the other bounded
/// reports in this file and leaves the surrounding repair log readable
/// on a set crafted to collide on every member.
const REPORT_CAP: usize = 8;

/// Say which declared names could not be honoured, and what they
/// landed as instead.
///
/// `debug`, not `warn`, since 1 Sep 2026 (`repair-report-name-vs-path-render`).
/// The reason to say this at all is still the one `get::publishplan`
/// gives at its own aside: the file is on disk and no payload is lost,
/// but the name it wears is not the one anything downstream is looking
/// for, so a user whose `*arr` skips it needs an account of why. What
/// changed is WHERE that account is aimed - this function's own module
/// doc comment has the pass-count defect this fixes and why the fix
/// belongs in the caller rather than here. `nzbfast` is the caller for
/// every job a user actually runs, and it now renders that account once
/// per job off [`RepairReport::path`]; a `warn!` here under that caller
/// repeated the same fact once per PASS with nothing above it to
/// collapse the two. A caller with no such account of its own -
/// `examples/par2_repair_dir.rs` among them - still reaches this at
/// `RUST_LOG=debug`.
fn report(moved: &[(String, String, Option<String>)], dir: &Path) {
    for (declared, landed, holder) in moved.iter().take(REPORT_CAP) {
        match holder {
            // Same set: both declarations are in hand, so name both -
            // "these two names are one name here" is the fact, and
            // neither name on its own says it.
            Some(other) => debug!(
                target: "repair",
                "{declared:?} and {other:?} are two files in this recovery set \
                 but one name on disk, so {declared:?} landed as {landed:?} - \
                 both payloads are here, but that is not the name the set \
                 declared for it"
            ),
            // The name is claimed by a DIFFERENT set in this directory
            // (`DirContext::contested`), whose descriptors this pass
            // never sees, so there is no second name to print.
            None => debug!(
                target: "repair",
                "{declared:?} is a name another recovery set in {} claims for \
                 different content, so it landed as {landed:?} - the payload \
                 is here, but that is not the name the set declared for it",
                dir.display()
            ),
        }
    }
    if moved.len() > REPORT_CAP {
        debug!(
            target: "repair",
            "{} further declared name(s) in this set collapse onto names \
             already taken and landed under disambiguated ones",
            moved.len() - REPORT_CAP
        );
    }
}
