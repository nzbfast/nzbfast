//! The obfuscated-RAR arm: `Rar!`-magic files whose NAMES carry no set
//! and no order, grouped into their original volume sets by header
//! continuity rather than by filename, extracted, and swept.
//!
//! Split out of `unpack.rs` (TODO 106) - it is one self-contained family
//! with one entry point, [`extract_obfuscated_rar`].

use super::*;

/// RAR volumes whose names carry NO recognized RAR extension but which
/// start with the Rar! magic (obfuscated usenet posts strip extensions and
/// rename volumes to hex). Only consulted when no normally-named set was
/// found, so this never shadows the fast name-based path. A named payload
/// file (`.cbr`) is excluded: its bytes are a RAR, but the file IS the
/// deliverable, and this collector's caller deletes what it spends.
pub(crate) fn collect_obfuscated_rar_volumes(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        let path = e.path();
        if e.file_type().is_ok_and(|t| t.is_file())
            && (!looks_like_named_rar(&path) || rar_name_carries_no_set(&path))
            && !nzbkit::extract::is_final_file(&path)
            && rar_magic(&path)
        {
            out.push(path);
        }
    }
    Ok(out)
}

/// The RAR5+ volume number from a parsed archive header, when present.
/// RAR5 volume sets carry it; RAR 1.5-4.x and single archives do not.
///
/// **On this path a missing number means the set cannot be ordered, and
/// obfuscated RAR4 volume sets are therefore not supported.** That is a
/// measured decision, not an oversight, so do not "fix" it by widening
/// the match arm - there is nothing to widen it to.
///
/// For a NAMED set the missing number costs nothing: `.partNN.rar` and
/// `.rNN` sort by filename into volume order, and
/// `rar_name_carries_no_set` keeps exactly those on the fast named path.
/// This collector exists for the opposite case - hash names carrying no
/// set and no order - so filename order is not available to fall back
/// on, and RAR4 headers carry no substitute. Measured 22 Aug 2026 over a
/// four-volume stored set written by `rars::rar15_40::write_stored_volumes`:
/// the two INTERIOR volumes are identical in every header field the
/// parser exposes - same main flags, same member name, both
/// `is_split_before` and `is_split_after`, same `pack_size`, `unp_size`,
/// `file_time`, `attr` - and differ only in `file_crc`, which on a
/// non-final RAR4 fragment is the CRC32 of that fragment's OWN packed
/// bytes. That identifies a piece; it does not place one. The ends are
/// findable (`MHD_FIRSTVOLUME` and the first member's `is_split_before`
/// name the head, a last member that is not `is_split_after` names the
/// tail) but nothing names volume 3 of 25.
///
/// Continuity linkage across a volume boundary is family-independent and
/// WOULD group such a set, but grouping is not ordering: a set whose one
/// spanning member covers every volume gives all interior volumes the
/// same split-before name, so each attach step is ambiguous and a rule
/// that declines on ambiguity attaches nothing. It buys only the
/// two-volume case and the rarer multi-member case, and neither is what
/// the field posts. `research/CENSUS-REWEIGHT-2026-08-22.md` §2c puts
/// `obfuscated_noext` at 2.20% of index bytes (4.13% of the 1-5 GB
/// stratum, 0.53% at 20-60 GB, none above) and measures a median of 25
/// volumes per multi-volume set at 1-5 GB (p99 144), rising to a median
/// of 113 above 60 GB; §4a puts all RAR4, store and encrypted together,
/// at ~4.3%. Nobody has measured the INTERSECTION directly, so read the
/// resulting tenth of a percent as marginals multiplied rather than as a
/// count - but the volume-count median is measured, and it says the
/// two-volume shape linkage could order is not the shape being posted.
///
/// What such a set does today is verified, not inferred, and it is safe:
/// every volume takes the numberless door below and becomes its own
/// single-volume set, the head volume fails and carries the job's
/// verdict, the continuations are recorded as strays, no partial payload
/// is written and every volume stays on disk for PAR2, `.rev` or a
/// retry. `obfuscated_rar4_set_fails_cleanly_and_keeps_every_volume` in
/// `repair/repair_tests.rs` pins that, and `note_unorderable_rar4`
/// prints the reason where a user would otherwise read "missing first
/// part" and go looking for a file that is right there.
pub(crate) fn archive_volume_number(archive: &rars::Archive) -> Option<u64> {
    match archive {
        rars::Archive::Rar50Plus(a) => a.main.volume_number,
        _ => None,
    }
}

/// Say once, in plain words, that a directory of obfuscated RAR4
/// volumes cannot be ordered - and therefore why the per-set messages
/// that follow are about a limit of the format rather than about a file
/// the user is missing.
///
/// Worth a line of its own because the honest per-set message is
/// actively misleading here: a continuation volume is reported as "a
/// mid-set volume with no first part on disk", and on THIS shape the
/// first part IS on disk. We simply cannot tell which of the volumes it
/// is. See `archive_volume_number` for the measurement behind that.
///
/// Deliberately narrow. It wants two or more RAR4 volume-set members
/// (`MHD_VOLUME`, so a standalone RAR4 archive never qualifies) sitting
/// in a directory the partition already broke into several sets: one
/// such volume beside sets that DID group is an ordinary stray, and
/// telling its owner about RAR4 ordering would be noise.
fn note_unorderable_rar4(sets: &[Vec<(PathBuf, rars::Archive)>]) {
    if sets.len() < 2 {
        return;
    }
    let rar4_volumes = sets
        .iter()
        .flatten()
        .filter(|(_, a)| matches!(a, rars::Archive::Rar15To40(a) if a.main.is_volume()))
        .count();
    if rar4_volumes < 2 {
        return;
    }
    warn!(
        target: "extract",
        "{rar4_volumes} of these are RAR4 volumes. RAR4 headers carry no volume \
         number, and these names carry no order either, so the set cannot be put back \
         in order and cannot be unpacked. Every volume is left on disk untouched; a \
         message below about a missing first part means this, not a missing file."
    );
}

/// What one run of [`extract_obfuscated_rar`] made of a directory.
///
/// Three facts rather than one bool: the pass is handed every
/// `Rar!`-magic file in the directory, and a directory can hold a file
/// that is a RAR volume by magic and is nobody's payload - see `stray`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ObfReport {
    /// At least one member-bearing set extracted. A memberless set (a
    /// `.rev`-shaped recovery volume) extracts as a no-op and publishes
    /// nothing, so it does not count - else it would forgive a stray
    /// fragment in `ok` (Codex F-23, 22 Aug 2026).
    pub(crate) produced: bool,
    /// A set with a usable head could not be unpacked. Always the job's
    /// verdict: that IS a payload we failed to deliver.
    pub(crate) failed: bool,
    /// The MID-SET FRAGMENTS this pass refused: volumes whose first
    /// member is `is_split_before`, so each continues a member that
    /// began in a volume that is not on disk. Never the job's verdict on
    /// their own - see the note on the failure arm.
    ///
    /// Carried as PATHS, not a bool, because forgiving a file's failure
    /// obliges us to keep every later pass off it too: the level's
    /// spent-intermediate sweep deletes the archives it was handed once
    /// the level succeeds, and this arm has just made a level succeed
    /// with a file in it that nothing opened.
    pub(crate) strays: Vec<PathBuf>,
}

impl ObfReport {
    /// The bool the two payload-path callers (`repair::reextract_dir`,
    /// `rarfix`) read: did the pass deliver what was packed here? A
    /// stray beside a set that extracted is forgiven, as in the nested
    /// pass; a directory whose obfuscated content was NOTHING BUT
    /// fragments is not - on those two paths those volumes are the job's
    /// own payload, so "not one usable set could be formed from them"
    /// has to stay a failure.
    pub(crate) fn ok(&self) -> bool {
        !self.failed && (self.produced || self.strays.is_empty())
    }
}

/// Extract obfuscated RAR volumes: parse each candidate, PARTITION the
/// volumes into their original sets (a directory can hold several
/// interleaved obfuscated sets - the volumes carry no usable names, so
/// grouping runs on headers: volume numbers plus split-member name
/// continuity across volume boundaries), order each set by header volume
/// number, and extract every set. See [`ObfReport`] for the verdict.
pub(crate) fn extract_obfuscated_rar(
    dir: &std::path::Path,
    candidates: &[PathBuf],
    password: Option<&str>,
    depth: usize,
) -> ObfReport {
    let options = nzbkit::mem::rar_read_options(password.map(str::as_bytes));
    // One parse session for the whole candidate set: an encrypted set
    // shares one salt across its volumes, and the per-volume PBKDF2
    // ladder dwarfed the parse itself on p99-sized sets.
    let mut parse = rars::ReadSession::new(options);
    let mut parsed: Vec<(Option<u64>, PathBuf, rars::Archive)> = Vec::new();
    for path in candidates {
        match parse.read_path(path) {
            Ok(archive) => parsed.push((archive_volume_number(&archive), path.clone(), archive)),
            // A Rar!-magic file that will not parse is not a usable volume;
            // skip it rather than abort the whole set.
            Err(e) => warn!(target: "extract", "skipping {}: {e}", path.display()),
        }
    }
    if parsed.is_empty() {
        return ObfReport {
            failed: true,
            ..ObfReport::default()
        };
    }
    parsed.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    // First/last member metadata drives the continuity linkage.
    let boundary = |archive: &rars::Archive| -> (Option<(Vec<u8>, bool)>, Option<(Vec<u8>, bool)>) {
        let mut first: Option<(Vec<u8>, bool)> = None;
        let mut last: Option<(Vec<u8>, bool)> = None;
        for member in archive.members() {
            let name = member.meta.name_bytes().to_vec();
            if first.is_none() {
                first = Some((name.clone(), member.meta.is_split_before));
            }
            last = Some((name, member.meta.is_split_after));
        }
        (first, last)
    };

    // Partition. Sets start at volumes with no volume number (a RAR5 set's
    // first volume, or a standalone archive); numbered volumes attach to
    // the open set whose tail's split-after member name matches their
    // split-before head - or, when the boundary member is not split, to
    // the only open set awaiting that number.
    let mut sets: Vec<Vec<(PathBuf, rars::Archive)>> = Vec::new();
    // Per set, parallel to `sets`: is this a MID-SET FRAGMENT - a set
    // whose HEAD volume begins inside a member that started in a volume
    // we do not have? A first volume cannot continue anything, so such a
    // head is not a head, and the set can never be unpacked - not by us,
    // not by unrar, not by 7-Zip. Recorded here, where the linkage that
    // would have given it a predecessor came up empty; read on the
    // failure arm below.
    let mut fragment: Vec<bool> = Vec::new();
    let headless = |first: &Option<(Vec<u8>, bool)>| -> bool {
        first
            .as_ref()
            .is_some_and(|(_, split_before)| *split_before)
    };
    let mut open: Vec<usize> = Vec::new(); // indexes of sets still growing
    for (number, path, archive) in parsed {
        if number.is_none() {
            let (first, last) = boundary(&archive);
            // A first volume whose last member is not split-after is a
            // complete single-volume archive.
            let closed = !last.is_some_and(|(_, split_after)| split_after);
            // Reachable here, not just on the invented arm below: RAR4
            // carries no volume number (`archive_volume_number` is
            // RAR5-only), so every volume of an obfuscated RAR4 set comes
            // in through this door, continuations included - and each one
            // starts a set of its own, because there is nothing to attach
            // it to an open set BY. That is the whole of the obfuscated
            // RAR4 limit, and `archive_volume_number` carries why it is
            // accepted rather than closed.
            let frag = headless(&first);
            sets.push(vec![(path, archive)]);
            fragment.push(frag);
            if !closed {
                open.push(sets.len() - 1);
            }
            continue;
        }
        let number = number.unwrap_or(0);
        let (first, last) = boundary(&archive);
        // Candidate open sets currently ending at `number - 1` volumes past
        // their first (RAR5 numbers later volumes 1, 2, …).
        let expecting: Vec<usize> = open
            .iter()
            .copied()
            .filter(|&si| sets[si].len() as u64 == number)
            .collect();
        let chosen = match expecting.len() {
            0 => None,
            1 => Some(expecting[0]),
            // Several open sets await this number: the split-member name
            // across the boundary is the only evidence there is, and it
            // has to be UNIQUE. First-match is not evidence - two
            // obfuscated sets that both span a member called `film.mkv`
            // both satisfy it, so `.find` attached the continuation to
            // whichever set happened to be created first (head path
            // order) and then closed it, after which the OTHER
            // continuation fell into the `1 =>` arm and was attached with
            // no boundary check at all. Two complete sets became two
            // cross-wired ones. Decline on ambiguity instead: the volume
            // starts its own set, every input stays on disk, and the
            // failure is explained rather than guessed.
            _ => {
                let mut hits = expecting.iter().copied().filter(|&si| {
                    let tail = &sets[si].last().expect("open set is non-empty").1;
                    let (_, tail_last) = boundary(tail);
                    match (&tail_last, &first) {
                        (Some((tail_name, true)), Some((head_name, true))) => {
                            tail_name == head_name
                        }
                        _ => false,
                    }
                });
                match (hits.next(), hits.next()) {
                    (Some(si), None) => Some(si),
                    (Some(_), Some(_)) => {
                        warn!(
                            target: "extract",
                            "volume {} (#{number}) continues an identically named member in \
                             several open sets - declining to guess; every volume is kept",
                            path.display(),
                        );
                        None
                    }
                    _ => None,
                }
            }
        };
        match chosen {
            Some(si) => {
                sets[si].push((path, archive));
                if !last.is_some_and(|(_, split_after)| split_after) {
                    open.retain(|&s| s != si);
                }
            }
            None => {
                // No open set expects this volume - treat it as starting
                // its own (best effort; extraction will surface gaps).
                //
                // "Invented" is deliberately NOT the fragment test: a
                // genuinely obfuscated post has no names to reason from,
                // so arriving here is ordinary for it. What is not is
                // arriving with a first member that continues a volume
                // nobody has.
                let frag = headless(&first);
                info!(
                    target: "extract",
                    "volume {} (#{number}) matches no open set - treating as its own set{}",
                    path.display(),
                    if frag {
                        " (it continues an earlier volume that is not here)"
                    } else {
                        ""
                    }
                );
                sets.push(vec![(path, archive)]);
                fragment.push(frag);
            }
        }
    }

    info!(
        target: "extract",
        "unpacking {} obfuscated RAR set(s) ({} volume(s)) by header order…",
        sets.len(),
        sets.iter().map(|s| s.len()).sum::<usize>()
    );
    note_unorderable_rar4(&sets);
    let mut report = ObfReport::default();
    // §101, the same refusal the named-stem ladder makes: a directory
    // holding more than one archive set must not eat. It was applied
    // only in `try_unrar_spent`'s loop, and this path partitions by
    // HEADER continuity rather than by stem, so a directory of two
    // obfuscated sets slipped past it entirely. Set one eats its volumes
    // and publishes; set two fails part-way with several of its own
    // volumes already hard-deleted - and the failure arm below still
    // says every volume of a failed set stays, "on a finished download
    // they are the only copy", which eating has just made untrue.
    // Held for the whole partitioned run, restored on drop.
    let _single_set_only = (sets.len() > 1).then(|| crate::eatvol::EatArm::new(false));
    for (si, set) in sets.into_iter().enumerate() {
        let is_fragment = fragment.get(si).copied().unwrap_or(false);
        // Keep each set's SOURCE paths instead of dropping them on the
        // floor: they are the exact files we parsed and are about to feed
        // the extractor, so a successful extraction proves them ours AND
        // spent. Nothing downstream can re-derive that. The nested pass's
        // `sweep_spent_entry` groups candidates by `release_stem`, and a
        // hash name matches none of the volume suffixes it strips - seven
        // obfuscated volumes read as seven separate releases, its
        // "exactly one set present" guard trips, and the whole set used
        // to be left sitting beside the extracted payload.
        let (sources, archives): (Vec<PathBuf>, Vec<rars::Archive>) = set.into_iter().unzip();
        // Does this set declare a real file to produce? A `.rev` recovery
        // volume also starts with `Rar!`, so it arrives here as a
        // candidate, and its payload can carry a RAR signature the SFX
        // scan latches onto - parsing as a memberless "set" of its own.
        // Deleting one destroys the recovery data a damaged set is
        // repaired FROM, which is the worst outcome available here.
        let has_member = archives
            .iter()
            .any(|a| a.members().any(|m| !m.meta.is_directory));
        // Taken per set, immediately before the extraction that fills it:
        // the diff against it names exactly what THIS set published.
        let before = snapshot_recursive(dir).ok();
        // `sources` and `archives` came off the same unzip, so index i of
        // one is index i of the other - the mapping §101's eating mode
        // needs to delete each volume as the extractor finishes with it.
        //
        // Withheld on the two gates the post-extraction sweep below
        // already applies, because eating happens INSIDE the extractor
        // and so runs before `sweep_spent_obfuscated` is ever consulted -
        // its refusals cannot protect a file that is already gone.
        //
        //  - `has_member`: a memberless set is the `.rev` shape. Such a
        //    file walks out of the extractor as a one-volume set with no
        //    files, which reports `consumed(0)` immediately, so eating
        //    hard-deleted the recovery data a damaged set is repaired
        //    FROM. The sweep's own doc calls that the worst outcome
        //    available here, and `repair.rs`'s
        //    `obfuscated_sweep_never_touches_a_memberless_rar_file`
        //    pins it as the property that must not bend - it passed only
        //    because eating is disarmed under test.
        //  - `depth >= 1`: depth 0 is the user's own set from the offline
        //    `extract` CLI, whose retention is finalize/policy's call.
        //    Unreachable today (the CLI never calls `eatvol::set_mode`,
        //    so its mode is always Off), but the two paths must not
        //    disagree about which volumes are spendable.
        //
        // An empty mapping is the off switch: `write_archives_to_spending`
        // requires one source per archive before it will eat anything.
        //  - `is_fragment`: by the test that named it, not a volume of
        //    anything we are extracting - which is why its failure is
        //    forgiven below. Forgiving it AND eating it is the one
        //    combination that loses a file nobody can get back.
        let eat_sources: &[PathBuf] = if has_member && depth >= 1 && !is_fragment {
            &sources
        } else {
            &[]
        };
        match write_archives_to_spending(dir, &archives, password, eat_sources) {
            Ok(()) => {
                info!(target: "extract", "native unpack complete ✔");
                // Same depth gate the named-set sweep uses, and for the
                // same reason: depth 0 is the user's own downloaded set or
                // an offline `extract` target, whose retention is
                // finalize/policy's call, not ours. Without this an
                // obfuscated set would be deleted where an identical named
                // set is kept, which is a difference the user never asked
                // for and cannot see coming.
                if depth >= 1 {
                    sweep_spent_obfuscated(dir, &sources, has_member, before.as_ref());
                }
                if has_member {
                    report.produced = true;
                }
            }
            Err(e) => {
                // Every volume of a failed set stays. PAR2 repair, `.rev`
                // reconstruction and a plain retry all read them, and on
                // a finished download they are the only copy.
                if is_fragment {
                    // …and its failure is not the job's verdict. The
                    // collector takes `Rar!` MAGIC, not extensions, so
                    // ANY producer of a stray fragment used to fail the
                    // whole job - "an archive in the output directory
                    // could not be unpacked" - with every file the NZB
                    // posted extracted correctly and the payload sitting
                    // right there. Reached in the field 22 Aug 2026 via
                    // par2cmdline's leftover `<name>.1` backup (that
                    // SOURCE is fixed in `repair::purge_par2_backups`);
                    // a user's own file, a partial from an interrupted
                    // external tool and a `.rev`/SFX-shaped payload the
                    // parser latches onto all reproduce it.
                    //
                    // Deliberately NOT the zip gap's rule - "an archive
                    // we cannot open FAILS the job when it is the
                    // payload" (step 5 of `extract_nested`, Codex H2,
                    // 2 Aug) - because the shapes differ. An unopened zip
                    // is a payload we could deliver with better code, so
                    // Failed is honest and makes an *arr re-grab. A
                    // headless volume is not a payload at all: nothing
                    // can produce a byte from it, so Failed buys no
                    // action and costs a job that is complete. The case
                    // this must not swallow - an obfuscated post that
                    // arrived with NO head volume - is answered by who
                    // forgives, not here: `ObfReport::ok`, read by the
                    // payload-path callers, forgives a fragment only
                    // beside a set that did extract.
                    let names: Vec<String> =
                        sources.iter().map(|p| p.display().to_string()).collect();
                    warn!(
                        target: "extract",
                        "{} is a mid-set volume with no first part on disk - \
                         nothing can unpack it, leaving it ({e})",
                        names.join(", ")
                    );
                    report.strays.extend(sources.iter().cloned());
                } else {
                    warn!(target: "extract", "obfuscated RAR unpack failed ({e})");
                    report.failed = true;
                }
            }
        }
    }
    report
}

/// Remove the obfuscated volumes one set consumed, once that set has
/// extracted and published successfully.
///
/// `sources` is not a guess from a filename: it is the list of files this
/// pass opened, parsed as RAR headers and handed to the extractor, so each
/// entry is provably an input of the extraction that just succeeded.
/// Three separate refusals, any one of which keeps the ENTIRE set:
///
/// * `has_member` is false - the set declared no file member, so it never
///   produced one. That is the `.rev` shape, and recovery data must
///   survive its own misdetection.
/// * we could not snapshot `dir` beforehand, so nothing here can tell an
///   input from an output. No proof, no delete.
/// * the extraction published no file at all - there is no payload these
///   volumes could be spent ON.
///
/// and per path: never remove something the extraction just published.
/// `lift_scratch_into` refuses to replace an existing name, so a member
/// colliding with a volume lands as `extracted-N-…` and the volume is
/// still the volume - but this asks the before/after diff rather than
/// trusting that invariant to hold forever.
pub(crate) fn sweep_spent_obfuscated(
    dir: &std::path::Path,
    sources: &[PathBuf],
    has_member: bool,
    before: Option<&std::collections::HashSet<PathBuf>>,
) {
    if !has_member {
        return;
    }
    let Some(before) = before else { return };
    let Ok(after) = snapshot_recursive(dir) else {
        return;
    };
    let published: std::collections::HashSet<PathBuf> = after.difference(before).cloned().collect();
    if published.is_empty() {
        return;
    }
    // Trash-aware, unlike the nested-intermediate sweep above: these
    // volumes were DOWNLOADED - they are the obfuscated post itself, the
    // .rar set a user might well want to keep or re-share - and the
    // "spent" verdict is a heuristic chain, which is exactly what the
    // "Deleted files go to the Trash" setting promises to make
    // reversible. Read once for the whole sweep (remove_user_file's
    // contract), and parked for the deferred worker like the finalize
    // sweeps (§64) so a slow Finder never sits inside the job's tail.
    let recoverable = crate::smart::cleanup_recoverable();
    let staging = crate::smart::trash_staging_dir(dir);
    for path in sources {
        if published.contains(path) {
            info!(
                target: "extract",
                "keeping {} - the extraction published it",
                path.display()
            );
            continue;
        }
        // §101: under the volume-eating mode the extraction already
        // deleted this one as it read past it. Nothing left to sweep, and
        // nothing worth warning about - the two paths agree on the end
        // state, they just get there at different moments.
        if !path.exists() {
            continue;
        }
        match crate::smart::remove_swept_file(path, recoverable, staging.as_deref()) {
            Ok(_) => info!(target: "extract", "removed spent volume {}", path.display()),
            // warn!, not println: the daemon's log ring is where a user
            // asking "why is this file still here" will look.
            Err(e) => warn!(
                target: "extract",
                "could not remove spent volume {}: {e}",
                path.display()
            ),
        }
    }
}
