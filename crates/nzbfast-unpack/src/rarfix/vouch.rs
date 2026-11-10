//! TODO 164: which of the archive sets the disk ladder left packed the
//! job's OWN PAR2 set vouches for.
//!
//! The multi-set rule in [`super::try_unrar_outcome`] is "any stem group
//! produced = the run succeeded", with the leftovers named in one
//! warning. That tolerance is deliberate (§101: a decoy, a corrupt
//! sample or a subtitle rar beside the release must not fail a good
//! job) and it stays. What the ladder cannot know is WHICH of its
//! leftovers is the release, and the level above it can: a group whose
//! volumes the recovery set carries FileDescs for is, by the poster's
//! own word, the posted release and not a decoy. A job whose vouched
//! set is still packed must not complete green.
//!
//! Three outcomes, decided here and applied by the tail:
//!
//! - no vouched group among the leftovers: today's warn-and-continue.
//!   A magic-sniffed, PAR2-unknown group is exactly the decoy shape,
//!   and this discriminator exists so that shape keeps its tolerance.
//! - every vouched leftover is an encrypted set that was never offered
//!   a password: the existing completed-but-locked shape (the 🔒 line,
//!   volumes kept, the daemon's finalize raises `password_required` on
//!   a COMPLETED record). Not a third shape, and not a Failed one:
//!   `password_required` on a Failed record kills the automatic retry
//!   (12 Aug 2026 sweep), and a `-hp` set that could not be opened is
//!   not the same evidence as a vouched group that failed to unpack.
//! - anything else vouched: the level fails, naming the sets. A
//!   vouched group that was handed a password and still failed is a
//!   wrong password or a damaged set, the same verdict the single-set
//!   arm has always reached.
//!
//! Since 9 Nov 2026 (decision D4's extension, TODO 358) a vouched set
//! CLEARLY smaller than what unpacked - the sample shape, see
//! `is_extra` - is not "anything else": PAR2 naming a broken sample
//! does not make the sample the release, so it is tolerated and named
//! like an unvouched one, provided the main payload was delivered.
//!
//! Name-level, on purpose: the settle path publishes the set's FileDesc
//! names (sanitized, lowercased) for the sniffed-leftover sweep, and a
//! volume file on disk is vouched for when its name is one of them.
//!
//! G2 (TODO 358, research/PLAN-WEAVER-PARITY-2026-11-08.md section 2):
//! the PAR2 test above only fires when a recovery set activated and
//! names the leftover, so a post with no PAR2 at all, or one whose set
//! skips the archive, left the decoy tolerance as the ONLY rule - and
//! "any group produced" then completed a job whose main payload was
//! still packed beside an unpacked sample. That is the shape Weaver
//! 0.16.12 reported as "job completed" (BENCH-WEAVER-01612-2026-11-07
//! section 3b). So an unvouched leftover is now also judged by SIZE: a
//! group whose volumes outweigh the largest group that DID unpack is
//! the main payload, never a decoy, and the level fails naming it (or
//! lands on the locked shape when it is an encrypted set that was never
//! offered a password, exactly as a vouched one does).
//!
//! What stays tolerated is reported by name (D4, item 15): the
//! [`VouchVerdict::Tolerated`](crate::rarfix::vouch::VouchVerdict::Tolerated) list is what a Completed job did NOT
//! deliver, and every name on it is a member outside the main payload
//! by construction - smaller than something that unpacked.

use crate::smart::sample::SAMPLE_MAX_FRACTION;
use std::collections::HashSet;
use std::path::PathBuf;

/// One stem group the ladder tried and could not unpack, carried out
/// with the volume files it was tried on rather than only its display
/// stem - the names are what the vouching test needs.
pub struct PackedGroup {
    /// The display stem the leftovers warning names.
    pub(crate) what: String,
    /// The group's volume files, as the ladder's directory read listed
    /// them.
    pub(crate) volumes: Vec<PathBuf>,
    /// A volume's headers need a password to open (the same probe the
    /// per-group password resolver keys on).
    pub(crate) encrypted: bool,
    /// The group WAS handed a password - the caller's or a harvested
    /// one - so its failure is not for want of one.
    pub(crate) had_password: bool,
    /// A refusal that named its own reason (today only a bomb verdict).
    /// Travels with the group so a vouched bomb still blames the disk.
    pub(crate) reason: Option<String>,
    /// G2: the group's volume bytes on disk, read when the group was
    /// recorded (its volumes are still there - it did not unpack).
    pub(crate) bytes: u64,
    /// The obfuscated arm's headless fragments (review lane 4 item 4):
    /// volumes whose first member continues a volume that is not on
    /// disk, carried out as one group. Never a complete set, so never a
    /// PEER of one - only OUTWEIGHING what unpacked makes them the main
    /// payload (a set that lost its first volume beside a sample). A
    /// single stray middle volume the size of a fifth of the delivered
    /// set is the field's par2-backup shape and stays tolerated, as
    /// `repair_tests::a_stray_mid_set_volume_does_not_fail_a_job_whose_set_unpacked`
    /// pins.
    pub(crate) remnant: bool,
}

impl PackedGroup {
    pub(crate) fn record(
        what: String,
        group: &[PathBuf],
        had_password: bool,
        reason: Option<String>,
    ) -> PackedGroup {
        PackedGroup {
            what,
            encrypted: group.iter().any(|p| nzbkit::rar::needs_password(p)),
            bytes: group_bytes(group),
            remnant: false,
            volumes: group.to_vec(),
            had_password,
            reason,
        }
    }

    fn vouched_by(&self, covered: &HashSet<String>) -> bool {
        self.volumes.iter().any(|p| {
            p.file_name()
                .map(|n| nzbkit::disk::sanitize_filename(&n.to_string_lossy()).to_lowercase())
                .is_some_and(|n| covered.contains(&n))
        })
    }
}

/// The on-disk bytes of a group's volumes. A volume that cannot be
/// stat'ed counts nothing, which can only make a leftover look SMALLER
/// than it is - and that errs toward the tolerance the ladder already
/// had, never toward a new failure.
pub(crate) fn group_bytes(group: &[PathBuf]) -> u64 {
    group
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum()
}

/// What a SUCCESSFUL ladder run reports: the volumes it spent, and the
/// groups it left packed.
#[derive(Default)]
pub struct UnpackOutcome {
    pub spent: Vec<PathBuf>,
    pub packed: Vec<PackedGroup>,
    /// G2: the volume bytes of the LARGEST group this run unpacked,
    /// measured before its volumes were spent. The yardstick
    /// [`judge`] measures an unvouched leftover against: anything
    /// bigger is the main payload, not a decoy. Zero when nothing was
    /// measured (an empty outcome, or a run that left nothing packed).
    pub largest_produced: u64,
}

/// The leftovers, as the warning lists them.
pub(crate) fn packed_names(packed: &[PackedGroup]) -> String {
    packed
        .iter()
        .map(|g| g.what.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The level's verdict on the ladder's leftovers.
#[derive(Debug, PartialEq, Eq)]
pub enum VouchVerdict {
    /// Nothing PAR2 vouched for stayed packed, and nothing left packed
    /// outweighs what unpacked: the decoy tolerance. The names are the
    /// leftovers themselves (empty when nothing stayed packed) - item
    /// 15's list of what a Completed job did NOT deliver, every one of
    /// them outside the main payload.
    Tolerated(Vec<String>),
    /// Every vouched leftover is an encrypted set that was never
    /// offered a password: the completed-but-locked shape.
    Locked(Vec<String>),
    /// A vouched set stayed packed: the level fails, naming it. `reason`
    /// is the first vouched group's own refusal, if any named one.
    Failed {
        names: Vec<String>,
        reason: Option<String>,
    },
    /// G2: an UNVOUCHED leftover outweighs every group that unpacked,
    /// so it is the main payload and the level fails, naming it.
    /// `reason` as in [`VouchVerdict::Failed`].
    MainPayload {
        names: Vec<String>,
        reason: Option<String>,
    },
}

/// Decide the leftovers against the recovery set's FileDesc names and
/// the largest group that unpacked.
/// `covered: None` is "no set activated", and with no set nothing is
/// vouched - but the size rule (G2) still applies.
///
/// `largest_produced` is [`UnpackOutcome::largest_produced`]. Zero
/// disables the size rule rather than making every leftover the main
/// payload: zero means "not measured", and a judgement on a missing
/// measurement is exactly the kind this module must not invent.
///
/// The size rule, as the 9 Nov 2026 pre-release sweep left it (TODO
/// 358, review lane 4 items 2 and 5):
///
/// - a leftover CLEARLY smaller than the largest group that unpacked -
///   under `SAMPLE_MAX_FRACTION` of it, see `is_extra` - is an EXTRA
///   (the sample, subs, proof shape) and is tolerated and named, vouched
///   or not. Vouched-and-tolerated is decision D4's extension: PAR2
///   naming a broken sample does not make the sample the release.
/// - with NO recovery set naming anything, a leftover that is not
///   clearly smaller is a PEER of what unpacked - one episode of a season
///   pack, the other disc - and is part of the main payload: the level
///   fails. "Strictly larger than what unpacked" assumed ONE main set and
///   completed a season pack with an episode missing.
/// - with a recovery set in scope that does NOT name the leftover, a
///   peer-sized leftover keeps the decoy tolerance and only one that
///   outweighs what unpacked is the main payload. The same strict line
///   holds for a `PackedGroup::remnant`, with or without a set. The set naming the
///   release and not the leftover is the decoy evidence the module doc
///   describes; without a set there is no such evidence, and size is
///   all there is.
pub fn judge(
    packed: &[PackedGroup],
    covered: Option<&HashSet<String>>,
    largest_produced: u64,
) -> VouchVerdict {
    let decoy_evidence = covered.is_some_and(|c| !c.is_empty());
    let mut vouched: Vec<&PackedGroup> = Vec::new();
    let mut main: Vec<&PackedGroup> = Vec::new();
    let mut tolerated: Vec<&PackedGroup> = Vec::new();
    for g in packed {
        let extra = is_extra(g.bytes, largest_produced);
        if covered.is_some_and(|c| g.vouched_by(c)) {
            // D4 extension: a vouched EXTRA beside a delivered main
            // payload is named, not failed. Unmeasured is never an extra,
            // so a vouched leftover with nothing to weigh it against
            // keeps TODO 164's verdict.
            if extra {
                tolerated.push(g);
            } else {
                vouched.push(g);
            }
        } else if largest_produced > 0
            && if decoy_evidence || g.remnant {
                g.bytes > largest_produced
            } else {
                !extra
            }
        {
            main.push(g);
        } else {
            tolerated.push(g);
        }
    }
    if vouched.is_empty() && main.is_empty() {
        return VouchVerdict::Tolerated(tolerated.iter().map(|g| g.what.clone()).collect());
    }
    let held: Vec<&PackedGroup> = vouched.iter().chain(main.iter()).copied().collect();
    let names: Vec<String> = held.iter().map(|g| g.what.clone()).collect();
    if held.iter().all(|g| g.encrypted && !g.had_password) {
        return VouchVerdict::Locked(names);
    }
    // A vouched failure keeps its own sentence (TODO 164) - the PAR2
    // evidence is the stronger of the two, and it is what the existing
    // suites read.
    let failed_vouched: Vec<&PackedGroup> = vouched
        .iter()
        .copied()
        .filter(|g| !(g.encrypted && !g.had_password))
        .collect();
    if !failed_vouched.is_empty() || main.is_empty() {
        let vnames: Vec<String> = vouched.iter().map(|g| g.what.clone()).collect();
        return VouchVerdict::Failed {
            reason: vouched.iter().find_map(|g| g.reason.clone()),
            names: vnames,
        };
    }
    VouchVerdict::MainPayload {
        reason: main.iter().find_map(|g| g.reason.clone()),
        names: main.iter().map(|g| g.what.clone()).collect(),
    }
}

/// Is a leftover of `bytes` an EXTRA beside the largest group that
/// unpacked - clearly smaller than it, rather than a peer?
///
/// The line is `SAMPLE_MAX_FRACTION`, the one the finished-directory
/// sweep already draws between a teaser and a feature (a "sample" video
/// under 15% of the feature is a throwaway; one at or over it is real
/// content). One rule, one copy: an archive set that size beside the set
/// that unpacked is the same shape one layer down. Unmeasured
/// (`largest_produced == 0`) is never an extra.
pub(crate) fn is_extra(bytes: u64, largest_produced: u64) -> bool {
    largest_produced > 0 && (bytes as f64) < (largest_produced as f64) * SAMPLE_MAX_FRACTION
}

/// The job-level sentence for a [`VouchVerdict::Failed`].
pub fn failure_sentence(names: &[String]) -> String {
    format!(
        "the PAR2 set vouches for {} archive set(s) that did not unpack: {} \
         (damaged, compressed with an unsupported method, or the password is wrong)",
        names.len(),
        names.join(", ")
    )
}

/// The job-level sentence for a [`VouchVerdict::MainPayload`].
pub fn main_payload_sentence(names: &[String]) -> String {
    format!(
        "the main payload could not be unpacked: {} is still packed and outweighs \
         everything that did unpack (damaged, compressed with an unsupported method, \
         or the password is wrong)",
        names.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn covered(names: &[&str]) -> HashSet<String> {
        names.iter().map(|n| n.to_lowercase()).collect()
    }

    fn group(what: &str, vols: &[&str], encrypted: bool, had_password: bool) -> PackedGroup {
        PackedGroup {
            what: what.into(),
            volumes: vols.iter().map(PathBuf::from).collect(),
            encrypted,
            had_password,
            reason: None,
            bytes: 0,
            remnant: false,
        }
    }

    /// The decoy shape: a leftover the set knows nothing about keeps
    /// today's tolerance - with or without a set in scope.
    #[test]
    fn an_unvouched_leftover_is_tolerated() {
        let packed = vec![group("decoy", &["/o/decoy.rar"], false, false)];
        assert_eq!(
            judge(&packed, None, 0),
            VouchVerdict::Tolerated(vec!["decoy".into()])
        );
        assert_eq!(
            judge(&packed, Some(&covered(&["release.rar", "release.r00"])), 0),
            VouchVerdict::Tolerated(vec!["decoy".into()])
        );
    }

    /// A vouched leftover fails the level, and the decoy beside it is
    /// not what the sentence names.
    #[test]
    fn a_vouched_leftover_fails_the_level_by_name() {
        let packed = vec![
            group("decoy", &["/o/decoy.rar"], false, false),
            group(
                "release",
                &["/o/Release.part1.rar", "/o/Release.part2.rar"],
                false,
                false,
            ),
        ];
        assert_eq!(
            judge(
                &packed,
                Some(&covered(&["release.part1.rar", "release.part2.rar"])),
                0
            ),
            VouchVerdict::Failed {
                names: vec!["release".into()],
                reason: None
            }
        );
        // Any ONE vouched volume is enough - the set need not name
        // every volume for the group to be the release.
        assert!(matches!(
            judge(&packed, Some(&covered(&["release.part2.rar"])), 0),
            VouchVerdict::Failed { .. }
        ));
    }

    /// An encrypted vouched set that was never offered a password lands
    /// on the locked shape, not on Failed; one that WAS offered a
    /// password and still stayed packed is a wrong password, which
    /// fails like the single-set arm does.
    #[test]
    fn an_encrypted_vouched_set_without_a_password_is_locked() {
        let cov = covered(&["locked.rar"]);
        let locked = vec![group("locked", &["/o/locked.rar"], true, false)];
        assert_eq!(
            judge(&locked, Some(&cov), 0),
            VouchVerdict::Locked(vec!["locked".into()])
        );
        let wrong = vec![group("locked", &["/o/locked.rar"], true, true)];
        assert!(matches!(
            judge(&wrong, Some(&cov), 0),
            VouchVerdict::Failed { .. }
        ));
        // A locked set beside a damaged vouched one: the damage decides.
        let mixed = vec![
            group("locked", &["/o/locked.rar"], true, false),
            group("broken", &["/o/broken.rar"], false, false),
        ];
        assert!(matches!(
            judge(&mixed, Some(&covered(&["locked.rar", "broken.rar"])), 0),
            VouchVerdict::Failed { .. }
        ));
    }

    /// A vouched group's own refusal (a bomb verdict) travels out with
    /// the failure, so the job blames the disk and not the archive.
    #[test]
    fn a_vouched_refusal_keeps_its_reason() {
        let mut g = group("big", &["/o/big.rar"], false, false);
        g.reason = Some("needs more space than the disk has".into());
        match judge(&[g], Some(&covered(&["big.rar"])), 0) {
            VouchVerdict::Failed { reason, .. } => {
                assert_eq!(
                    reason.as_deref(),
                    Some("needs more space than the disk has")
                )
            }
            other => panic!("{other:?}"),
        }
    }

    fn sized(what: &str, bytes: u64, encrypted: bool, had_password: bool) -> PackedGroup {
        let mut g = group(what, &[&format!("/o/{what}.rar")], encrypted, had_password);
        g.bytes = bytes;
        g
    }

    /// G2: with no PAR2 set in scope, a leftover that outweighs the
    /// largest group that unpacked is the main payload - the job fails
    /// naming it, where the decoy tolerance used to complete it over a
    /// packed release with only a sample delivered.
    #[test]
    fn an_unvouched_leftover_larger_than_what_unpacked_is_the_main_payload() {
        let packed = vec![sized("release", 4_000_000, false, false)];
        assert_eq!(
            judge(&packed, None, 50_000),
            VouchVerdict::MainPayload {
                names: vec!["release".into()],
                reason: None
            }
        );
        // ...and the same when a set IS in scope but does not name it.
        assert!(matches!(
            judge(&packed, Some(&covered(&["sample.rar"])), 50_000),
            VouchVerdict::MainPayload { .. }
        ));
        let s = main_payload_sentence(&["release".into()]);
        assert!(
            s.contains("main payload could not be unpacked: release"),
            "{s}"
        );
    }

    /// Item 15 (D4): a leftover SMALLER than what unpacked is outside
    /// the main payload, so it is tolerated - and named, so the job can
    /// say what it did not deliver.
    #[test]
    fn a_smaller_unvouched_leftover_is_tolerated_and_named() {
        let packed = vec![
            sized("sample", 50_000, false, false),
            sized("subs", 2_000, false, false),
        ];
        assert_eq!(
            judge(&packed, None, 4_000_000),
            VouchVerdict::Tolerated(vec!["sample".into(), "subs".into()])
        );
        // Same size as the release keeps the tolerance WHERE A RECOVERY
        // SET NAMES THE RELEASE AND NOT THE TWIN: strictly greater. (With
        // no set at all the twin is a peer since the 9 Nov sweep - see
        // `a_failed_peer_set_with_no_par2_is_part_of_the_main_payload`.)
        assert_eq!(
            judge(
                &[sized("twin", 10, false, false)],
                Some(&covered(&["release.rar"])),
                10
            ),
            VouchVerdict::Tolerated(vec!["twin".into()])
        );
        // Nothing measured is not a verdict.
        assert_eq!(
            judge(&[sized("big", 10, false, false)], None, 0),
            VouchVerdict::Tolerated(vec!["big".into()])
        );
        // Nothing packed is an empty list.
        assert_eq!(judge(&[], None, 10), VouchVerdict::Tolerated(Vec::new()));
    }

    /// An encrypted main payload never offered a password lands on the
    /// existing locked shape, exactly as a vouched one does; offered
    /// one and still packed, it fails.
    #[test]
    fn an_encrypted_main_payload_without_a_password_is_locked() {
        assert_eq!(
            judge(&[sized("release", 100, true, false)], None, 10),
            VouchVerdict::Locked(vec!["release".into()])
        );
        assert!(matches!(
            judge(&[sized("release", 100, true, true)], None, 10),
            VouchVerdict::MainPayload { .. }
        ));
    }

    /// A vouched failure keeps the TODO 164 sentence even when a main
    /// payload is also packed beside it.
    #[test]
    fn a_vouched_failure_outranks_the_size_rule() {
        let mut v = sized("vouched", 5, false, false);
        v.volumes = vec![PathBuf::from("/o/vouched.rar")];
        let packed = vec![v, sized("big", 100, false, false)];
        assert_eq!(
            judge(&packed, Some(&covered(&["vouched.rar"])), 10),
            VouchVerdict::Failed {
                names: vec!["vouched".into()],
                reason: None
            }
        );
    }
    /// Review lane 4 item 2 (9 Nov 2026): a season pack - one set per
    /// episode, no PAR2 - where one episode failed and is the SAME size
    /// as, or a little smaller than, an episode that unpacked. "Strictly
    /// larger than what unpacked" called that a decoy and completed the
    /// job with an episode missing. With no recovery set to say which
    /// set is the release, a peer-sized leftover IS the main payload.
    #[test]
    fn a_failed_peer_set_with_no_par2_is_part_of_the_main_payload() {
        for e05 in [1_000_000u64, 900_000, 150_000] {
            assert_eq!(
                judge(&[sized("show.s01e05", e05, false, false)], None, 1_000_000),
                VouchVerdict::MainPayload {
                    names: vec!["show.s01e05".into()],
                    reason: None
                },
                "a failed episode of {e05} bytes beside a delivered 1,000,000"
            );
        }
        // The same twin with a set in scope that names only the release
        // keeps the decoy tolerance (the e2e_vouch decoy leg's shape:
        // m5_max 9,922 beside m3_default 10,007).
        assert_eq!(
            judge(
                &[sized("decoy", 9_922, false, false)],
                Some(&covered(&["c.rar"])),
                10_007
            ),
            VouchVerdict::Tolerated(vec!["decoy".into()])
        );
    }

    /// ...and the shape the tolerance exists for: a main payload that
    /// unpacked beside a broken sample well under SAMPLE_MAX_FRACTION of
    /// it completes, with the sample named.
    #[test]
    fn a_failed_sample_beside_the_main_payload_is_tolerated_and_named() {
        assert_eq!(
            judge(
                &[sized("movie.sample", 149_999, false, false)],
                None,
                1_000_000
            ),
            VouchVerdict::Tolerated(vec!["movie.sample".into()])
        );
        assert!(is_extra(149_999, 1_000_000));
        assert!(!is_extra(150_000, 1_000_000), "at the line is a peer");
        assert!(!is_extra(1, 0), "unmeasured is never an extra");
    }

    /// Item 5, decision D4's extension (9 Nov 2026): a broken EXTRA that PAR2
    /// vouches for no longer fails a job whose main payload landed - it
    /// is Completed and named, like an unvouched one. A vouched set that
    /// is a PEER of what unpacked, or larger, is still the release and
    /// still fails with TODO 164's sentence.
    #[test]
    fn a_vouched_extra_beside_a_delivered_main_payload_is_tolerated_and_named() {
        let cov = covered(&["sample.rar", "peer.rar", "big.rar"]);
        assert_eq!(
            judge(
                &[sized("sample", 10_000, false, false)],
                Some(&cov),
                1_000_000
            ),
            VouchVerdict::Tolerated(vec!["sample".into()])
        );
        assert_eq!(
            judge(
                &[sized("peer", 900_000, false, false)],
                Some(&cov),
                1_000_000
            ),
            VouchVerdict::Failed {
                names: vec!["peer".into()],
                reason: None
            }
        );
        assert!(matches!(
            judge(
                &[sized("big", 4_000_000, false, false)],
                Some(&cov),
                1_000_000
            ),
            VouchVerdict::Failed { .. }
        ));
        // A vouched extra beside a vouched peer: the peer decides, and
        // the sentence names only the peer.
        assert_eq!(
            judge(
                &[
                    sized("sample", 10_000, false, false),
                    sized("peer", 900_000, false, false)
                ],
                Some(&cov),
                1_000_000
            ),
            VouchVerdict::Failed {
                names: vec!["peer".into()],
                reason: None
            }
        );
    }
}
