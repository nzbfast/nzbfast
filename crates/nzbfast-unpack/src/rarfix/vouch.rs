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
//! Name-level, on purpose: the settle path publishes the set's FileDesc
//! names (sanitized, lowercased) for the sniffed-leftover sweep, and a
//! volume file on disk is vouched for when its name is one of them.

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

/// What a SUCCESSFUL ladder run reports: the volumes it spent, and the
/// groups it left packed.
pub struct UnpackOutcome {
    pub spent: Vec<PathBuf>,
    pub packed: Vec<PackedGroup>,
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
    /// Nothing PAR2 vouched for stayed packed: the decoy tolerance.
    Tolerated,
    /// Every vouched leftover is an encrypted set that was never
    /// offered a password: the completed-but-locked shape.
    Locked(Vec<String>),
    /// A vouched set stayed packed: the level fails, naming it. `reason`
    /// is the first vouched group's own refusal, if any named one.
    Failed {
        names: Vec<String>,
        reason: Option<String>,
    },
}

/// Decide the leftovers against the recovery set's FileDesc names.
/// `None` is "no set activated", and with no set nothing is vouched.
pub fn judge(packed: &[PackedGroup], covered: Option<&HashSet<String>>) -> VouchVerdict {
    let Some(covered) = covered else {
        return VouchVerdict::Tolerated;
    };
    let vouched: Vec<&PackedGroup> = packed.iter().filter(|g| g.vouched_by(covered)).collect();
    if vouched.is_empty() {
        return VouchVerdict::Tolerated;
    }
    let names: Vec<String> = vouched.iter().map(|g| g.what.clone()).collect();
    if vouched.iter().all(|g| g.encrypted && !g.had_password) {
        return VouchVerdict::Locked(names);
    }
    VouchVerdict::Failed {
        reason: vouched.iter().find_map(|g| g.reason.clone()),
        names,
    }
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
        }
    }

    /// The decoy shape: a leftover the set knows nothing about keeps
    /// today's tolerance - with or without a set in scope.
    #[test]
    fn an_unvouched_leftover_is_tolerated() {
        let packed = vec![group("decoy", &["/o/decoy.rar"], false, false)];
        assert_eq!(judge(&packed, None), VouchVerdict::Tolerated);
        assert_eq!(
            judge(&packed, Some(&covered(&["release.rar", "release.r00"]))),
            VouchVerdict::Tolerated
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
                Some(&covered(&["release.part1.rar", "release.part2.rar"]))
            ),
            VouchVerdict::Failed {
                names: vec!["release".into()],
                reason: None
            }
        );
        // Any ONE vouched volume is enough - the set need not name
        // every volume for the group to be the release.
        assert!(matches!(
            judge(&packed, Some(&covered(&["release.part2.rar"]))),
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
            judge(&locked, Some(&cov)),
            VouchVerdict::Locked(vec!["locked".into()])
        );
        let wrong = vec![group("locked", &["/o/locked.rar"], true, true)];
        assert!(matches!(
            judge(&wrong, Some(&cov)),
            VouchVerdict::Failed { .. }
        ));
        // A locked set beside a damaged vouched one: the damage decides.
        let mixed = vec![
            group("locked", &["/o/locked.rar"], true, false),
            group("broken", &["/o/broken.rar"], false, false),
        ];
        assert!(matches!(
            judge(&mixed, Some(&covered(&["locked.rar", "broken.rar"]))),
            VouchVerdict::Failed { .. }
        ));
    }

    /// A vouched group's own refusal (a bomb verdict) travels out with
    /// the failure, so the job blames the disk and not the archive.
    #[test]
    fn a_vouched_refusal_keeps_its_reason() {
        let mut g = group("big", &["/o/big.rar"], false, false);
        g.reason = Some("needs more space than the disk has".into());
        match judge(&[g], Some(&covered(&["big.rar"]))) {
            VouchVerdict::Failed { reason, .. } => {
                assert_eq!(
                    reason.as_deref(),
                    Some("needs more space than the disk has")
                )
            }
            other => panic!("{other:?}"),
        }
    }
}
