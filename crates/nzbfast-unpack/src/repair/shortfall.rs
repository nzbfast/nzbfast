//! [`RepairShortfall`] - why a PAR2 repair could not complete when the
//! reason is arithmetic about the RECOVERY SET rather than a bad byte,
//! and the two helpers that decide how one is spelled.
//!
//! Lifted out of `repair.rs` for the size gate (TODO 106); the bodies
//! are a verbatim move. It lives beside its producers because the
//! wording IS the point of it - `get::tail` puts `clause()` straight
//! into the job's fail message, and `failkind::another_copy_can_help`
//! reads that sentence back out to decide whether another copy of the
//! release could help.
//!
//! `shortfall_gate_tests.rs` beside this file is NOT its test module: it
//! covers the parent's `shortfall_is_final`, which answers a different
//! question (is the arithmetic final, or has the adoption scan yet to
//! look). `RepairShortfall::clause`'s own cases ride `get::tail`'s
//! round-trip test and `failkind`, because what they pin is the SENTENCE
//! reaching a user; `skip_clause_tests` at the foot of this file is the
//! one exception, and it is here because the clause it covers reads a
//! `FileSlot` field rather than the enum, so there is nothing in the
//! producer's own frame left to pin it from.

use super::VolumeYield;

/// Why a PAR2 repair could not complete, when the reason is arithmetic
/// about the RECOVERY SET rather than a bad byte anywhere.
///
/// The one class of repair failure whose numbers belong in the job's
/// own fail message and not just the console: the user is owed which of
/// the two halves of the post let them down, because the answers are
/// opposite. `Blocks` means the poster shipped too little parity for
/// the damage and no provider could have helped. `Unservable` means the
/// parity is declared, is the right size, and this provider will not
/// hand it over - the payload may be all but perfect (99.8% on the
/// §282 incident), and an alternate source is the whole remedy.
///
/// Both spellings carry "repair could not complete", so both classify
/// [`crate::failkind::FailKind::Unrepairable`]: transient enough for
/// the one automatic retry, and hinting `search` rather than `retry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairShortfall {
    /// Not enough recovery blocks are declared to cover the damage,
    /// whatever the provider does.
    ///
    /// `have` IS A PER-SET FIGURE and the wording has to keep saying
    /// so. It is `recovery_candidates(nzb, set, ..)` folded - the
    /// volumes of the one recovery set this arithmetic is about - and
    /// until 31 Aug 2026 the clause spelled it "the NZB only carries
    /// {have}", which is a claim about the whole post. Exact on the
    /// single-set post that is the overwhelming majority, and false on
    /// a per-file-set (TODO 311, GH #63) or overlapping post: measured
    /// verbatim that day as `20 recovery block(s) needed but the NZB
    /// only carries 1` over a post carrying 23. That is not a counting
    /// slip, because the two arms above exist precisely to send the
    /// user two opposite ways - a figure reported as the post's total
    /// says "the poster shorted you, give up" about parity that is not
    /// this set's to spend.
    ///
    /// `set` is the recovery set id the figures were measured over,
    /// and it is `Some` only where naming it DISAMBIGUATES: the post
    /// carries more than one recovery set, so "which set" is a live
    /// question and the tag correlates the fail message with the
    /// `[par2]` console lines, which identify a set by the first 8 of
    /// [`nzbkit::par2::hex16`]. `None` on a one-set post, where the tag
    /// would be noise in a sentence a user reads.
    ///
    /// WHAT THE TAG DELIBERATELY DOES NOT FIX: both producers assign
    /// this inside a per-set loop, so on a post where TWO sets are
    /// unrepairable the surviving figures are whichever set ran last.
    /// That was the second half of the same 31 Aug finding, and naming
    /// the set IS its answer - an arbitrary pick stated as "the" reason
    /// is a false claim about the post, while the same pick stated
    /// about a named set is a true one, and both sets being short
    /// leaves the remedy identical either way. Making the pick
    /// deterministic (first, or the largest deficit) would be a
    /// behaviour change with no user-visible payoff on top of that, so
    /// it was left alone on purpose rather than overlooked.
    Blocks {
        needed: usize,
        have: usize,
        set: Option<[u8; 16]>,
    },
    /// §282 item 4: the volumes are declared and the source will not
    /// serve them. Carries the measured yield that said so.
    Unservable(VolumeYield),
}

impl RepairShortfall {
    /// Drop the set tag: this post carries ONE recovery set, so there
    /// is nothing for the tag to disambiguate.
    ///
    /// Applied once, by whoever owns the whole set list, rather than at
    /// each producer: a producer holds its own [`nzbkit::par2::Par2Set`]
    /// and cannot see how many siblings it has, so it always records
    /// the id and the owner blanks it. A no-op on `Unservable`, whose
    /// sentence is about the provider and never about arithmetic.
    pub(crate) fn forget_set(&mut self) {
        if let RepairShortfall::Blocks { set, .. } = self {
            *set = None;
        }
    }

    /// The clause the job's fail message states this shortfall in, put
    /// after "verification failed and PAR2 repair could not complete".
    pub fn clause(&self) -> String {
        match self {
            RepairShortfall::Blocks { needed, have, set } => {
                // The fixed span here is `failkind`'s
                // RECOVERY_SHORTFALL_CLAUSE, which is how
                // `another_copy_can_help` reads this verdict back out of
                // a message - so it must stay CONTIGUOUS in both
                // spellings, which is why the set tag is appended rather
                // than spliced into the middle.
                let tag = set.map_or_else(String::new, |id| {
                    format!(" (recovery set {})", &nzbkit::par2::hex16(&id)[..8])
                });
                format!(
                    "{needed} recovery block(s) needed but the recovery set that covers \
                     this damage carries only {have}{tag}"
                )
            }
            RepairShortfall::Unservable(y) => format!(
                "the recovery data for this post could not be fetched from your \
                 provider ({}). The payload is not the problem here, so a different \
                 source for the same release is what would fix it",
                y.describe()
            ),
        }
    }
}

/// Scope a shortfall's set tag to the POST it came out of.
///
/// Every producer inside the [`fetch_and_repair`] ladder records the id
/// of the set it measured, because a producer holds one
/// [`nzbkit::par2::Par2Set`] and cannot see how many siblings the post
/// has. This is the frame that can: `sets_in_post` is the whole set
/// list the plan was built from, NOT the sets that took damage. The two
/// part company on exactly the shape the tag exists for - a per-file-set
/// post (TODO 311, GH #63) where one track is damaged leaves seventeen
/// sets with nothing to do and one plan, and a tag dropped on that count
/// would go missing from the very sentence that needs it.
pub fn scope_to_post(
    short: Option<RepairShortfall>,
    sets_in_post: usize,
) -> Option<RepairShortfall> {
    short.map(|mut s| {
        if sets_in_post < 2 {
            s.forget_set();
        }
        s
    })
}

/// A [`RepairShortfall::Blocks`] from a caller that already knows how
/// many recovery sets the post carries.
///
/// The disk-fallback arm in `get::settle` is the one producer outside
/// the [`fetch_and_repair`] ladder, and it reads its sets straight off
/// the packets on disk, so it can answer "is there anything to
/// disambiguate" itself and needs no [`RepairShortfall::forget_set`]
/// pass afterwards. Out of line rather than inline because
/// `get/settle.rs` was at 2,990 of the size gate's 3,000-line ceiling on
/// 31 Aug 2026, which is also why the caller is one line.
pub fn blocks_over_set(
    needed: usize,
    have: usize,
    set_id: [u8; 16],
    multi: bool,
) -> Option<RepairShortfall> {
    Some(RepairShortfall::Blocks {
        needed,
        have,
        set: multi.then_some(set_id),
    })
}

/// The clause that names the user's own `--skip-samples` as a possible
/// source of a recovery shortfall (M4-29 follow-up, 31 Aug 2026).
///
/// THE DEFECT THIS CLOSES. `skip_samples` decides in `get::plan` off the
/// NZB's posted hint, long before any PAR2 FileDesc name exists. A post
/// whose SUBJECT is `Movie.Sample.mkv` and whose FileDesc calls the same
/// bytes `Feature.mkv` therefore never queues an article for the
/// payload, `get::residual::charge_missing_files` charges `Feature.mkv`
/// as missing entirely, and when the parity is too short to rebuild it
/// the job failed saying only how many blocks it was short. The skip
/// banner is the FIRST line of the same log and nothing joined the two,
/// so a user read an incomplete post where the truth was a setting they
/// chose. Measured green on origin/main `8fbe1c3bd` by the two
/// `e2e_norar::extreme` pins named at the end of this comment; the EXIT
/// was honest throughout, which is why the row read PASS and this stayed
/// open.
///
/// WHY THE WORDING IS CONDITIONAL AND NOT AN ACCUSATION. The two names
/// are not the same string and cannot be joined by matching them - that
/// gap IS M4-29 - so this must not assert which missing file was which.
/// It states the ONE thing that is true in both directions: these files
/// were declined at the user's request, and IF the recovery set covers
/// one of them under a different name then its blocks are part of this
/// shortfall. On the ordinary shape, where the skip matched the set's
/// own name, `get::settle` has already struck the file off `missing_files`
/// so it charges no damage at all, the condition the sentence states is
/// plainly false, and the reader loses nothing by reading it. Asserting
/// a cause instead would be false on exactly that shape.
///
/// IT NAMES BOTH SURFACES the setting has, and that is not belt and
/// braces: the CLI spells it `--skip-samples` and the dashboard spells
/// it "Skip sample files" (`set.skipsample` in the catalogues), and this
/// one sentence is composed once and read on both. A user who cannot
/// find the switch cannot act on the sentence, which is the whole point
/// of it.
///
/// GATED ON [`RepairShortfall::Blocks`], never on `Unservable`: that arm
/// means the parity is declared and the right size and the PROVIDER will
/// not serve it, so the payload is not what was short and a skipped
/// teaser is beside the point. Empty string when nothing was skipped,
/// which is every job that never turned the setting on.
///
/// APPENDED, never spliced, for the reason
/// [`RepairShortfall::clause`] already carries: `failkind`'s
/// `RECOVERY_SHORTFALL_CLAUSE` is read back out of this message by
/// `another_copy_can_help`, and it has to stay contiguous.
///
/// Held by `e2e_norar::extreme::a_skipped_sample_with_too_little_parity_fails_rather_than_going_green`,
/// whose sibling `..._a_filedesc_covers_is_rebuilt_from_parity` is its
/// control, and by the unit cases below.
pub fn skipped_samples_clause(
    short: &RepairShortfall,
    slots: &[std::sync::Arc<crate::unpack::FileSlot>],
) -> String {
    if !matches!(short, RepairShortfall::Blocks { .. }) {
        return String::new();
    }
    // The posted hint, which is exactly what `get::plan`'s skip banner
    // names - the two lists are the same filter over the same field, so
    // a reader can match this sentence to that line by eye.
    let names: Vec<&str> = slots
        .iter()
        .filter(|s| s.sample_skipped)
        .map(|s| s.hint.as_str())
        .collect();
    if names.is_empty() {
        return String::new();
    }
    format!(
        ". This job also skipped {} sample file(s) at your request (the \"Skip sample \
         files\" setting, --skip-samples): {} - if the recovery set covers one of those \
         under a different name, its blocks are part of this shortfall",
        names.len(),
        names.join(", ")
    )
}

/// The two clauses `nzbfast_core::failkind`'s rows classify, held to
/// what this producer actually emits.
///
/// WHY IT IS HERE. Those rows used to build the string by calling
/// `.clause()` directly, from inside `failkind`'s own test module. The
/// crate-split step 2 cut put `failkind` in `nzbfast-core` and left
/// `repair` a layer above it, so that call is no longer possible in
/// that direction - and dropping it would have left `failkind`
/// classifying a sentence nothing proves the producer still writes,
/// which is exactly the drift the classifier exists to catch. So the
/// assertion moved to the side that can see both halves: the literals
/// live in `failkind/tests.rs` (named there, with this test named back)
/// and this pins them to the producer.
///
/// A reworded clause therefore reddens HERE, on the author's own push,
/// naming the string to move. Fix it by moving both - never by
/// loosening this to a substring or a length.
#[cfg(test)]
mod failkind_clause_pin {
    use super::*;

    #[test]
    fn the_block_shortfall_clauses_are_what_failkind_classifies() {
        assert_eq!(
            RepairShortfall::Blocks {
                needed: 9,
                have: 8,
                set: None,
            }
            .clause(),
            "9 recovery block(s) needed but the recovery set that covers this damage carries \
             only 8"
        );
        assert_eq!(
            RepairShortfall::Blocks {
                needed: 20,
                have: 8,
                set: Some([0xAB; 16]),
            }
            .clause(),
            "20 recovery block(s) needed but the recovery set that covers this damage carries \
             only 8 (recovery set abababab)"
        );
    }
}

#[cfg(test)]
mod skip_clause_tests {
    use super::*;
    use crate::unpack::FileSlot;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize};

    /// A slot carrying only the two fields this clause reads.
    fn slot(hint: &str, sample_skipped: bool) -> Arc<FileSlot> {
        Arc::new(FileSlot {
            hint: hint.to_string(),
            hint_is_posted_name: true,
            yenc_votes: Default::default(),
            name_choice: AtomicU8::new(crate::unpack::NAME_UNDECIDED),
            is_par2_main: false,
            sample_skipped,
            par2_name_demoted: Default::default(),
            par2_sniffed: AtomicBool::new(false),
            total_segments: 1,
            remaining: AtomicUsize::new(0),
            missing: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            deferred: AtomicUsize::new(0),
            abandoned: AtomicUsize::new(0),
            capture: std::sync::Mutex::new(None),
        })
    }

    fn blocks() -> RepairShortfall {
        RepairShortfall::Blocks {
            needed: 182,
            have: 20,
            set: None,
        }
    }

    /// M4-29's own shape: the skip fired on the posted hint, the parity
    /// is short, and the sentence must name the setting AND the file it
    /// declined - by the same posted name `get::plan`'s banner prints,
    /// so a reader can pair the two lines by eye.
    #[test]
    fn a_block_shortfall_beside_a_skipped_sample_names_the_setting() {
        let slots = [
            slot("Movie.Sample.mkv", true),
            slot("Main.Video.mkv", false),
        ];
        let c = skipped_samples_clause(&blocks(), &slots);
        assert!(c.contains("--skip-samples"), "{c}");
        assert!(c.contains("Movie.Sample.mkv"), "{c}");
        assert!(c.contains("1 sample file(s)"), "{c}");
        assert!(
            !c.contains("Main.Video.mkv"),
            "a file that was fetched is not evidence of anything: {c}"
        );
        // Conditional, never an accusation: the two names cannot be
        // joined (that gap IS M4-29), so it must not claim WHICH missing
        // file the skip cost.
        assert!(c.contains("if the recovery set covers"), "{c}");
    }

    /// The setting was never on, so there is nothing to attribute and
    /// the fail message must read exactly as it did before.
    #[test]
    fn nothing_skipped_adds_nothing_to_the_message() {
        let slots = [slot("Main.Video.mkv", false)];
        assert!(skipped_samples_clause(&blocks(), &slots).is_empty());
        assert!(skipped_samples_clause(&blocks(), &[]).is_empty());
    }

    /// `Unservable` is the OTHER half of the post - the parity is
    /// declared, is the right size, and the provider will not hand it
    /// over. A skipped teaser is beside the point there, and saying so
    /// would send the user at their own settings when the remedy is a
    /// different source.
    #[test]
    fn an_unservable_shortfall_is_never_blamed_on_the_skip() {
        let slots = [slot("Movie.Sample.mkv", true)];
        let unservable = RepairShortfall::Unservable(super::super::VolumeYield::default());
        assert!(skipped_samples_clause(&unservable, &slots).is_empty());
    }

    /// Appended, never spliced: `failkind::another_copy_can_help` reads
    /// `RECOVERY_SHORTFALL_CLAUSE` back out of the composed message and
    /// needs it contiguous. This pins the round trip over the composed
    /// sentence rather than over `clause()` alone.
    #[test]
    fn the_composed_sentence_still_reads_back_as_a_recovery_shortfall() {
        let s = blocks();
        let slots = [slot("Movie.Sample.mkv", true)];
        let msg = format!(
            "verification failed and PAR2 repair could not complete: {}{}",
            s.clause(),
            skipped_samples_clause(&s, &slots)
        );
        assert!(
            crate::failkind::another_copy_can_help(
                crate::failkind::fail_kind(&msg),
                crate::failkind::fail_hint(&msg),
                &msg,
                false
            ),
            "the appended clause broke the evidence span: {msg}"
        );
    }
}
