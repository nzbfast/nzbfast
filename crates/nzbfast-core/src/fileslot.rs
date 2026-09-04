//! [`FileSlot`] - the per-file runtime state of a download - and the
//! name question that hangs off it.
//!
//! Here rather than in `unpack` because every layer reads one. `get`
//! decodes into them, `repair` counts damage over them, `streamhub`
//! holds a run's slots so the queue APIs can freeze a row at the instant
//! it stops moving, and the daemon reports them. That last one is what
//! forced the move: the hub is in the plan's lowest layer and the slot
//! was two above it, so the hub's own field types named the unpack layer
//! (step 1 of research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md).
//!
//! Nothing here knows anything about extraction. `unpack` re-exports
//! both [`FileSlot`] and [`slot_name`], so every existing path -
//! `crate::unpack::FileSlot`, `crate::unpack::slot_name::NameVotes`, the
//! bare names reached through `super::*` - is unchanged.

/// GH #63: which of the post's two names a slot's file is written
/// under. Carries `FileSlot::write_name` and `FileSlot::hint_beats`,
/// and - M4-70 - `FileSlot::contested_yenc_name`, which re-decides that
/// question at settle off what the ARTICLES declared.
pub mod slot_name;

pub struct FileSlot {
    pub hint: String,
    /// GH #63: `hint` came from the POST and is a name worth reading.
    /// Decided at plan time, not sniffed back off `hint`. See
    /// [`slot_name`] for what both of these are for.
    pub hint_is_posted_name: bool,
    /// Latched answer to "which name is this slot's file written
    /// under" - see [`slot_name`].
    pub name_choice: std::sync::atomic::AtomicU8,
    pub is_par2_main: bool,
    /// M4-28: [`Self::is_par2_main`] was decided from the NZB NAME
    /// alone, and an active set has since named these bytes as one of
    /// its own PAYLOAD files - md5-16k over the first 16 KiB plus an
    /// exact length, the same evidence
    /// [`SniffCtl::matched_deferred`] rescues a wrongly-deferred slot
    /// on. Set once, at settle, by
    /// `crate::get::settle::reclaim_par2_named_payload`.
    ///
    /// A separate flag rather than a mutable `is_par2_main`: that field
    /// is read at PLAN time to decide what to queue, what to capture in
    /// memory and which set index a repair may read its packets from
    /// (`settle::repair`'s `main_par2_for`, which proves ownership from
    /// the bytes' own set id and must keep seeing a real index as one).
    /// This says only that the settle-side census must count the slot as
    /// payload, which is the half that was wrong.
    pub par2_name_demoted: std::sync::atomic::AtomicBool,
    /// Issue #14: this slot was posted as payload (hash subject, hash yEnc
    /// name) but its offset-0 article decoded to the `PAR2\0PKT` magic -
    /// it IS recovery data, identified in-stream after the slot was built.
    /// Set once by whichever decode consumer sees the head article; never
    /// cleared.
    pub par2_sniffed: std::sync::atomic::AtomicBool,
    pub total_segments: usize,
    pub remaining: std::sync::atomic::AtomicUsize,
    pub missing: std::sync::atomic::AtomicUsize,
    /// Decode or write failures charged to THIS slot. The global
    /// `decode_errors` counter says a job hit one; only a per-slot count can
    /// say whether the file a PAR2 repair just healed is the one that hit it.
    pub errors: std::sync::atomic::AtomicUsize,
    /// Segments never fetched because the slot was identified as a PAR2
    /// volume in-stream and deferred (removed from the pool queue). Kept
    /// apart from `missing`: a deferred article is a choice, not damage.
    pub deferred: std::sync::atomic::AtomicUsize,
    /// PAR2-race experiment: segments deliberately abandoned mid-run
    /// because recovery blocks on hand already covered them with margin
    /// and repair beats the fetch remainder. A third category next to
    /// `missing` (damage we suffered) and `deferred` (a choice that is
    /// not damage): this is a choice that IS damage - the settle
    /// read-back counts the absent blocks as bad and repair heals them,
    /// so it must exempt the sparse-slot census like a deferral while
    /// still reading as damage evidence for the repair branches.
    pub abandoned: std::sync::atomic::AtomicUsize,
    /// The user asked for sample files to be skipped and this slot's
    /// posted name plus declared size said it is one
    /// (`smart::skippable_samples`), so NONE of its articles were
    /// queued. Decided once at plan time and never revised: the
    /// segments are booked into `deferred` - a choice, not damage -
    /// exactly as a resume-recognised recovery volume's are, which is
    /// what keeps the census and the uncovered-hole scan from failing
    /// the job over a file nobody wanted. The flag itself is read by
    /// the settle pass, which has to strike the file off the PAR2 set's
    /// missing list as well, or repair would fetch recovery volumes to
    /// rebuild the very bytes the setting declined.
    pub sample_skipped: bool,
    /// M4-70: what this slot's ARTICLES declared it was called. The
    /// write path latches the first one and must - the file has to be
    /// called something while it is being written - so the question is
    /// re-decided at settle off this record, by `get::yencname`. See
    /// [`slot_name::NameVotes`] for the per-article cost, which in the
    /// agreeing case is one compare and one relaxed add.
    pub yenc_votes: slot_name::NameVotes,
    /// Par2-main slots capture decoded bytes in memory so the recovery set
    /// activates mid-download without re-reading from disk. `Some` from
    /// build time for slots the NZB names as par2; installed at sniff time
    /// for the in-stream bootstrap volume of an obfuscated post.
    pub capture: std::sync::Mutex<Option<Vec<u8>>>,
}

impl FileSlot {
    /// Recovery data by ANY route - NZB classification or the in-stream
    /// magic sniff. The settle/repair accounting that excludes par2 slots
    /// keys off this, not `is_par2_main` alone.
    pub fn is_par2(&self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let by_name = self.is_par2_main && !self.par2_name_demoted.load(Relaxed);
        by_name || self.par2_sniffed.load(Relaxed)
    }
}
