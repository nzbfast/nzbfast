//! The VALUE TYPES of the NZB-seed path: the caller-facing spec, the
//! error enum every stage returns, the stats and inventory records the
//! maintenance passes hand back, and the small internal shape records
//! (`SeedProbe`, `SeedFileShape`, `SeedShape`, `LoadedSeed`, `ExactHit`,
//! `HashCandidate`) the matcher works in terms of. Types and their tiny
//! inherent impls only - nothing here touches a database.
//!
//! Cut out of `seed.rs` on 7 Sep 2026 (claim `debt-split-hot-files-7sep`)
//! at 3,314 of the size gate's 4,000-line file ceiling. Verbatim move;
//! the public items are re-exported beside the `mod` line, so
//! `index::seed::` paths are unchanged for callers.

// Documented in full as part of TODO 84's missing_docs ratchet. The lint
// is on here so the count cannot climb back: a new public item in this
// module needs a doc comment.
#![warn(missing_docs)]

use super::*;

/// Attribution and listing metadata for one external NZB.
///
/// "External" is intentionally source-neutral: this can describe a user's
/// own NZB, an uploader submission, or a licensed reference-indexer result.
#[derive(Debug, Clone, Copy)]
pub struct NzbSeedSpec<'a> {
    /// Which source this assertion came from. Free-form and at most 128
    /// bytes after trimming; it is half the identity of an assertion,
    /// so the same NZB from two sources stays two auditable rows.
    pub source: &'a str,
    /// The source's own identifier for this NZB, at most 1,024 bytes.
    /// The other half of the assertion identity: re-asserting the same
    /// `(source, source_guid)` updates rather than duplicates.
    pub source_guid: &'a str,
    /// The release name the source gives, at most 4,096 bytes. A
    /// trailing `.nzb` is stripped before storage.
    pub name: &'a str,
    /// The source's category string, at most 256 bytes. May be empty,
    /// unlike the three fields above.
    pub category: &'a str,
    /// The source's posted timestamp, Unix seconds.
    pub posted: i64,
    /// The source's declared size in bytes. Not verified against the
    /// NZB and used only for the capacity accounting.
    pub bytes: u64,
}

/// What every stage of the seed path returns on failure.
///
/// The variants separate WHOSE fault it is, which is what decides
/// whether a caller should retry, drop the input, or raise an alarm:
/// `Invalid` and `Nzb` blame the submission, `Capacity` is a local
/// limit the caller can act on, and `Corrupt` and `Sqlite` are this
/// index's own state.
#[derive(Debug, thiserror::Error)]
pub enum NzbSeedError {
    /// The submitted metadata failed validation: an empty required
    /// field, one past its length cap, or a character XML disallows.
    #[error("invalid external NZB seed: {0}")]
    Invalid(&'static str),
    /// The NZB itself would not parse.
    #[error("NZB: {0}")]
    Nzb(#[from] crate::nzb::NzbError),
    /// Stored seed evidence read back inconsistent. An index-state
    /// fault, not a submission fault: the affected set is abandoned and
    /// counted in `sets_errored`.
    #[error("corrupt local seed evidence: {0}")]
    Corrupt(&'static str),
    /// A configured storage limit for external seeds is reached, so
    /// this submission was not stored.
    #[error("external NZB seed capacity reached: {0}")]
    Capacity(&'static str),
    /// The database refused the operation.
    #[error("SQLite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

pub(in crate::index) fn normalize_seed_metadata<'a>(
    source: &'a str,
    source_guid: &'a str,
    name: &'a str,
    category: &'a str,
) -> Result<(&'a str, &'a str, &'a str, &'a str), NzbSeedError> {
    let source = source.trim();
    let source_guid = source_guid.trim();
    let name = crate::nzbimport::strip_nzb_suffix(name.trim()).trim();
    let category = category.trim();
    if source.is_empty() {
        return Err(NzbSeedError::Invalid("source is empty"));
    }
    if source_guid.is_empty() {
        return Err(NzbSeedError::Invalid("source GUID is empty"));
    }
    if name.is_empty() {
        return Err(NzbSeedError::Invalid("name is empty"));
    }
    if source.len() > 128 || source_guid.len() > 1_024 || name.len() > 4_096 || category.len() > 256
    {
        return Err(NzbSeedError::Invalid("metadata field is too long"));
    }
    if [source, source_guid, name, category].iter().any(|value| {
        value
            .chars()
            .any(|character| character.is_control() || matches!(character, '\u{FFFE}' | '\u{FFFF}'))
    }) {
        return Err(NzbSeedError::Invalid(
            "metadata field contains an XML-disallowed character",
        ));
    }
    Ok((source, source_guid, name, category))
}

/// Validate source metadata without opening or mutating an index. Durable
/// acquisition spools use this before publishing evidence that may outlive the
/// current process, then the store repeats the same validation at commit time.
pub fn validate_nzb_seed_spec(spec: NzbSeedSpec<'_>) -> Result<(), NzbSeedError> {
    normalize_seed_metadata(spec.source, spec.source_guid, spec.name, spec.category).map(|_| ())
}

/// Result of saving one source assertion. The same NZB seen through two
/// sources shares `set_id`; each source assertion remains auditable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NzbSeedStored {
    /// The membership set this assertion joined. Shared by every source
    /// that asserts the same NZB.
    pub set_id: i64,
    /// This particular source assertion's row.
    pub assertion_id: i64,
    /// The key the set was identified by, derived from the NZB's own
    /// file manifests rather than from any name.
    pub membership_key: String,
    /// True when this store created the set rather than joining one.
    pub new_set: bool,
    /// True when this store created the assertion rather than updating
    /// an existing `(source, source_guid)` row.
    pub new_assertion: bool,
    /// Data files in the stored NZB, PAR2 volumes excluded.
    pub data_files: usize,
    /// Message-IDs stored as match probes.
    pub probe_ids: usize,
    /// True when every data file contributed its full declared part
    /// count. False keeps the set shadow-only: a partial probe catalog
    /// cannot support a strong membership key, so it can never name a
    /// release.
    pub probe_complete: bool,
}

/// One replay pass's measurable result.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NzbSeedReplayStats {
    /// This pass crossed the durable cursor's end and began a new cycle.
    /// Background callers can stop after observing it without mistaking a
    /// full `limit` batch for proof that more unseen sets remain.
    pub cycle_wrapped: bool,
    /// Sets this pass looked at. The denominator for [`fan_out`].
    ///
    /// [`fan_out`]: NzbSeedReplayStats::fan_out
    pub sets_examined: usize,
    /// Sets that reached a complete, settled, title-agreeing match, so
    /// name claims were written for them. The success terminal.
    pub sets_matched: usize,
    /// Sets with no local candidate at all. The ordinary outcome for an
    /// NZB whose articles this index has never seen.
    pub sets_unmatched: usize,
    /// Sets with candidates that no single release covered completely.
    /// Distinguished from `sets_fragmented` by failing the coverage or
    /// quorum test.
    pub sets_partial: usize,
    /// Sets whose manifest matched but whose release had not crossed the
    /// header-settle window. A LATER pass can still match these, so this
    /// is a wait, not a refusal.
    pub sets_unsettled: usize,
    /// Sets whose required files are covered only by the UNION of two or
    /// more local releases. Real (a crosspost split across releases) but
    /// never a naming basis, since no single release is the set.
    pub sets_fragmented: usize,
    /// Sets that cannot be trusted to name anything: the probe catalog
    /// was incomplete or carried no strong membership key. Shadow-only
    /// by construction.
    pub sets_unsafe: usize,
    /// Sets where the sources disagree about the name, so no claim was
    /// applied. Any earlier claim attributed to this set key is
    /// retracted rather than left standing.
    pub sets_title_conflict: usize,
    /// Sets whose only title was unusable as a name.
    pub sets_invalid_title: usize,
    /// Sets skipped because a per-pass scan budget was already spent.
    /// A budget refusal, not a verdict about the set: a later pass
    /// examines it normally.
    pub sets_saturated: usize,
    /// Sets abandoned on corrupt stored evidence.
    pub sets_errored: usize,
    /// Candidate releases reached by message-id hash lookup, before any
    /// coverage test.
    pub hash_candidates: usize,
    /// Candidates thrown out before the coverage test.
    pub hash_candidates_rejected: usize,
    /// Local release copies that passed the complete-and-settled test.
    /// Can exceed `sets_matched`, because a crosspost puts the same set
    /// on several releases; that ratio is [`fan_out`].
    ///
    /// [`fan_out`]: NzbSeedReplayStats::fan_out
    pub exact_release_matches: usize,
    /// Claims that named a previously unnamed release.
    pub claims_applied: usize,
    /// Claims that displaced a weaker existing name.
    pub claims_replaced: usize,
    /// Claims that agreed with the name already applied.
    pub claims_confirmed: usize,
    /// Claims stored without being applied, the evidence tier not being
    /// enough to name on its own.
    pub claims_recorded: usize,
    /// Claims stored against a release holding an equal-or-stronger
    /// DIFFERENT name. Logged and never auto-resolved here.
    pub claims_conflicted: usize,
    /// Claims refused as unusable (an empty or path-like name, an
    /// unknown release).
    pub claims_rejected: usize,
}

impl NzbSeedReplayStats {
    /// Exact local release copies reached per external membership set in
    /// this pass. Crossposts can make this greater than one.
    pub fn fan_out(&self) -> f64 {
        if self.sets_examined == 0 {
            0.0
        } else {
            self.exact_release_matches as f64 / self.sets_examined as f64
        }
    }
}

/// Persistent inventory for a shadow-mode readout.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NzbSeedInventory {
    /// Membership sets stored.
    pub sets: usize,
    /// Source assertions stored across those sets. Greater than `sets`
    /// wherever two sources asserted the same NZB.
    pub assertions: usize,
    /// File rows across all stored sets.
    pub files: usize,
    /// Message-ID probes stored.
    pub probe_ids: usize,
    /// Audit edges from a set to a local release, every state included.
    pub match_edges: usize,
    /// Sets currently in the matched terminal state.
    pub matched_sets: usize,
    /// Sets whose required files only the union of several releases
    /// covers.
    pub fragmented_sets: usize,
    /// Sets parked because their sources disagree about the name.
    pub title_conflict_sets: usize,
    /// Match edges that actually carry a name claim. The numerator for
    /// [`fan_out`].
    ///
    /// [`fan_out`]: NzbSeedInventory::fan_out
    pub named_release_edges: usize,
}

impl NzbSeedInventory {
    /// Named release edges per stored set, over the whole inventory.
    ///
    /// The durable counterpart of
    /// [`NzbSeedReplayStats::fan_out`], which measures one pass.
    /// Greater than one means crossposts, not double counting.
    pub fn fan_out(&self) -> f64 {
        if self.sets == 0 {
            0.0
        } else {
            self.named_release_edges as f64 / self.sets as f64
        }
    }
}

/// Auditable exact/partial membership edge from a seed set to a local row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NzbSeedMatch {
    /// The local release this edge points at.
    pub release_id: i64,
    /// Message-IDs matched exactly between the set and that release.
    pub exact_ids: usize,
    /// How many of the set's required data files this release covered.
    pub covered_data_files: usize,
    /// The edge's verdict, as the replay pass spelled it: `matched`,
    /// `partial`, `fragmented`, `unsettled`, `unsafe`, `unmatched`,
    /// `invalid-title`, `title-conflict`, `error`, or one of the claim
    /// outcomes (`applied`, `replaced`, `confirmed`, `recorded`,
    /// `conflict`, `rejected`).
    pub state: String,
    /// The membership key a name claim was attributed to, or empty for
    /// an edge that carried no claim.
    pub claim_key: String,
    /// When this edge was written, Unix seconds.
    pub at: i64,
}

#[derive(Debug)]
pub(in crate::index) struct SeedProbe {
    pub(in crate::index) file_ord: usize,
    pub(in crate::index) part_ord: u32,
    pub(in crate::index) msgid: String,
}

#[derive(Debug)]
pub(in crate::index) struct SeedFileShape {
    pub(in crate::index) subject: String,
    pub(in crate::index) bytes: u64,
    pub(in crate::index) segments: usize,
    pub(in crate::index) required: bool,
    pub(in crate::index) dropped: usize,
    pub(in crate::index) kind: i64,
    pub(in crate::index) manifest_key: String,
}

#[derive(Debug)]
pub(in crate::index) struct SeedShape {
    pub(in crate::index) strong_membership_key: String,
    pub(in crate::index) files: Vec<SeedFileShape>,
    pub(in crate::index) probes: Vec<SeedProbe>,
    pub(in crate::index) data_files: usize,
    pub(in crate::index) segments: usize,
    pub(in crate::index) probe_complete: bool,
}

/// Validated, compact seed evidence prepared without holding an index lock.
///
/// Building full-file manifest hashes can inspect a large NZB. Background
/// callers should do that work first, then hold the database writer only for
/// [`Index::nzb_seed_store_prepared`].
#[derive(Debug)]
pub struct NzbSeedPrepared {
    pub(in crate::index) shape: SeedShape,
}

impl NzbSeedPrepared {
    /// Build seed evidence from a parsed NZB, without touching a
    /// database.
    ///
    /// This is the half that can be expensive on a large NZB, which is
    /// why it is separable: do it first, then hold the database writer
    /// only for the store call. An NZB with no usable Message-IDs is
    /// refused here rather than stored as a set that could never match.
    pub fn from_nzb(nzb: &crate::nzb::Nzb) -> Result<Self, NzbSeedError> {
        let shape = seed_shape(nzb)?;
        if shape.probes.is_empty() {
            return Err(NzbSeedError::Invalid("NZB has no usable Message-IDs"));
        }
        Ok(Self { shape })
    }
}

#[derive(Debug)]
pub(in crate::index) struct LoadedSeed {
    pub(in crate::index) id: i64,
    pub(in crate::index) probe_complete: bool,
    /// Required data file -> exact-ID threshold for that file.
    pub(in crate::index) required_files: BTreeMap<i64, usize>,
    /// Canonical identity of every stored file manifest. `None` keeps legacy,
    /// incomplete, or internally inconsistent proof catalogs shadow-only.
    pub(in crate::index) strong_membership_key: Option<String>,
}

#[derive(Debug)]
pub(in crate::index) struct ExactHit {
    pub(in crate::index) release_id: i64,
    pub(in crate::index) ids: Vec<String>,
    pub(in crate::index) covered: BTreeSet<i64>,
    pub(in crate::index) per_file: BTreeMap<i64, usize>,
    pub(in crate::index) local_data_files: usize,
    pub(in crate::index) matched_local_data_files: usize,
    /// Present only when every local file decoded to its declared part count.
    /// The key preserves file roles and duplicate identical manifests.
    pub(in crate::index) strong_membership_key: Option<String>,
    /// The current release is complete and old enough to have crossed the
    /// conservative header-settle window.
    pub(in crate::index) settled: bool,
}

pub(in crate::index) enum ExactHitScan {
    Hit(ExactHit),
    Deferred,
}

impl ExactHit {
    pub(in crate::index) fn manifest_qualifies(&self, seed: &LoadedSeed) -> bool {
        let full_manifest_matches = self
            .strong_membership_key
            .as_ref()
            .zip(seed.strong_membership_key.as_ref())
            .is_some_and(|(local, expected)| local == expected);
        self.ids.len() >= crate::nzbimport::MIN_MSGID_QUORUM
            && self.local_data_files > 0
            && self.matched_local_data_files == self.local_data_files
            && seed
                .required_files
                .iter()
                .all(|(file_ord, need)| self.per_file.get(file_ord).unwrap_or(&0) >= need)
            && full_manifest_matches
    }

    pub(in crate::index) fn qualifies(&self, seed: &LoadedSeed) -> bool {
        self.settled && self.manifest_qualifies(seed)
    }
}

#[derive(Debug)]
pub(in crate::index) struct HashCandidate {
    pub(in crate::index) release_id: i64,
    /// External file ordinal, normalized Message-ID, and whether the
    /// external file is required data. Optional PAR2 IDs participate in
    /// the common claim key when they mapped, but never satisfy a data
    /// coverage gate.
    pub(in crate::index) probes: Vec<(i64, String, bool)>,
}

#[derive(Debug, Default)]
pub(in crate::index) struct SeedReplayScanBudget {
    pub(in crate::index) files: usize,
    pub(in crate::index) segments: usize,
    pub(in crate::index) encoded_bytes: usize,
    pub(in crate::index) decoded_text: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::index) struct NzbSeedUsage {
    pub(in crate::index) sets: i64,
    pub(in crate::index) assertions: i64,
    pub(in crate::index) posted_assertions: i64,
    pub(in crate::index) charged_bytes: i64,
}

pub(in crate::index) enum SeedTitle {
    Missing,
    Conflict,
    One {
        assertion_id: i64,
        name: String,
        source: String,
        category: String,
    },
}
