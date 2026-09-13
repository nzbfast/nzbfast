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

use super::*;

/// Attribution and listing metadata for one external NZB.
///
/// "External" is intentionally source-neutral: this can describe a user's
/// own NZB, an uploader submission, or a licensed reference-indexer result.
#[derive(Debug, Clone, Copy)]
pub struct NzbSeedSpec<'a> {
    pub source: &'a str,
    pub source_guid: &'a str,
    pub name: &'a str,
    pub category: &'a str,
    pub posted: i64,
    pub bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum NzbSeedError {
    #[error("invalid external NZB seed: {0}")]
    Invalid(&'static str),
    #[error("NZB: {0}")]
    Nzb(#[from] crate::nzb::NzbError),
    #[error("corrupt local seed evidence: {0}")]
    Corrupt(&'static str),
    #[error("external NZB seed capacity reached: {0}")]
    Capacity(&'static str),
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
    pub set_id: i64,
    pub assertion_id: i64,
    pub membership_key: String,
    pub new_set: bool,
    pub new_assertion: bool,
    pub data_files: usize,
    pub probe_ids: usize,
    pub probe_complete: bool,
}

/// One replay pass's measurable result.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NzbSeedReplayStats {
    /// This pass crossed the durable cursor's end and began a new cycle.
    /// Background callers can stop after observing it without mistaking a
    /// full `limit` batch for proof that more unseen sets remain.
    pub cycle_wrapped: bool,
    pub sets_examined: usize,
    pub sets_matched: usize,
    pub sets_unmatched: usize,
    pub sets_partial: usize,
    pub sets_unsettled: usize,
    pub sets_fragmented: usize,
    pub sets_unsafe: usize,
    pub sets_title_conflict: usize,
    pub sets_invalid_title: usize,
    pub sets_saturated: usize,
    pub sets_errored: usize,
    pub hash_candidates: usize,
    pub hash_candidates_rejected: usize,
    pub exact_release_matches: usize,
    pub claims_applied: usize,
    pub claims_replaced: usize,
    pub claims_confirmed: usize,
    pub claims_recorded: usize,
    pub claims_conflicted: usize,
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
    pub sets: usize,
    pub assertions: usize,
    pub files: usize,
    pub probe_ids: usize,
    pub match_edges: usize,
    pub matched_sets: usize,
    pub fragmented_sets: usize,
    pub title_conflict_sets: usize,
    pub named_release_edges: usize,
}

impl NzbSeedInventory {
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
    pub release_id: i64,
    pub exact_ids: usize,
    pub covered_data_files: usize,
    pub state: String,
    pub claim_key: String,
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
