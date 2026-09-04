//! Durable external-NZB identity seeds.
//!
//! A fetched NZB can arrive before the scanner has seen the articles it
//! names. The direct indexer and posted-NZB lanes currently try the
//! Message-ID join once and discard that evidence on a miss. This module
//! keeps the NZB's name assertion, a bounded file-aware Message-ID sample,
//! and a digest of every complete file manifest so later scans can replay
//! the join without treating the sample itself as title proof.
//!
//! The file boundary is load-bearing. A season-pack NZB often joins one
//! local release per episode; naming every quorum hit with the pack title
//! destroys the more specific episode identity. A seed may auto-name only a
//! local release whose complete canonical file manifest, including optional
//! PAR2 files, equals the seed's whole manifest. Data shards and separately
//! clustered PAR2 files can still form auditable collection edges, but never
//! inherit the collection title as row names.

use super::*;
use crate::md5fast::{Digest, Md5};
use rusqlite::OptionalExtension;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// The durable seed-replay cursor: the highest `nzb_seed_sets.id` the
/// bounded walk has finished. Public because the daemon-side proof that
/// the lap's reserved replay slice actually advances it has to read the
/// same key this module writes, and a second copy of the name in a test
/// would pass against a key nothing uses.
pub const SEED_REPLAY_CURSOR: &str = "nzb_seed_replay_at";
/// One-shot repair marker for seeds stored before the strong per-file
/// manifest key existed. See [`Index::nzb_seed_legacy_rekey_slice`].
const SEED_REKEY_FLAG: &str = "nzb_seed_rekey_v1";
const SEED_REKEY_CURSOR: &str = "nzb_seed_rekey_at";
/// Sets examined per repair pass. The realistic catalogue is a few hundred
/// legacy rows, but [`SEED_SET_CAP`] allows 65,536, so the pass is chunked
/// and resumable rather than trusting the small case.
const SEED_REKEY_CHUNK: usize = 256;
/// Chunks one `open` will drive before leaving the rest to the next one, so
/// a hostile catalogue cannot turn a one-shot repair into an unbounded stall
/// on the writer. No new legacy row can be created (the legacy write path is
/// gone from `main`), so the remainder only ever shrinks.
pub(super) const SEED_REKEY_CHUNKS_PER_OPEN: usize = 64;
/// One-shot purge marker for the residue the re-key deliberately refuses:
/// legacy-keyed sets with no strong file keys on disk at all. See
/// [`Index::nzb_seed_unrepairable_purge_slice`].
const SEED_PURGE_FLAG: &str = "nzb_seed_purge_v1";
const SEED_PURGE_CURSOR: &str = "nzb_seed_purge_at";
const SEED_PURGE_CHUNK: usize = 256;
/// Chunks one `open` will drive, for the same reason as
/// [`SEED_REKEY_CHUNKS_PER_OPEN`].
pub(super) const SEED_PURGE_CHUNKS_PER_OPEN: usize = 64;
const SEED_TABLES: [&str; 5] = [
    "nzb_seed_sets",
    "nzb_seed_assertions",
    "nzb_seed_files",
    "nzb_seed_msgids",
    "nzb_seed_matches",
];
const SEED_CLEANUP_OBJECTS: [&str; 6] = [
    "idx_nzb_seed_matches_release",
    "nzb_seed_meta",
    "nzb_seed_release_ad_v2",
    "nzb_seed_file_ai_v2",
    "nzb_seed_file_au_v2",
    "nzb_seed_file_ad_v2",
];
const SEED_FILE_CLEANUP_TRIGGER_DROP_SQL: &str = "
    DROP TRIGGER IF EXISTS nzb_seed_file_ai;
    DROP TRIGGER IF EXISTS nzb_seed_file_au;
    DROP TRIGGER IF EXISTS nzb_seed_file_ad;
    DROP TRIGGER IF EXISTS nzb_seed_file_ai_v2;
    DROP TRIGGER IF EXISTS nzb_seed_file_au_v2;
    DROP TRIGGER IF EXISTS nzb_seed_file_ad_v2;";
const SEED_FILE_CLEANUP_TRIGGER_CREATE_SQL: &str = "
     CREATE TRIGGER nzb_seed_file_ai_v2
        AFTER INSERT ON files BEGIN
       UPDATE releases SET seed_manifest_at=unixepoch()
        WHERE id=new.release_id;
       UPDATE nzb_seed_sets SET state='pending',last_reconciled=0
        WHERE id IN (SELECT set_id FROM nzb_seed_matches
                      WHERE release_id=new.release_id);
       DELETE FROM name_claims
        WHERE release_id=new.release_id AND tier='msgid-set'
          AND source LIKE 'external-nzb:%';
       UPDATE releases SET pre_title='',pre_source=''
        WHERE id=new.release_id
          AND pre_source LIKE 'proven:msgid-set:external-nzb:%';
       DELETE FROM nzb_seed_matches WHERE release_id=new.release_id;
     END;
     CREATE TRIGGER nzb_seed_file_au_v2
        AFTER UPDATE OF release_id,filename,total_parts,segments ON files BEGIN
       UPDATE releases SET seed_manifest_at=unixepoch()
        WHERE id IN (old.release_id,new.release_id);
       UPDATE nzb_seed_sets SET state='pending',last_reconciled=0
        WHERE id IN (SELECT set_id FROM nzb_seed_matches
                      WHERE release_id IN (old.release_id,new.release_id));
       DELETE FROM name_claims
        WHERE release_id IN (old.release_id,new.release_id)
          AND tier='msgid-set'
          AND source LIKE 'external-nzb:%';
       UPDATE releases SET pre_title='',pre_source=''
        WHERE id IN (old.release_id,new.release_id)
          AND pre_source LIKE 'proven:msgid-set:external-nzb:%';
       DELETE FROM nzb_seed_matches
        WHERE release_id IN (old.release_id,new.release_id);
     END;
     CREATE TRIGGER nzb_seed_file_ad_v2
        AFTER DELETE ON files BEGIN
       UPDATE releases SET seed_manifest_at=unixepoch()
        WHERE id=old.release_id;
       UPDATE nzb_seed_sets SET state='pending',last_reconciled=0
        WHERE id IN (SELECT set_id FROM nzb_seed_matches
                      WHERE release_id=old.release_id);
       DELETE FROM name_claims
        WHERE release_id=old.release_id AND tier='msgid-set'
          AND source LIKE 'external-nzb:%';
       UPDATE releases SET pre_title='',pre_source=''
        WHERE id=old.release_id
          AND pre_source LIKE 'proven:msgid-set:external-nzb:%';
       DELETE FROM nzb_seed_matches WHERE release_id=old.release_id;
     END;";
/// A field corpus topped out at 574 files. This keeps a hostile seed from
/// turning one licensed/user-supplied NZB into an unbounded SQLite write.
const SEED_FILE_CAP: usize = 4_096;
/// Message-IDs are globally unique in honest traffic. Crossing this many
/// candidate releases is therefore hostile or corrupt, not useful fan-out.
pub(super) const SEED_CANDIDATE_CAP: usize = 2_048;
/// Persisted external proof is intentionally finite. At the ordinary licensed
/// acquisition rate this retains years of history, while an aggressive source
/// cannot grow the optional proof tables forever.
pub(super) const SEED_SET_CAP: i64 = 65_536;
pub(super) const SEED_ASSERTIONS_CAP: i64 = 131_072;
/// Public assertions may consume at most one half of each shared resource.
/// Trusted assertions retain the other half and may use any public headroom.
pub(super) const SEED_POSTED_SET_CAP: i64 = SEED_SET_CAP / 2;
pub(super) const SEED_ASSERTION_CLASS_CAP: i64 = 65_536;
/// Logical proof-byte budget. The ledger charges indexed text copies plus a
/// conservative fixed cost for every logical row. It is deterministic rather
/// than a claim about SQLite page allocation.
pub(super) const SEED_CHARGED_BYTES_CAP: i64 = 1 << 30;
pub(super) const SEED_POSTED_CHARGED_BYTES_CAP: i64 = SEED_CHARGED_BYTES_CAP / 2;
const SEED_ROW_CHARGE: i64 = 256;
/// A legitimate exact membership set should not name dozens of independent
/// local releases. Keep a small audit fan-out, and saturate without writing any
/// derived edge or name when a set exceeds it.
pub(super) const SEED_MATCH_EDGE_CAP: usize = 16;
/// Titles are copied into derived claim and release rows. Bound that fan-out
/// independently from the external-proof byte ledger.
pub(super) const SEED_APPLIED_TITLE_BYTES_CAP: usize = 255;
/// A membership set normally has one assertion per permitted source. This
/// ceiling also bounds duplicate commercial history before title arbitration.
const SEED_ASSERTION_CAP: usize = 4_096;
const SEED_REPLAY_FILE_SCAN_CAP: usize = 32_768;
const SEED_REPLAY_SEGMENT_SCAN_CAP: usize = 2_000_000;
const SEED_REPLAY_SEGMENT_BYTES_SCAN_CAP: usize = 128 << 20;
const SEED_REPLAY_DECODED_TEXT_SCAN_CAP: usize = crate::nzb::limits::MAX_TEXT_BYTES;
/// Header grouping has no explicit "last file" signal. Require a complete
/// local release to remain present for this long before direct naming, then
/// use file-table triggers to withdraw the claim immediately if it changes
/// later. This avoids treating a momentarily exact growing prefix as final.
pub(super) const SEED_RELEASE_SETTLE_SECS: i64 = 15 * 60;

/// Publicly posted NZB metadata is useful membership evidence but is not a
/// trusted title assertion. Rows from this reserved source stay shadow-only;
/// a non-public source must independently assert a readable title before
/// replay or collection export can use it.
pub const NZB_SEED_POSTED_SOURCE: &str = "posted-nzb";

pub(super) fn is_external_nzb_pre_source(source: &str) -> bool {
    source.starts_with("proven:msgid-set:external-nzb:")
}

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

fn normalize_seed_metadata<'a>(
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
struct SeedProbe {
    file_ord: usize,
    part_ord: u32,
    msgid: String,
}

#[derive(Debug)]
struct SeedFileShape {
    subject: String,
    bytes: u64,
    segments: usize,
    required: bool,
    dropped: usize,
    kind: i64,
    manifest_key: String,
}

#[derive(Debug)]
struct SeedShape {
    strong_membership_key: String,
    files: Vec<SeedFileShape>,
    probes: Vec<SeedProbe>,
    data_files: usize,
    segments: usize,
    probe_complete: bool,
}

/// Validated, compact seed evidence prepared without holding an index lock.
///
/// Building full-file manifest hashes can inspect a large NZB. Background
/// callers should do that work first, then hold the database writer only for
/// [`Index::nzb_seed_store_prepared`].
#[derive(Debug)]
pub struct NzbSeedPrepared {
    shape: SeedShape,
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
struct LoadedSeed {
    id: i64,
    probe_complete: bool,
    /// Required data file -> exact-ID threshold for that file.
    required_files: BTreeMap<i64, usize>,
    /// Canonical identity of every stored file manifest. `None` keeps legacy,
    /// incomplete, or internally inconsistent proof catalogs shadow-only.
    strong_membership_key: Option<String>,
}

#[derive(Debug)]
struct ExactHit {
    release_id: i64,
    ids: Vec<String>,
    covered: BTreeSet<i64>,
    per_file: BTreeMap<i64, usize>,
    local_data_files: usize,
    matched_local_data_files: usize,
    /// Present only when every local file decoded to its declared part count.
    /// The key preserves file roles and duplicate identical manifests.
    strong_membership_key: Option<String>,
    /// The current release is complete and old enough to have crossed the
    /// conservative header-settle window.
    settled: bool,
}

enum ExactHitScan {
    Hit(ExactHit),
    Deferred,
}

impl ExactHit {
    fn manifest_qualifies(&self, seed: &LoadedSeed) -> bool {
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

    fn qualifies(&self, seed: &LoadedSeed) -> bool {
        self.settled && self.manifest_qualifies(seed)
    }
}

#[derive(Debug)]
struct HashCandidate {
    release_id: i64,
    /// External file ordinal, normalized Message-ID, and whether the
    /// external file is required data. Optional PAR2 IDs participate in
    /// the common claim key when they mapped, but never satisfy a data
    /// coverage gate.
    probes: Vec<(i64, String, bool)>,
}

#[derive(Debug, Default)]
struct SeedReplayScanBudget {
    files: usize,
    segments: usize,
    encoded_bytes: usize,
    decoded_text: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NzbSeedUsage {
    sets: i64,
    assertions: i64,
    posted_assertions: i64,
    charged_bytes: i64,
}

pub(super) enum SeedTitle {
    Missing,
    Conflict,
    One {
        assertion_id: i64,
        name: String,
        source: String,
        category: String,
    },
}

fn is_seed_value_error(error: &NzbSeedError) -> bool {
    matches!(
        error,
        NzbSeedError::Corrupt(_)
            | NzbSeedError::Sqlite(
                rusqlite::Error::FromSqlConversionFailure(..)
                    | rusqlite::Error::IntegralValueOutOfRange(..)
                    | rusqlite::Error::Utf8Error(..)
                    | rusqlite::Error::InvalidColumnType(..)
            )
    )
}

fn sqlite_u64(n: u64) -> i64 {
    n.min(i64::MAX as u64) as i64
}

fn add_seed_charge(total: &mut u64, bytes: usize, copies: u64) -> Result<(), NzbSeedError> {
    *total = total
        .checked_add(
            (bytes as u64)
                .checked_mul(copies)
                .ok_or(NzbSeedError::Capacity("charged-byte accounting overflow"))?,
        )
        .ok_or(NzbSeedError::Capacity("charged-byte accounting overflow"))?;
    Ok(())
}

/// The logical charge one stored seed set holds in
/// `nzb_seed_usage.charged_bytes`, as an SQL expression over an
/// `nzb_seed_sets` row aliased `s`, with [`SEED_ROW_CHARGE`] bound as `?1`.
///
/// This is the SQL form of [`seed_set_charge`] plus [`seed_assertion_charge`]
/// over the set's own assertions, counted from the rows that are actually on
/// disk. Both the capacity backfill and the purge refund read it, so the
/// ledger is filled and drained by one expression rather than two that can
/// drift: a set admitted by `nzb_seed_store_xml` and then purged returns
/// every counter to its pre-admission value, which
/// `admitting_a_seed_and_purging_it_returns_every_ledger_counter` pins.
const SEED_SET_LOGICAL_CHARGE_SQL: &str = "?1 * (1
      + (SELECT COUNT(*) FROM nzb_seed_files WHERE set_id=s.id)
      + (SELECT COUNT(*) FROM nzb_seed_file_keys WHERE set_id=s.id)
      + (SELECT COUNT(*) FROM nzb_seed_msgids WHERE set_id=s.id)
      + (SELECT COUNT(*) FROM nzb_seed_assertions WHERE set_id=s.id))
    + 2*LENGTH(CAST(s.membership_key AS BLOB))
    + COALESCE((SELECT SUM(LENGTH(CAST(subject AS BLOB)))
                  FROM nzb_seed_files WHERE set_id=s.id),0)
    + COALESCE((SELECT SUM(LENGTH(CAST(manifest_key AS BLOB)))
                  FROM nzb_seed_file_keys WHERE set_id=s.id),0)
    + COALESCE((SELECT SUM(2*LENGTH(CAST(msgid AS BLOB)))
                  FROM nzb_seed_msgids WHERE set_id=s.id),0)
    + COALESCE((SELECT SUM(
          2*LENGTH(CAST(source AS BLOB)) +
          2*LENGTH(CAST(source_guid AS BLOB)) +
          2*LENGTH(CAST(name AS BLOB)) +
          LENGTH(CAST(name_key AS BLOB)) +
          LENGTH(CAST(category AS BLOB)))
                  FROM nzb_seed_assertions WHERE set_id=s.id),0)";

fn seed_set_charge(shape: &SeedShape, membership_key: &str) -> Result<i64, NzbSeedError> {
    let file_rows = shape
        .files
        .len()
        .checked_mul(2)
        .ok_or(NzbSeedError::Capacity("charged-byte accounting overflow"))?;
    let rows = 1usize
        .checked_add(file_rows)
        .and_then(|rows| rows.checked_add(shape.probes.len()))
        .ok_or(NzbSeedError::Capacity("charged-byte accounting overflow"))?;
    let mut total = (rows as u64)
        .checked_mul(SEED_ROW_CHARGE as u64)
        .ok_or(NzbSeedError::Capacity("charged-byte accounting overflow"))?;
    // The unique membership index and Message-ID uniqueness index retain a
    // second copy of those text keys. Subjects and manifest digests are stored
    // only in their owning WITHOUT ROWID/table records.
    add_seed_charge(&mut total, membership_key.len(), 2)?;
    for file in &shape.files {
        add_seed_charge(&mut total, file.subject.len(), 1)?;
        add_seed_charge(&mut total, file.manifest_key.len(), 1)?;
    }
    for probe in &shape.probes {
        add_seed_charge(&mut total, probe.msgid.len(), 2)?;
    }
    i64::try_from(total).map_err(|_| NzbSeedError::Capacity("charged-byte accounting overflow"))
}

fn seed_assertion_charge(
    source: &str,
    source_guid: &str,
    name: &str,
    name_key: &str,
    category: &str,
) -> Result<i64, NzbSeedError> {
    let mut total = SEED_ROW_CHARGE as u64;
    // The source/GUID/name tuple is repeated by the assertion uniqueness
    // index. The normalized title and category are table payload only.
    add_seed_charge(&mut total, source.len(), 2)?;
    add_seed_charge(&mut total, source_guid.len(), 2)?;
    add_seed_charge(&mut total, name.len(), 2)?;
    add_seed_charge(&mut total, name_key.len(), 1)?;
    add_seed_charge(&mut total, category.len(), 1)?;
    i64::try_from(total).map_err(|_| NzbSeedError::Capacity("charged-byte accounting overflow"))
}

pub(super) fn seed_file_kind(kind: crate::nzb::FileKind) -> i64 {
    match kind {
        crate::nzb::FileKind::Data => 0,
        crate::nzb::FileKind::Par2Main => 1,
        crate::nzb::FileKind::Par2Volume => 2,
    }
}

pub(super) fn canonical_seed_local_msgid(value: &str) -> Option<&str> {
    let wrapped = value.starts_with('<') || value.ends_with('>');
    let canonical = if wrapped {
        value.strip_prefix('<')?.strip_suffix('>')?
    } else {
        value
    };
    if canonical.is_empty()
        || canonical.len() > crate::nzb::limits::MAX_WIRE_TOKEN
        || !crate::nzb::is_wire_safe(canonical)
    {
        None
    } else {
        Some(canonical)
    }
}

fn corrupt_seed_candidate(message: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        2,
        rusqlite::types::Type::Blob,
        Box::new(NzbSeedError::Corrupt(message)),
    )
}

fn choose_seed_title(
    rows: Vec<(i64, String, String, String, String)>,
    assertion_limit: usize,
) -> SeedTitle {
    if rows.len() > assertion_limit {
        return SeedTitle::Conflict;
    }
    let mut names: BTreeMap<String, (i64, String, String, String)> = BTreeMap::new();
    for (assertion_id, name, key, source, category) in rows {
        let valid = !key.is_empty()
            && name.len() <= SEED_APPLIED_TITLE_BYTES_CAP
            && !name.contains('/')
            && !name.contains('\\')
            && !name.starts_with('.')
            && crate::release::stem_is_a_name(&name);
        if valid {
            names
                .entry(key)
                .or_insert((assertion_id, name, source, category));
        }
    }
    match names.len() {
        0 => SeedTitle::Missing,
        1 => {
            let (_, (assertion_id, name, source, category)) = names.into_iter().next().unwrap();
            SeedTitle::One {
                assertion_id,
                name,
                source,
                category,
            }
        }
        _ => SeedTitle::Conflict,
    }
}

/// Strong, filename-independent identity for one NZB file.
///
/// The bounded replay table retains only a few raw probes per file. This
/// digest commits to the complete normalized `(part, Message-ID)` manifest,
/// its role and any parser-dropped entries, so a collection export can prove
/// the whole file after the source NZB itself has gone away. SHA-256 is used
/// here rather than the legacy membership key's MD5 because source NZBs are
/// untrusted input and this key is an acceptance boundary, not a prefilter.
pub(super) fn seed_file_manifest_key<'a>(
    kind: crate::nzb::FileKind,
    dropped: usize,
    parts: impl IntoIterator<Item = (u32, &'a str)>,
) -> String {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;

    let mut parts: Vec<(u32, &str)> = parts
        .into_iter()
        .map(|(part, id)| (part, claims::norm_msgid(id)))
        .collect();
    parts.sort_unstable();
    parts.dedup();
    let mut h = Sha256::new();
    h.update((parts.len() as u64).to_le_bytes());
    h.update((dropped as u64).to_le_bytes());
    h.update([seed_file_kind(kind) as u8]);
    for (part, id) in parts {
        h.update(part.to_le_bytes());
        h.update((id.len() as u64).to_le_bytes());
        h.update(id.as_bytes());
    }
    let digest = h.finalize();
    let mut key = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut key, "{byte:02x}").expect("formatting into String cannot fail");
    }
    key
}

/// What one [`Index::nzb_seed_legacy_rekey_slice`] pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NzbSeedRekeyStats {
    /// Legacy-keyed sets read this pass.
    pub examined: usize,
    /// Sets whose stored key was replaced by the recomputed strong key.
    pub rekeyed: usize,
    /// Sets whose strong key is already held by another set, so the legacy
    /// row is a duplicate of a healthy one and is left alone.
    pub collided: usize,
    /// Sets with missing, short or non-strong file keys. Nothing on disk can
    /// rebuild their identity, so they are left for a later re-grab.
    pub unrepairable: usize,
    /// No legacy set remains; the marker is stamped and this will not run
    /// again.
    pub done: bool,
}

/// What one [`Index::nzb_seed_unrepairable_purge_slice`] pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NzbSeedPurgeStats {
    /// Legacy-keyed sets read this pass.
    pub examined: usize,
    /// Sets deleted: legacy-keyed, no strong file keys on disk, no name
    /// claim resting on them.
    pub purged: usize,
    /// Sets left alone because their strong key IS on disk, so
    /// [`Index::nzb_seed_legacy_rekey_slice`] owns them.
    pub kept: usize,
    /// Sets left alone because a `name_claims` row still rests on one of
    /// their match edges. By construction there should be none - a set
    /// without a verified strong key never reaches the naming branch - and
    /// this counter is how that construction is checked rather than assumed.
    pub claimed: usize,
    /// No legacy set remains; the marker is stamped and this will not run
    /// again.
    pub done: bool,
}

fn strong_seed_membership_key_from_files(mut file_keys: Vec<(i64, String)>) -> String {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;

    file_keys.sort_unstable();
    let mut hash = Sha256::new();
    hash.update(b"nzbfast:nzb-seed-set:v1\0");
    hash.update((file_keys.len() as u64).to_le_bytes());
    for (kind, key) in &file_keys {
        hash.update(kind.to_le_bytes());
        hash.update((key.len() as u64).to_le_bytes());
        hash.update(key.as_bytes());
    }
    let digest = hash.finalize();
    let mut key = String::with_capacity(7 + digest.len() * 2);
    key.push_str("sha256:");
    for byte in digest {
        write!(&mut key, "{byte:02x}").expect("formatting into String cannot fail");
    }
    key
}

fn is_strong_seed_file_key(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(super) fn strong_membership_key(nzb: &crate::nzb::Nzb) -> String {
    strong_seed_membership_key_from_files(
        nzb.files
            .iter()
            .map(|file| {
                let kind = file.kind();
                (
                    seed_file_kind(kind),
                    seed_file_manifest_key(
                        kind,
                        file.dropped_segments,
                        file.segments
                            .iter()
                            .map(|segment| (segment.number, segment.message_id.as_str())),
                    ),
                )
            })
            .collect(),
    )
}

pub(super) fn membership_key(nzb: &crate::nzb::Nzb) -> String {
    // Hash canonical per-file membership, then sort those hashes. File
    // order and source formatting may differ across two copies of the same
    // NZB; file boundaries and part numbers may not.
    let mut file_keys = Vec::with_capacity(nzb.files.len());
    for file in &nzb.files {
        let mut parts: Vec<(u32, &str)> = file
            .segments
            .iter()
            .map(|s| (s.number, claims::norm_msgid(&s.message_id)))
            .collect();
        parts.sort_unstable();
        parts.dedup();
        let mut h = Md5::new();
        h.update((parts.len() as u64).to_le_bytes());
        h.update((file.dropped_segments as u64).to_le_bytes());
        h.update([match file.kind() {
            crate::nzb::FileKind::Data => 0,
            crate::nzb::FileKind::Par2Main => 1,
            crate::nzb::FileKind::Par2Volume => 2,
        }]);
        for (part, id) in parts {
            h.update(part.to_le_bytes());
            h.update((id.len() as u64).to_le_bytes());
            h.update(id.as_bytes());
        }
        file_keys.push(crate::par2::hex16(&h.finalize().into()));
    }
    file_keys.sort();
    let mut h = Md5::new();
    h.update((file_keys.len() as u64).to_le_bytes());
    for key in file_keys {
        h.update(key.as_bytes());
    }
    crate::par2::hex16(&h.finalize().into())
}

fn validate_seed_input(nzb: &crate::nzb::Nzb, text_limit: usize) -> Result<(), NzbSeedError> {
    let mut retained_segments = 0usize;
    let mut retained_text = 0usize;
    let mut all_ids = HashSet::new();
    for file in &nzb.files {
        if file.subject.len() > crate::nzb::limits::MAX_FIELD {
            return Err(NzbSeedError::Invalid("file subject is too long"));
        }
        retained_text = retained_text
            .checked_add(file.subject.len())
            .ok_or(NzbSeedError::Invalid("NZB text exceeds limit"))?;
        retained_segments = retained_segments
            .checked_add(file.segments.len())
            .and_then(|count| count.checked_add(file.dropped_segments))
            .ok_or(NzbSeedError::Invalid("too many segments"))?;
        if file.segments.len().saturating_add(file.dropped_segments) == 0 {
            return Err(NzbSeedError::Invalid("NZB contains an empty file"));
        }
        if retained_segments > crate::nzb::limits::MAX_SEGMENTS {
            return Err(NzbSeedError::Invalid("too many segments"));
        }
        let mut parts = HashSet::with_capacity(file.segments.len());
        for segment in &file.segments {
            let canonical = claims::norm_msgid(&segment.message_id);
            if segment.number == 0
                || canonical.is_empty()
                || canonical != segment.message_id
                || canonical.len() > crate::nzb::limits::MAX_WIRE_TOKEN
                || !crate::nzb::is_wire_safe(canonical)
            {
                return Err(NzbSeedError::Invalid(
                    "NZB contains a non-canonical segment",
                ));
            }
            retained_text = retained_text
                .checked_add(canonical.len())
                .ok_or(NzbSeedError::Invalid("NZB text exceeds limit"))?;
            if retained_text > text_limit {
                return Err(NzbSeedError::Invalid("NZB text exceeds limit"));
            }
            if !parts.insert(segment.number) || !all_ids.insert(canonical) {
                return Err(NzbSeedError::Invalid(
                    "NZB contains ambiguous segment identity",
                ));
            }
        }
    }
    if retained_text > text_limit {
        return Err(NzbSeedError::Invalid("NZB text exceeds limit"));
    }
    Ok(())
}

fn seed_shape(nzb: &crate::nzb::Nzb) -> Result<SeedShape, NzbSeedError> {
    if nzb.files.len() > SEED_FILE_CAP {
        return Err(NzbSeedError::Invalid("too many files"));
    }
    validate_seed_input(nzb, crate::nzb::limits::MAX_TEXT_BYTES)?;
    let has_data = nzb
        .files
        .iter()
        .any(|f| f.kind() == crate::nzb::FileKind::Data);
    if !has_data {
        return Err(NzbSeedError::Invalid("NZB has no data files"));
    }
    let files: Vec<SeedFileShape> = nzb
        .files
        .iter()
        .map(|f| {
            let kind = f.kind();
            SeedFileShape {
                subject: f.subject.clone(),
                bytes: f.bytes(),
                segments: f.segments.len() + f.dropped_segments,
                required: kind == crate::nzb::FileKind::Data,
                dropped: f.dropped_segments,
                kind: seed_file_kind(kind),
                manifest_key: seed_file_manifest_key(
                    kind,
                    f.dropped_segments,
                    f.segments
                        .iter()
                        .map(|segment| (segment.number, segment.message_id.as_str())),
                ),
            }
        })
        .collect();
    let data_files = files.iter().filter(|f| f.required).count();
    let segments = files.iter().map(|f| f.segments).sum();

    // Breadth first, required files before optional PAR2 files. This gives
    // every data file a join key before a large file consumes the budget.
    let mut probes = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut per_file = vec![0usize; files.len()];
    // `Nzb::parse` part-sorts these already, but callers may also pass a
    // programmatic Nzb. Sort references once per file and reuse them for
    // every probe round. Rebuilding and sorting a million-segment vector
    // eight times turns the parser's bounded input into avoidable work.
    let ordered: Vec<Vec<&crate::nzb::Segment>> = nzb
        .files
        .iter()
        .map(|file| {
            let mut segments: Vec<_> = file.segments.iter().collect();
            segments.sort_unstable_by_key(|s| (s.number, s.message_id.as_str()));
            segments
        })
        .collect();
    let desired_per_file: Vec<usize> = ordered
        .iter()
        .enumerate()
        .map(|(i, segments)| {
            if !files[i].required {
                return 0;
            }
            let mut unique = HashSet::with_capacity(MSGID_KEYS_PER_FILE);
            for seg in segments {
                unique.insert(claims::norm_msgid(&seg.message_id));
                if unique.len() == MSGID_KEYS_PER_FILE {
                    break;
                }
            }
            unique.len()
        })
        .collect();
    let mut duplicate_across_files = false;
    'rounds: for required in [true, false] {
        for round in 0..crate::nzbimport::PROBES_PER_FILE {
            for (file_ord, file) in ordered.iter().enumerate() {
                if files[file_ord].required != required {
                    continue;
                }
                let Some(seg) = file.get(round) else {
                    continue;
                };
                let id = claims::norm_msgid(&seg.message_id).to_string();
                match seen.get(&id) {
                    Some(&other) => {
                        duplicate_across_files |= other != file_ord;
                        continue;
                    }
                    None => {
                        seen.insert(id.clone(), file_ord);
                    }
                }
                probes.push(SeedProbe {
                    file_ord,
                    part_ord: seg.number,
                    msgid: id,
                });
                per_file[file_ord] += 1;
                if probes.len() >= crate::nzbimport::PROBE_CAP {
                    break 'rounds;
                }
            }
        }
    }
    let required_complete = files
        .iter()
        .enumerate()
        .all(|(i, f)| !f.required || (per_file[i] >= desired_per_file[i] && f.dropped == 0));
    let probe_complete = required_complete
        && !duplicate_across_files
        && probes.len() >= crate::nzbimport::MIN_MSGID_QUORUM;
    let strong_membership_key = strong_seed_membership_key_from_files(
        files
            .iter()
            .map(|file| (file.kind, file.manifest_key.clone()))
            .collect(),
    );
    Ok(SeedShape {
        strong_membership_key,
        files,
        probes,
        data_files,
        segments,
        probe_complete,
    })
}

impl Index {
    pub(super) fn nzb_seed_schema_present_on(db: &Connection) -> rusqlite::Result<bool> {
        let mut stmt = db.prepare_cached(
            "SELECT COUNT(*) FROM sqlite_master
              WHERE type='table' AND name IN (?1,?2,?3,?4,?5)",
        )?;
        let count: i64 = stmt.query_row(SEED_TABLES, |r| r.get(0))?;
        Ok(count == SEED_TABLES.len() as i64)
    }

    pub(super) fn nzb_seed_schema_present(&self) -> rusqlite::Result<bool> {
        Self::nzb_seed_schema_present_on(&self.db)
    }

    pub(super) fn nzb_seed_file_key_schema_present(&self) -> rusqlite::Result<bool> {
        self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master
               WHERE type='table' AND name='nzb_seed_file_keys')",
            [],
            |row| row.get(0),
        )
    }

    fn nzb_seed_file_cleanup_present_on(db: &Connection) -> rusqlite::Result<bool> {
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM sqlite_master
              WHERE type='trigger' AND tbl_name='files'
                AND name IN (?1,?2,?3)",
            rusqlite::params![
                SEED_CLEANUP_OBJECTS[3],
                SEED_CLEANUP_OBJECTS[4],
                SEED_CLEANUP_OBJECTS[5]
            ],
            |row| row.get(0),
        )?;
        Ok(count == 3)
    }

    fn nzb_seed_cleanup_present(&self) -> rusqlite::Result<bool> {
        let count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM sqlite_master
              WHERE (type='index' AND tbl_name='nzb_seed_matches' AND name=?1)
                 OR (type='table' AND name=?2)
                 OR (type='trigger' AND tbl_name='releases' AND name=?3)",
            rusqlite::params![
                SEED_CLEANUP_OBJECTS[0],
                SEED_CLEANUP_OBJECTS[1],
                SEED_CLEANUP_OBJECTS[2]
            ],
            |row| row.get(0),
        )?;
        Ok(count == 3 && Self::nzb_seed_file_cleanup_present_on(&self.db)?)
    }

    /// Move the optional seed revocation triggers to the current `files`
    /// table after a table-rebuild swap. The caller supplies the active
    /// transaction connection so the rename, reinstall, and validation
    /// publish atomically. A database without the optional seed catalog is
    /// left untouched.
    pub(super) fn reinstall_nzb_seed_file_cleanup_triggers_on(
        db: &Connection,
    ) -> rusqlite::Result<()> {
        if !Self::nzb_seed_schema_present_on(db)? {
            return Ok(());
        }
        Self::drop_nzb_seed_file_cleanup_triggers_on(db)?;
        db.execute_batch(SEED_FILE_CLEANUP_TRIGGER_CREATE_SQL)?;
        if !Self::nzb_seed_file_cleanup_present_on(db)? {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_SCHEMA),
                Some("external NZB seed cleanup triggers are not attached to files".to_string()),
            ));
        }
        Ok(())
    }

    pub(super) fn drop_nzb_seed_file_cleanup_triggers_on(db: &Connection) -> rusqlite::Result<()> {
        db.execute_batch(SEED_FILE_CLEANUP_TRIGGER_DROP_SQL)
    }

    pub(super) fn ensure_nzb_seed_schema(&self) -> rusqlite::Result<()> {
        let had_tables = self.nzb_seed_schema_present()?;
        let had_cleanup = had_tables && self.nzb_seed_cleanup_present()?;
        if had_tables && had_cleanup {
            return Ok(());
        }
        self.db.execute_batch("SAVEPOINT nzb_seed_schema")?;
        let install = (|| -> rusqlite::Result<()> {
            self.db.execute_batch(
                "CREATE TABLE IF NOT EXISTS nzb_seed_sets(
                id INTEGER PRIMARY KEY,
                membership_key TEXT NOT NULL UNIQUE,
                file_count INTEGER NOT NULL,
                data_files INTEGER NOT NULL,
                segment_count INTEGER NOT NULL,
                probe_count INTEGER NOT NULL,
                probe_complete INTEGER NOT NULL,
                state TEXT NOT NULL DEFAULT 'pending',
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                last_reconciled INTEGER NOT NULL DEFAULT 0,
                reconcile_count INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS nzb_seed_assertions(
                id INTEGER PRIMARY KEY,
                set_id INTEGER NOT NULL,
                source TEXT NOT NULL,
                source_guid TEXT NOT NULL,
                name TEXT NOT NULL,
                name_key TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT '',
                posted INTEGER NOT NULL DEFAULT 0,
                bytes INTEGER NOT NULL DEFAULT 0,
                acquired_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                UNIQUE(source, source_guid, set_id, name));
             CREATE INDEX IF NOT EXISTS idx_nzb_seed_assertions_set
                ON nzb_seed_assertions(set_id);
             CREATE TABLE IF NOT EXISTS nzb_seed_files(
                set_id INTEGER NOT NULL,
                file_ord INTEGER NOT NULL,
                subject TEXT NOT NULL,
                bytes INTEGER NOT NULL,
                segments INTEGER NOT NULL,
                required INTEGER NOT NULL,
                PRIMARY KEY(set_id, file_ord)) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS nzb_seed_msgids(
                set_id INTEGER NOT NULL,
                file_ord INTEGER NOT NULL,
                part_ord INTEGER NOT NULL,
                msgid TEXT NOT NULL,
                h INTEGER NOT NULL,
                PRIMARY KEY(set_id, file_ord, part_ord),
                UNIQUE(set_id, msgid)) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS idx_nzb_seed_msgids_set
                ON nzb_seed_msgids(set_id);
             CREATE INDEX IF NOT EXISTS idx_nzb_seed_msgids_hash
                ON nzb_seed_msgids(h,set_id);
             CREATE TABLE IF NOT EXISTS nzb_seed_matches(
                set_id INTEGER NOT NULL,
                release_id INTEGER NOT NULL,
                exact_ids INTEGER NOT NULL,
                covered_data_files INTEGER NOT NULL,
                state TEXT NOT NULL,
                claim_key TEXT NOT NULL DEFAULT '',
                at INTEGER NOT NULL,
                PRIMARY KEY(set_id, release_id)) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS idx_nzb_seed_matches_state
                ON nzb_seed_matches(state);
             DROP INDEX IF EXISTS idx_nzb_seed_matches_release;
             CREATE INDEX IF NOT EXISTS idx_nzb_seed_matches_release
                ON nzb_seed_matches(release_id);
             CREATE TABLE IF NOT EXISTS nzb_seed_meta(
                id INTEGER PRIMARY KEY CHECK(id=1),
                schema_at INTEGER NOT NULL);
             INSERT OR IGNORE INTO nzb_seed_meta(id,schema_at)
                VALUES(1,unixepoch());
             DROP TRIGGER IF EXISTS nzb_seed_release_ad;
             DROP TRIGGER IF EXISTS nzb_seed_release_ad_v2;
             DROP TRIGGER IF EXISTS nzb_seed_file_ai;
             DROP TRIGGER IF EXISTS nzb_seed_file_au;
             DROP TRIGGER IF EXISTS nzb_seed_file_ad;
             CREATE TRIGGER IF NOT EXISTS nzb_seed_release_ad_v2
                AFTER DELETE ON releases BEGIN
               DELETE FROM nzb_seed_matches
                WHERE release_id=old.id AND release_id>0;
             END;",
            )?;
            Self::reinstall_nzb_seed_file_cleanup_triggers_on(&self.db)?;
            if !self.nzb_seed_cleanup_present()? {
                return Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_SCHEMA),
                    Some("external NZB seed cleanup objects have invalid ownership".to_string()),
                ));
            }
            if had_tables && !had_cleanup {
                // A prototype DB created before the release-delete trigger
                // may already contain an edge to a recycled releases rowid.
                // The trigger/index and this purge publish in one commit, so
                // a crash can never leave the marker without the repair.
                // Early prototypes keyed claims by a sampled candidate ID set.
                // Once their only set/release attribution edge is gone, those
                // keys cannot be reconstructed safely. Withdraw all external
                // MsgidSet claims during the same repair transaction and let
                // current strong manifests replay them.
                self.db.execute(
                    "DELETE FROM name_claims WHERE tier='msgid-set'
                      AND source LIKE 'external-nzb:%'",
                    [],
                )?;
                self.db.execute(
                    "UPDATE releases SET pre_title='',pre_source=''
                      WHERE pre_source LIKE 'proven:msgid-set:external-nzb:%'",
                    [],
                )?;
                self.db.execute("DELETE FROM nzb_seed_matches", [])?;
                self.db.execute(
                    "UPDATE nzb_seed_sets SET state='pending',last_reconciled=0",
                    [],
                )?;
            }
            Ok(())
        })();
        match install {
            Ok(()) => self.db.execute_batch("RELEASE nzb_seed_schema")?,
            Err(error) => {
                let _ = self
                    .db
                    .execute_batch("ROLLBACK TO nzb_seed_schema; RELEASE nzb_seed_schema");
                return Err(error);
            }
        }
        // Runtime DDL invalidates pooled readers just like the named-feed
        // and summary prototypes. The daemon drains this bit after a write.
        self.ddl.set(true);
        Ok(())
    }

    /// Re-key seeds stored before the strong per-file manifest key existed.
    ///
    /// # Why these sets are otherwise dead
    ///
    /// [`Self::verified_nzb_seed_membership_key`] recomputes a `sha256:` key
    /// from `nzb_seed_file_keys` and returns `None` unless it equals the
    /// stored `membership_key`. A legacy key is a bare MD5 hex digest, which
    /// can never equal a `sha256:`-prefixed string, so every replay files the
    /// set `unsafe` ([`Self::reconcile_one_nzb_seed_locked`]) and it can never
    /// name anything however far the reverse map fills. Measured on the live
    /// index 2 Sep 2026: 237 of 248 sets carrying a trusted external title
    /// were pinned this way, and the sweep kept re-reconciling them to the
    /// same dead end
    /// (`research/SEED-COLLECTION-SIZING-2026-09-02.md`).
    ///
    /// # Why a rewrite is sound rather than a fresh grab
    ///
    /// The strong key is a pure function of the per-file kinds and manifest
    /// digests already stored, so this recomputes exactly the string the
    /// verifier will compute and rewrites nothing else. A set whose file keys
    /// are absent, short or not strong digests is NOT repaired: its identity
    /// genuinely is not on disk, and inventing one would be the "fix the gate,
    /// not the site" edit. Those wait for a later grab to seed them cleanly.
    ///
    /// `membership_key` is UNIQUE, so a legacy set whose strong key is already
    /// held by a newer row is a second copy of the same NZB. That row is left
    /// exactly as it is: the healthy twin already carries the evidence, and
    /// merging their assertions could manufacture a title conflict out of one
    /// source agreeing with itself.
    ///
    /// Repaired sets return to `pending` with their stale match edges dropped,
    /// because those edges were written against an identity the set no longer
    /// has. No `name_claims` row can exist for them: a set without a verified
    /// strong key never reaches the naming branch at all.
    pub fn nzb_seed_legacy_rekey_slice(&self) -> rusqlite::Result<NzbSeedRekeyStats> {
        let mut stats = NzbSeedRekeyStats::default();
        if self.kv_get(SEED_REKEY_FLAG).is_some() || !self.nzb_seed_schema_present()? {
            stats.done = true;
            return Ok(stats);
        }
        if !self.nzb_seed_file_key_schema_present()? {
            // Nothing can be recomputed without the file-key table, and an
            // index that never had it also never had a strong key to drift
            // from. Leave the marker unset so a later open retries.
            return Ok(stats);
        }
        let cursor = self
            .kv_get(SEED_REKEY_CURSOR)
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0);
        let legacy: Vec<(i64, usize, usize)> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT id,file_count,LENGTH(CAST(membership_key AS BLOB))
                   FROM nzb_seed_sets
                  WHERE id>?1 AND membership_key NOT LIKE 'sha256:%'
                  ORDER BY id LIMIT ?2",
            )?;
            stmt.query_map(rusqlite::params![cursor, SEED_REKEY_CHUNK as i64], |row| {
                Ok((
                    row.get(0)?,
                    row.get::<_, i64>(1)?.max(0) as usize,
                    row.get::<_, i64>(2)?.max(0) as usize,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        let exhausted = legacy.len() < SEED_REKEY_CHUNK;
        self.db.execute_batch("SAVEPOINT nzb_seed_rekey")?;
        let repair = (|| -> rusqlite::Result<()> {
            let mut charge_delta = 0i64;
            let mut last = cursor;
            for (set_id, file_count, stored_len) in &legacy {
                stats.examined += 1;
                last = *set_id;
                let Some(strong) = self.strong_key_from_stored_file_keys(*set_id, *file_count)?
                else {
                    stats.unrepairable += 1;
                    continue;
                };
                let updated = self.db.execute(
                    "UPDATE OR IGNORE nzb_seed_sets
                        SET membership_key=?2,state='pending',last_reconciled=0
                      WHERE id=?1",
                    rusqlite::params![set_id, &strong],
                )?;
                if updated == 0 {
                    stats.collided += 1;
                    continue;
                }
                self.db
                    .execute("DELETE FROM nzb_seed_matches WHERE set_id=?1", [set_id])?;
                stats.rekeyed += 1;
                // The unique membership index keeps a second copy of the key,
                // which is the same factor admission charged for the old one.
                charge_delta += 2 * (strong.len() as i64 - *stored_len as i64);
            }
            // A prototype catalogue can carry seed tables with no capacity
            // ledger at all, and this repair runs on the open path where a
            // "no such table" would refuse the whole index. There is no
            // accounting to keep when there is no ledger.
            if charge_delta != 0 && self.nzb_seed_capacity_schema_present()? {
                self.db.execute(
                    "UPDATE nzb_seed_usage
                        SET charged_bytes=MAX(0,charged_bytes+?1) WHERE id=1",
                    [charge_delta],
                )?;
            }
            self.kv_set(SEED_REKEY_CURSOR, &last.to_string())?;
            if exhausted {
                self.kv_set(SEED_REKEY_FLAG, "1")?;
            }
            Ok(())
        })();
        match repair {
            Ok(()) => self.db.execute_batch("RELEASE nzb_seed_rekey")?,
            Err(error) => {
                let _ = self
                    .db
                    .execute_batch("ROLLBACK TO nzb_seed_rekey; RELEASE nzb_seed_rekey");
                return Err(error);
            }
        }
        stats.done = exhausted;
        Ok(stats)
    }

    /// Delete the residue [`Self::nzb_seed_legacy_rekey_slice`] deliberately
    /// refuses, so a later grab of the same NZB re-seeds it cleanly.
    ///
    /// A set whose `membership_key` is legacy AND whose strong per-file
    /// manifests are not on disk can never express its own identity: the
    /// re-key will not invent one, so the set replays to `unsafe` forever,
    /// can never name a row, and costs a replay slot every lap. Measured on
    /// the live catalogue on 2 Sep 2026: 237 legacy sets, 220 repairable in
    /// place by the re-key, 17 in exactly this shape
    /// (`research/SEED-COLLECTION-SIZING-2026-09-02.md` sections 5 and 10).
    ///
    /// This is a SEPARATE pass from the re-key on purpose. The re-key's
    /// refusal to invent an identity is pinned by tests of its own
    /// (`a_legacy_seed_without_strong_file_keys_waits_for_a_later_grab` and
    /// the short-manifest case beside it), and folding a delete into that
    /// branch would have meant rewriting what those tests assert. The
    /// predicate is not duplicated: this pass asks the same
    /// [`Self::strong_key_from_stored_file_keys`] and acts only where it
    /// answers `None`, so the two passes cannot disagree about which sets
    /// are which. Order between them does not matter for correctness.
    ///
    /// Three guards, in the order they are cheapest to check:
    /// a `sha256:` key is never even selected; a set whose strong key IS on
    /// disk is kept for the re-key; and a set with any surviving name claim
    /// is kept whatever its key says.
    ///
    /// Like the re-key this runs on the writer's open path, where an error
    /// refuses the whole index rather than skipping a repair. Two things keep
    /// that widening small: a catalogue with no `nzb_seed_file_keys` table at
    /// all is left entirely alone (there, EVERY set reads as "no keys on
    /// disk"), and every ledger decrement is clamped in SQL, so a ledger that
    /// has already drifted cannot trip a `CHECK` and turn a repair into a
    /// refused open.
    pub fn nzb_seed_unrepairable_purge_slice(&self) -> rusqlite::Result<NzbSeedPurgeStats> {
        let mut stats = NzbSeedPurgeStats::default();
        if self.kv_get(SEED_PURGE_FLAG).is_some() || !self.nzb_seed_schema_present()? {
            stats.done = true;
            return Ok(stats);
        }
        if !self.nzb_seed_file_key_schema_present()? {
            // Without that table every set on the catalogue reads as "no
            // strong keys on disk", so running here would purge the whole
            // catalogue on the strength of a missing table rather than a
            // missing identity. Leave the marker unset so a later open, once
            // the table exists, retries against real evidence.
            return Ok(stats);
        }
        let cursor = self
            .kv_get(SEED_PURGE_CURSOR)
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0);
        let legacy: Vec<(i64, usize)> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT id,file_count FROM nzb_seed_sets
                  WHERE id>?1 AND membership_key NOT LIKE 'sha256:%'
                  ORDER BY id LIMIT ?2",
            )?;
            stmt.query_map(rusqlite::params![cursor, SEED_PURGE_CHUNK as i64], |row| {
                Ok((row.get(0)?, row.get::<_, i64>(1)?.max(0) as usize))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        let exhausted = legacy.len() < SEED_PURGE_CHUNK;
        self.db.execute_batch("SAVEPOINT nzb_seed_purge")?;
        let purge = (|| -> rusqlite::Result<()> {
            let mut last = cursor;
            for (set_id, file_count) in &legacy {
                stats.examined += 1;
                last = *set_id;
                if self
                    .strong_key_from_stored_file_keys(*set_id, *file_count)?
                    .is_some()
                {
                    stats.kept += 1;
                    continue;
                }
                if !self.nzb_seed_prior_claim_keys(*set_id)?.is_empty() {
                    stats.claimed += 1;
                    continue;
                }
                self.delete_nzb_seed_set(*set_id)?;
                stats.purged += 1;
            }
            self.kv_set(SEED_PURGE_CURSOR, &last.to_string())?;
            if exhausted {
                self.kv_set(SEED_PURGE_FLAG, "1")?;
            }
            Ok(())
        })();
        match purge {
            Ok(()) => self.db.execute_batch("RELEASE nzb_seed_purge")?,
            Err(error) => {
                let _ = self
                    .db
                    .execute_batch("ROLLBACK TO nzb_seed_purge; RELEASE nzb_seed_purge");
                return Err(error);
            }
        }
        stats.done = exhausted;
        Ok(stats)
    }

    /// Remove one seed set and every row that hangs off it, giving the
    /// capacity ledger back exactly what admission took.
    ///
    /// There are no cascading foreign keys on the seed catalogue, so each
    /// child table is named. The refund is read BEFORE the first delete,
    /// from [`SEED_SET_LOGICAL_CHARGE_SQL`] - the same expression the ledger
    /// was filled by - so a set admitted and then deleted leaves every
    /// counter where it started. Callers hold the savepoint.
    ///
    /// Each decrement is clamped, and `posted_assertions` is additionally
    /// held at or below the new `assertions`. That is not defensive noise:
    /// this runs on the open path, and an already-drifted ledger meeting a
    /// bare subtraction would trip a `CHECK` and refuse the index rather
    /// than repair it.
    pub(super) fn delete_nzb_seed_set(&self, set_id: i64) -> rusqlite::Result<()> {
        // A prototype catalogue can carry seed tables with no capacity ledger
        // at all; there is no accounting to keep when there is no ledger.
        let ledger = self.nzb_seed_capacity_schema_present()?;
        let refund = if ledger {
            self.nzb_seed_set_logical_charge(set_id)?
        } else {
            0
        };
        let (assertions, posted): (i64, i64) = self.db.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN source=?2 THEN 1 ELSE 0 END),0)
               FROM nzb_seed_assertions WHERE set_id=?1",
            rusqlite::params![set_id, NZB_SEED_POSTED_SOURCE],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        for sql in [
            "DELETE FROM nzb_seed_matches WHERE set_id=?1",
            "DELETE FROM nzb_seed_msgids WHERE set_id=?1",
            "DELETE FROM nzb_seed_file_keys WHERE set_id=?1",
            "DELETE FROM nzb_seed_files WHERE set_id=?1",
            "DELETE FROM nzb_seed_assertions WHERE set_id=?1",
            "DELETE FROM nzb_seed_sets WHERE id=?1",
        ] {
            self.db.execute(sql, [set_id])?;
        }
        if ledger {
            self.db.execute(
                "UPDATE nzb_seed_usage
                    SET sets=MAX(0,sets-1),
                        assertions=MAX(0,assertions-?1),
                        posted_assertions=MIN(MAX(0,posted_assertions-?2),
                                              MAX(0,assertions-?1)),
                        charged_bytes=MAX(0,charged_bytes-?3)
                  WHERE id=1",
                rusqlite::params![assertions, posted, refund],
            )?;
        }
        Ok(())
    }

    /// What one stored set contributes to `nzb_seed_usage.charged_bytes`.
    /// Visible to `seed_tests` so the ledger round-trip can be measured
    /// against a pristine set rather than one a test has already edited.
    pub(super) fn nzb_seed_set_logical_charge(&self, set_id: i64) -> rusqlite::Result<i64> {
        self.db.query_row(
            &format!(
                "SELECT {SEED_SET_LOGICAL_CHARGE_SQL}
                   FROM nzb_seed_sets s WHERE s.id=?2"
            ),
            rusqlite::params![SEED_ROW_CHARGE, set_id],
            |row| row.get(0),
        )
    }

    /// The strong membership key this set's stored file keys imply, or `None`
    /// when they cannot express one. Unlike
    /// [`Self::verified_nzb_seed_membership_key`] this does not compare
    /// against the stored key, because the whole point here is that the
    /// stored key is the wrong format.
    fn strong_key_from_stored_file_keys(
        &self,
        set_id: i64,
        file_count: usize,
    ) -> rusqlite::Result<Option<String>> {
        if file_count == 0 {
            return Ok(None);
        }
        let keys: Vec<(i64, String)> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT kind,manifest_key FROM nzb_seed_file_keys
                  WHERE set_id=?1 ORDER BY file_ord",
            )?;
            stmt.query_map([set_id], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        if keys.len() != file_count
            || keys
                .iter()
                .any(|(kind, key)| !matches!(*kind, 0..=2) || !is_strong_seed_file_key(key))
        {
            return Ok(None);
        }
        Ok(Some(strong_seed_membership_key_from_files(keys)))
    }

    fn ensure_nzb_seed_file_key_schema(&self) -> rusqlite::Result<()> {
        if self.nzb_seed_file_key_schema_present()? {
            return Ok(());
        }
        self.db
            .execute_batch("SAVEPOINT nzb_seed_file_keys_schema")?;
        let install = self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS nzb_seed_file_keys(
                set_id INTEGER NOT NULL,
                file_ord INTEGER NOT NULL,
                kind INTEGER NOT NULL,
                manifest_key TEXT NOT NULL,
                PRIMARY KEY(set_id,file_ord)) WITHOUT ROWID;",
        );
        match install {
            Ok(()) => self.db.execute_batch("RELEASE nzb_seed_file_keys_schema")?,
            Err(error) => {
                let _ = self.db.execute_batch(
                    "ROLLBACK TO nzb_seed_file_keys_schema;
                     RELEASE nzb_seed_file_keys_schema",
                );
                return Err(error);
            }
        }
        self.ddl.set(true);
        Ok(())
    }

    pub(super) fn nzb_seed_capacity_schema_present(&self) -> rusqlite::Result<bool> {
        let objects: bool = self.db.query_row(
            "SELECT (SELECT EXISTS(SELECT 1 FROM sqlite_master
                       WHERE type='table' AND name='nzb_seed_usage'))
                  AND (SELECT EXISTS(SELECT 1 FROM sqlite_master
                       WHERE type='index'
                         AND name='idx_nzb_seed_assertions_trusted'))",
            [],
            |row| row.get(0),
        )?;
        if !objects {
            return Ok(false);
        }
        self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM nzb_seed_usage WHERE id=1)",
            [],
            |row| row.get(0),
        )
    }

    fn ensure_nzb_seed_capacity_schema(&self) -> rusqlite::Result<()> {
        if self.nzb_seed_capacity_schema_present()? {
            return Ok(());
        }
        self.db
            .execute_batch("SAVEPOINT nzb_seed_capacity_schema")?;
        let install = (|| -> rusqlite::Result<()> {
            self.db.execute_batch(
                "CREATE TABLE IF NOT EXISTS nzb_seed_usage(
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    sets INTEGER NOT NULL CHECK(sets>=0),
                    assertions INTEGER NOT NULL CHECK(assertions>=0),
                    posted_assertions INTEGER NOT NULL
                        CHECK(posted_assertions>=0 AND posted_assertions<=assertions),
                    charged_bytes INTEGER NOT NULL CHECK(charged_bytes>=0));
                 CREATE INDEX IF NOT EXISTS idx_nzb_seed_assertions_trusted
                    ON nzb_seed_assertions(set_id,id)
                    WHERE source<>'posted-nzb';",
            )?;
            // Backfill an older seed schema using the exact same logical-byte
            // formula as admission, summed over every set with
            // SEED_SET_LOGICAL_CHARGE_SQL - the one expression the purge
            // refund also reads, so filling and draining the ledger can never
            // be two formulas that drift. Every assertion belongs to a set and
            // nothing leaves an orphan behind, so summing per set reaches every
            // charged row. INSERT OR IGNORE makes index-only repair leave an
            // existing ledger untouched. Summing per set also means a child
            // row whose set is gone is not charged for, which is the same
            // reachability the refund uses; nothing on `main` can strand one.
            self.db.execute(
                &format!(
                    "INSERT OR IGNORE INTO nzb_seed_usage(
                        id,sets,assertions,posted_assertions,charged_bytes)
                     SELECT 1,
                        COUNT(*),
                        (SELECT COUNT(*) FROM nzb_seed_assertions),
                        (SELECT COUNT(*) FROM nzb_seed_assertions
                          WHERE source=?2),
                        COALESCE(SUM({SEED_SET_LOGICAL_CHARGE_SQL}),0)
                       FROM nzb_seed_sets s"
                ),
                rusqlite::params![SEED_ROW_CHARGE, NZB_SEED_POSTED_SOURCE],
            )?;
            Ok(())
        })();
        match install {
            Ok(()) => self.db.execute_batch("RELEASE nzb_seed_capacity_schema")?,
            Err(error) => {
                let _ = self.db.execute_batch(
                    "ROLLBACK TO nzb_seed_capacity_schema;
                     RELEASE nzb_seed_capacity_schema",
                );
                return Err(error);
            }
        }
        self.ddl.set(true);
        Ok(())
    }

    fn nzb_seed_usage(&self) -> Result<NzbSeedUsage, NzbSeedError> {
        let usage = self.db.query_row(
            "SELECT sets,assertions,posted_assertions,charged_bytes
               FROM nzb_seed_usage WHERE id=1",
            [],
            |row| {
                Ok(NzbSeedUsage {
                    sets: row.get(0)?,
                    assertions: row.get(1)?,
                    posted_assertions: row.get(2)?,
                    charged_bytes: row.get(3)?,
                })
            },
        )?;
        if usage.sets < 0
            || usage.assertions < 0
            || usage.posted_assertions < 0
            || usage.posted_assertions > usage.assertions
            || usage.charged_bytes < 0
        {
            return Err(NzbSeedError::Corrupt("invalid seed usage ledger"));
        }
        Ok(usage)
    }

    fn admit_nzb_seed_capacity(
        &self,
        new_set: bool,
        new_assertion: bool,
        posted_assertion: bool,
        charged_bytes: i64,
    ) -> Result<(), NzbSeedError> {
        let usage = self.nzb_seed_usage()?;
        let set_delta = i64::from(new_set);
        let assertion_delta = i64::from(new_assertion);
        let posted_delta = i64::from(new_assertion && posted_assertion);
        let trusted_delta = assertion_delta - posted_delta;
        let trusted_assertions = usage
            .assertions
            .checked_sub(usage.posted_assertions)
            .ok_or(NzbSeedError::Corrupt("invalid seed usage ledger"))?;
        let over = |current: i64, delta: i64, cap: i64| {
            delta > 0 && current.checked_add(delta).is_none_or(|next| next > cap)
        };
        if over(usage.sets, set_delta, SEED_SET_CAP) {
            return Err(NzbSeedError::Capacity("set limit"));
        }
        if posted_assertion && over(usage.sets, set_delta, SEED_POSTED_SET_CAP) {
            return Err(NzbSeedError::Capacity("posted set reserve"));
        }
        if over(usage.assertions, assertion_delta, SEED_ASSERTIONS_CAP) {
            return Err(NzbSeedError::Capacity("assertion limit"));
        }
        if over(
            usage.posted_assertions,
            posted_delta,
            SEED_ASSERTION_CLASS_CAP,
        ) {
            return Err(NzbSeedError::Capacity("posted assertion limit"));
        }
        if over(trusted_assertions, trusted_delta, SEED_ASSERTION_CLASS_CAP) {
            return Err(NzbSeedError::Capacity("trusted assertion limit"));
        }
        if charged_bytes < 0 || over(usage.charged_bytes, charged_bytes, SEED_CHARGED_BYTES_CAP) {
            return Err(NzbSeedError::Capacity("charged-byte limit"));
        }
        if posted_assertion
            && over(
                usage.charged_bytes,
                charged_bytes,
                SEED_POSTED_CHARGED_BYTES_CAP,
            )
        {
            return Err(NzbSeedError::Capacity("posted charged-byte reserve"));
        }
        if set_delta == 0 && assertion_delta == 0 && charged_bytes == 0 {
            return Ok(());
        }
        let changed = self.db.execute(
            "UPDATE nzb_seed_usage
                SET sets=sets+?1,
                    assertions=assertions+?2,
                    posted_assertions=posted_assertions+?3,
                    charged_bytes=charged_bytes+?4
              WHERE id=1",
            rusqlite::params![set_delta, assertion_delta, posted_delta, charged_bytes],
        )?;
        if changed != 1 {
            return Err(NzbSeedError::Corrupt("missing seed usage ledger"));
        }
        Ok(())
    }

    /// Whether this exact external source assertion has already been
    /// persisted. This is a read-only idempotency check: a database that
    /// has never stored seed evidence returns `false` without installing
    /// the optional seed schema.
    pub fn nzb_seed_assertion_exists(
        &self,
        source: &str,
        source_guid: &str,
        name: &str,
    ) -> Result<bool, NzbSeedError> {
        let (source, source_guid, name, _) =
            normalize_seed_metadata(source, source_guid, name, "")?;
        if !self.nzb_seed_schema_present()? {
            return Ok(false);
        }
        Ok(self.db.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM nzb_seed_assertions
                 WHERE source=?1 AND source_guid=?2 AND name=?3)",
            rusqlite::params![source, source_guid, name],
            |row| row.get(0),
        )?)
    }

    /// Whether this source assertion is backed by a complete strong file
    /// manifest. Unlike [`Self::nzb_seed_assertion_exists`], a legacy sampled
    /// assertion returns `false` so a caller retaining the source NZB can
    /// reacquire it into the full-manifest store. This remains a read-only
    /// probe: an index without either optional seed table generation returns
    /// `false` without installing schema.
    pub fn nzb_seed_strong_assertion_exists(
        &self,
        source: &str,
        source_guid: &str,
        name: &str,
    ) -> Result<bool, NzbSeedError> {
        let (source, source_guid, name, _) =
            normalize_seed_metadata(source, source_guid, name, "")?;
        if !self.nzb_seed_schema_present()? || !self.nzb_seed_file_key_schema_present()? {
            return Ok(false);
        }
        let set_ids: Vec<i64> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT set_id FROM nzb_seed_assertions
                  WHERE source=?1 AND source_guid=?2 AND name=?3
                  ORDER BY set_id LIMIT ?4",
            )?;
            stmt.query_map(
                rusqlite::params![source, source_guid, name, (SEED_ASSERTION_CAP + 1) as i64],
                |row| row.get(0),
            )?
            .collect::<rusqlite::Result<_>>()?
        };
        if set_ids.len() > SEED_ASSERTION_CAP {
            return Ok(false);
        }
        for set_id in set_ids {
            if self.verified_nzb_seed_membership_key(set_id)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Parse and durably save one named external NZB before attempting a
    /// join. A later [`Self::nzb_seed_reconcile`] can therefore benefit
    /// from articles the scanner has not ingested yet.
    pub fn nzb_seed_store_xml(
        &mut self,
        spec: NzbSeedSpec<'_>,
        xml: &[u8],
        now: i64,
    ) -> Result<NzbSeedStored, NzbSeedError> {
        let nzb = crate::nzb::Nzb::parse(xml)?;
        self.nzb_seed_store(spec, &nzb, now)
    }

    /// Parsed-NZB form of [`Self::nzb_seed_store_xml`].
    pub fn nzb_seed_store(
        &mut self,
        spec: NzbSeedSpec<'_>,
        nzb: &crate::nzb::Nzb,
        now: i64,
    ) -> Result<NzbSeedStored, NzbSeedError> {
        let prepared = NzbSeedPrepared::from_nzb(nzb)?;
        self.nzb_seed_store_prepared(spec, &prepared, now)
    }

    /// Store an NZB seed whose bounded manifest shape was built outside the
    /// index writer lock.
    pub fn nzb_seed_store_prepared(
        &mut self,
        spec: NzbSeedSpec<'_>,
        prepared: &NzbSeedPrepared,
        now: i64,
    ) -> Result<NzbSeedStored, NzbSeedError> {
        Ok(self
            .nzb_seed_store_prepared_guarded(spec, prepared, now, || Some(()))?
            .expect("the unconditional seed commit guard always succeeds"))
    }

    /// Atomically publish retry ownership before a caller deletes its
    /// fsynced sidecar journal. The ordinary index writer deliberately uses
    /// `synchronous=NORMAL` because headers are reacquirable; a popped
    /// one-shot confirmation candidate is not. Temporarily use FULL so a
    /// successful return is a safe hand-off from the journal to SQLite.
    pub fn retry_kv_set_durable(&self, entries: &[(&str, &str)]) -> rusqlite::Result<()> {
        let prior: i64 = self
            .db
            .query_row("PRAGMA synchronous", [], |row| row.get(0))?;
        let changed = prior < 2;
        if changed {
            self.db.execute_batch("PRAGMA synchronous=FULL")?;
        }
        let written = (|| {
            let tx = self.db.unchecked_transaction()?;
            for (key, value) in entries {
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES(?1, ?2)
                     ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    [key, value],
                )?;
            }
            tx.commit()
        })();
        let restored = if changed {
            self.db
                .execute_batch(&format!("PRAGMA synchronous={prior}"))
        } else {
            Ok(())
        };
        match (written, restored) {
            (Ok(()), Ok(())) => Ok(()),
            (Ok(()), Err(error)) => Err(error),
            (Err(error), _) => Err(error),
        }
    }

    /// Store irreplaceable acquired evidence with SQLite's power-loss-safe
    /// commit level, then restore this ingest-oriented connection's prior
    /// synchronous setting. Ordinary header rows are reacquirable and use
    /// NORMAL; a caller may delete its only external proof after this returns.
    pub fn nzb_seed_store_prepared_durable(
        &mut self,
        spec: NzbSeedSpec<'_>,
        prepared: &NzbSeedPrepared,
        now: i64,
    ) -> Result<NzbSeedStored, NzbSeedError> {
        let prior: i64 = self
            .db
            .query_row("PRAGMA synchronous", [], |row| row.get(0))?;
        let changed = prior < 2;
        if changed {
            self.db.execute_batch("PRAGMA synchronous=FULL")?;
        }
        let stored = self.nzb_seed_store_prepared(spec, prepared, now);
        let restored = if changed {
            self.db
                .execute_batch(&format!("PRAGMA synchronous={prior}"))
        } else {
            Ok(())
        };
        match (stored, restored) {
            (Ok(stored), Ok(())) => Ok(stored),
            (Ok(_), Err(error)) => Err(error.into()),
            (Err(error), _) => Err(error),
        }
    }

    /// Store prepared evidence only if `commit_guard` still accepts it at
    /// the transaction boundary. Inserts remain inside a SAVEPOINT until the
    /// callback runs; `None` rolls them back. The returned guard is kept alive
    /// through `RELEASE`, allowing a caller to serialize an external record's
    /// final state with the durable commit without holding that guard during
    /// manifest preparation or row insertion.
    pub fn nzb_seed_store_prepared_guarded<G>(
        &mut self,
        spec: NzbSeedSpec<'_>,
        prepared: &NzbSeedPrepared,
        now: i64,
        commit_guard: impl FnOnce() -> Option<G>,
    ) -> Result<Option<NzbSeedStored>, NzbSeedError> {
        let (source, source_guid, name, category) =
            normalize_seed_metadata(spec.source, spec.source_guid, spec.name, spec.category)?;
        let shape = &prepared.shape;
        // File-key and capacity migrations on an existing proof catalog are
        // independent durable maintenance. Install them before the
        // per-acquisition savepoint so a seed rejected at capacity cannot roll
        // the ledger/index repair back and force the same full backfill on
        // every retry. Cleanup repair remains inside the acquisition savepoint
        // because its edge purge must not escape a refused commit guard. A
        // brand-new catalog is still created inside the guard below,
        // preserving the guarantee that a refused first store leaves no
        // optional proof schema behind.
        if self.nzb_seed_schema_present()? {
            self.ensure_nzb_seed_file_key_schema()?;
            self.ensure_nzb_seed_capacity_schema()?;
        }
        self.db.execute_batch("SAVEPOINT nzb_seed_store")?;
        let setup = (|| -> Result<(), NzbSeedError> {
            self.ensure_nzb_seed_schema()?;
            self.ensure_nzb_seed_file_key_schema()?;
            self.ensure_nzb_seed_capacity_schema()?;
            Ok(())
        })();
        if let Err(error) = setup {
            let _ = self
                .db
                .execute_batch("ROLLBACK TO nzb_seed_store; RELEASE nzb_seed_store");
            return Err(error);
        }
        let out = (|| -> Result<NzbSeedStored, NzbSeedError> {
            // Every current-generation assertion lives under the SHA-256
            // whole-manifest key. Any MD5 row is legacy, even if an earlier
            // prototype happened to attach file keys to it: reacquisition
            // forks instead of inheriting assertions that were once allowed
            // to name from a bounded probe sample.
            let storage_membership_key = &shape.strong_membership_key;
            let existing_set_id: Option<i64> = self
                .db
                .query_row(
                    "SELECT id FROM nzb_seed_sets WHERE membership_key=?1",
                    [storage_membership_key],
                    |row| row.get(0),
                )
                .optional()?;
            let new_set = existing_set_id.is_none();
            let name_key = crate::predb::match_key(name);
            let existing_assertion_id: Option<i64> = if let Some(set_id) = existing_set_id {
                self.db
                    .query_row(
                        "SELECT id FROM nzb_seed_assertions
                          WHERE source=?1 AND source_guid=?2 AND set_id=?3 AND name=?4",
                        rusqlite::params![source, source_guid, set_id, name],
                        |row| row.get(0),
                    )
                    .optional()?
            } else {
                None
            };
            let new_assertion = existing_assertion_id.is_none();
            let set_charge = if new_set {
                seed_set_charge(shape, storage_membership_key)?
            } else {
                0
            };
            let assertion_charge = if new_assertion {
                seed_assertion_charge(source, source_guid, name, &name_key, category)?
            } else {
                0
            };
            let charged_bytes = set_charge
                .checked_add(assertion_charge)
                .ok_or(NzbSeedError::Capacity("charged-byte accounting overflow"))?;
            // Reserve every positive delta before the first proof insert. The
            // ledger update and all rows below share this outer savepoint, so
            // an insertion error or a refused commit guard rolls both back.
            self.admit_nzb_seed_capacity(
                new_set,
                new_assertion,
                source == NZB_SEED_POSTED_SOURCE,
                charged_bytes,
            )?;
            if new_set {
                self.db.execute(
                    "INSERT INTO nzb_seed_sets(
                        membership_key, file_count, data_files, segment_count,
                        probe_count, probe_complete, first_seen, last_seen)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?7)",
                    rusqlite::params![
                        storage_membership_key,
                        shape.files.len() as i64,
                        shape.data_files as i64,
                        shape.segments.min(i64::MAX as usize) as i64,
                        shape.probes.len() as i64,
                        shape.probe_complete,
                        now,
                    ],
                )?;
            }
            let set_id = if let Some(set_id) = existing_set_id {
                set_id
            } else {
                self.db.query_row(
                    "SELECT id FROM nzb_seed_sets WHERE membership_key=?1",
                    [storage_membership_key],
                    |row| row.get(0),
                )?
            };
            self.db.execute(
                "UPDATE nzb_seed_sets SET last_seen=MAX(last_seen,?2) WHERE id=?1",
                rusqlite::params![set_id, now],
            )?;
            let mut stored_file_keys: Vec<(i64, String)> = {
                let mut stmt = self.db.prepare_cached(
                    "SELECT kind,manifest_key FROM nzb_seed_file_keys
                      WHERE set_id=?1 ORDER BY kind,manifest_key",
                )?;
                stmt.query_map([set_id], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            let mut incoming_file_keys: Vec<(i64, String)> = shape
                .files
                .iter()
                .map(|file| (file.kind, file.manifest_key.clone()))
                .collect();
            incoming_file_keys.sort_unstable();
            stored_file_keys.sort_unstable();
            if !new_set && !stored_file_keys.is_empty() && stored_file_keys != incoming_file_keys {
                return Err(NzbSeedError::Corrupt(
                    "strong file manifests disagree for one membership key",
                ));
            }
            if !new_set && stored_file_keys.is_empty() {
                return Err(NzbSeedError::Corrupt(
                    "strong seed set is missing its file manifests",
                ));
            }
            if new_set {
                let mut file_insert = self.db.prepare_cached(
                    "INSERT INTO nzb_seed_files(
                        set_id,file_ord,subject,bytes,segments,required)
                     VALUES(?1,?2,?3,?4,?5,?6)",
                )?;
                for (ord, file) in shape.files.iter().enumerate() {
                    file_insert.execute(rusqlite::params![
                        set_id,
                        ord as i64,
                        file.subject,
                        sqlite_u64(file.bytes),
                        file.segments.min(i64::MAX as usize) as i64,
                        file.required,
                    ])?;
                }
                drop(file_insert);
                let mut key_insert = self.db.prepare_cached(
                    "INSERT INTO nzb_seed_file_keys(
                        set_id,file_ord,kind,manifest_key)
                     VALUES(?1,?2,?3,?4)",
                )?;
                for (ord, file) in shape.files.iter().enumerate() {
                    key_insert.execute(rusqlite::params![
                        set_id,
                        ord as i64,
                        file.kind,
                        file.manifest_key,
                    ])?;
                }
                drop(key_insert);
                let mut probe_insert = self.db.prepare_cached(
                    "INSERT INTO nzb_seed_msgids(set_id,file_ord,part_ord,msgid,h)
                     VALUES(?1,?2,?3,?4,?5)",
                )?;
                for probe in &shape.probes {
                    probe_insert.execute(rusqlite::params![
                        set_id,
                        probe.file_ord as i64,
                        probe.part_ord,
                        probe.msgid,
                        claims::msgid_hash(&probe.msgid),
                    ])?;
                }
            }
            if new_assertion {
                self.db.execute(
                    "INSERT INTO nzb_seed_assertions(
                        set_id,source,source_guid,name,name_key,category,posted,
                        bytes,acquired_at,last_seen)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)",
                    rusqlite::params![
                        set_id,
                        source,
                        source_guid,
                        name,
                        name_key,
                        category,
                        spec.posted,
                        sqlite_u64(spec.bytes),
                        now,
                    ],
                )?;
            }
            let assertion_id = if let Some(assertion_id) = existing_assertion_id {
                assertion_id
            } else {
                self.db.query_row(
                    "SELECT id FROM nzb_seed_assertions
                      WHERE source=?1 AND source_guid=?2 AND set_id=?3 AND name=?4",
                    rusqlite::params![source, source_guid, set_id, name],
                    |row| row.get(0),
                )?
            };
            self.db.execute(
                "UPDATE nzb_seed_assertions SET last_seen=MAX(last_seen,?2)
                  WHERE id=?1",
                rusqlite::params![assertion_id, now],
            )?;
            Ok(NzbSeedStored {
                set_id,
                assertion_id,
                membership_key: storage_membership_key.clone(),
                new_set,
                new_assertion,
                data_files: shape.data_files,
                probe_ids: shape.probes.len(),
                probe_complete: shape.probe_complete,
            })
        })();
        match out {
            Ok(v) => {
                let Some(guard) = commit_guard() else {
                    self.db
                        .execute_batch("ROLLBACK TO nzb_seed_store; RELEASE nzb_seed_store")?;
                    return Ok(None);
                };
                match self.db.execute_batch("RELEASE nzb_seed_store") {
                    Ok(()) => {
                        drop(guard);
                        Ok(Some(v))
                    }
                    Err(error) => {
                        // A failed outermost RELEASE can leave its savepoint
                        // live (I/O/full/busy), while a commit-hook refusal may
                        // already have rolled it back. Clean up only when the
                        // connection still owns a transaction, and retain the
                        // caller's guard until that attempt is complete.
                        if !self.db.is_autocommit() {
                            let _ = self.db.execute_batch(
                                "ROLLBACK TO nzb_seed_store; RELEASE nzb_seed_store",
                            );
                        }
                        drop(guard);
                        Err(error.into())
                    }
                }
            }
            Err(e) => {
                let _ = self
                    .db
                    .execute_batch("ROLLBACK TO nzb_seed_store; RELEASE nzb_seed_store");
                Err(e)
            }
        }
    }

    fn verified_nzb_seed_membership_key(&self, set_id: i64) -> rusqlite::Result<Option<String>> {
        let metadata: Option<(i64, String)> = self
            .db
            .query_row(
                "SELECT file_count,membership_key
                   FROM nzb_seed_sets WHERE id=?1",
                [set_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((file_count, stored_membership_key)) = metadata else {
            return Ok(None);
        };
        let Ok(file_count) = usize::try_from(file_count) else {
            return Ok(None);
        };
        let stored_file_key_count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM nzb_seed_file_keys WHERE set_id=?1",
            [set_id],
            |row| row.get(0),
        )?;
        let stored_file_keys: Vec<Option<(i64, String)>> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT CASE WHEN k.kind IS NULL THEN NULL ELSE k.kind END,
                        k.manifest_key
                   FROM nzb_seed_files f LEFT JOIN nzb_seed_file_keys k
                     ON k.set_id=f.set_id AND k.file_ord=f.file_ord
                  WHERE f.set_id=?1 ORDER BY f.file_ord",
            )?;
            stmt.query_map([set_id], |row| {
                let kind: Option<i64> = row.get(0)?;
                let key: Option<String> = row.get(1)?;
                Ok(kind.zip(key))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        if file_count == 0
            || usize::try_from(stored_file_key_count).ok() != Some(file_count)
            || stored_file_keys.len() != file_count
            || stored_file_keys.iter().any(|file| {
                !file.as_ref().is_some_and(|(kind, key)| {
                    matches!(*kind, 0..=2) && is_strong_seed_file_key(key)
                })
            })
        {
            return Ok(None);
        }
        let computed =
            strong_seed_membership_key_from_files(stored_file_keys.into_iter().flatten().collect());
        Ok((computed == stored_membership_key).then_some(computed))
    }

    fn load_nzb_seed(&self, set_id: i64) -> rusqlite::Result<Option<LoadedSeed>> {
        let probe_complete: Option<bool> = self
            .db
            .query_row(
                "SELECT probe_complete FROM nzb_seed_sets WHERE id=?1",
                [set_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(probe_complete) = probe_complete else {
            return Ok(None);
        };
        let strong_membership_key = self.verified_nzb_seed_membership_key(set_id)?;
        let required_ordinals: Vec<i64> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT file_ord FROM nzb_seed_files
                  WHERE set_id=?1 AND required=1 ORDER BY file_ord",
            )?;
            stmt.query_map([set_id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        let probes: Vec<(i64, String)> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT s.file_ord,s.msgid
                   FROM nzb_seed_msgids s JOIN nzb_seed_files f
                     ON f.set_id=s.set_id AND f.file_ord=s.file_ord
                  WHERE s.set_id=?1 AND f.required=1
                  ORDER BY s.file_ord,s.part_ord",
            )?;
            stmt.query_map([set_id], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        let mut required_files = BTreeMap::new();
        for file_ord in required_ordinals {
            let held = probes.iter().filter(|(ord, _)| *ord == file_ord).count();
            required_files.insert(file_ord, held.min(MSGID_KEYS_PER_FILE));
        }
        Ok(Some(LoadedSeed {
            id: set_id,
            probe_complete,
            required_files,
            strong_membership_key,
        }))
    }

    fn exact_nzb_seed_hit(
        &self,
        release_id: i64,
        probes: &[(i64, String, bool)],
        now: i64,
        budget: &mut SeedReplayScanBudget,
        keep_going: &mut impl FnMut() -> bool,
    ) -> rusqlite::Result<ExactHitScan> {
        let settled = self
            .db
            .query_row(
                "SELECT r.complete,r.first_seen,
                        CASE WHEN r.seed_manifest_at<>0
                             THEN r.seed_manifest_at ELSE m.schema_at END
                   FROM releases r CROSS JOIN nzb_seed_meta m
                  WHERE r.id=?1 AND m.id=1",
                [release_id],
                |row| {
                    Ok((
                        row.get::<_, bool>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
            .is_some_and(|(complete, first_seen, changed_at)| {
                complete
                    && now.saturating_sub(first_seen.max(changed_at)) >= SEED_RELEASE_SETTLE_SECS
            });
        let wanted: HashMap<&str, (i64, bool)> = probes
            .iter()
            .map(|(file_ord, id, required)| (id.as_str(), (*file_ord, *required)))
            .collect();
        let mut matched: BTreeMap<String, i64> = BTreeMap::new();
        let mut required_matched: BTreeMap<String, i64> = BTreeMap::new();
        let mut local_data_files = 0usize;
        let mut matched_local_data_files = 0usize;
        let mut local_file_keys = Vec::new();
        let mut full_manifest_complete = true;
        let mut stmt = self.db.prepare_cached(
            "SELECT filename,total_parts,segments FROM files WHERE release_id=?1",
        )?;
        let mut rows = stmt.query([release_id])?;
        loop {
            if !keep_going() {
                return Ok(ExactHitScan::Deferred);
            }
            let Some(row) = rows.next()? else {
                break;
            };
            if budget.files >= SEED_REPLAY_FILE_SCAN_CAP {
                return Err(corrupt_seed_candidate("candidate file scan limit exceeded"));
            }
            budget.files += 1;
            let filename = match row.get_ref(0)? {
                rusqlite::types::ValueRef::Text(raw) => std::str::from_utf8(raw)
                    .map_err(|_| corrupt_seed_candidate("candidate filename is not valid UTF-8"))?,
                _ => return Err(corrupt_seed_candidate("candidate filename is not text")),
            };
            if filename.len() > crate::nzb::limits::MAX_FIELD {
                return Err(corrupt_seed_candidate("candidate filename is too long"));
            }
            let total_parts = usize::try_from(row.get::<_, i64>(1)?)
                .ok()
                .filter(|total| *total > 0)
                .ok_or_else(|| corrupt_seed_candidate("candidate has invalid declared parts"))?;
            let raw = match row.get_ref(2)? {
                rusqlite::types::ValueRef::Text(raw) | rusqlite::types::ValueRef::Blob(raw) => raw,
                _ => {
                    return Err(corrupt_seed_candidate(
                        "candidate segment list is not text or blob",
                    ));
                }
            };
            if raw.len() > SEED_REPLAY_SEGMENT_BYTES_SCAN_CAP.saturating_sub(budget.encoded_bytes) {
                return Err(corrupt_seed_candidate(
                    "candidate encoded-byte limit exceeded",
                ));
            }
            budget.encoded_bytes += raw.len();
            let segment_limit =
                total_parts.min(SEED_REPLAY_SEGMENT_SCAN_CAP.saturating_sub(budget.segments));
            let text_limit = SEED_REPLAY_DECODED_TEXT_SCAN_CAP.saturating_sub(budget.decoded_text);
            let segments = match crate::index::segcodec::parse_capped_bytes_guarded(
                raw,
                segment_limit,
                text_limit,
                keep_going,
            ) {
                crate::index::segcodec::GuardedParse::Complete(segments) => segments,
                crate::index::segcodec::GuardedParse::Deferred => {
                    return Ok(ExactHitScan::Deferred);
                }
                crate::index::segcodec::GuardedParse::Invalid => {
                    return Err(corrupt_seed_candidate("undecodable local segment list"));
                }
            };
            if !keep_going() {
                return Ok(ExactHitScan::Deferred);
            }
            if segments.is_empty() || segments.len() > total_parts {
                return Err(corrupt_seed_candidate(
                    "local segment list exceeds declared parts",
                ));
            }
            let complete_file = segments.len() == total_parts;
            full_manifest_complete &= complete_file;
            budget.segments = budget
                .segments
                .checked_add(segments.len())
                .ok_or_else(|| corrupt_seed_candidate("candidate segment limit exceeded"))?;
            let kind = crate::nzb::classify_subject(filename);
            let local_data = kind == crate::nzb::FileKind::Data;
            local_data_files += usize::from(local_data);
            let mut required_file_matched = false;
            let mut decoded_text = 0usize;
            let mut manifest_parts = Vec::with_capacity(segments.len());
            for (segment_index, (part, id, _)) in segments.into_iter().enumerate() {
                if segment_index > 0 && segment_index.is_multiple_of(256) && !keep_going() {
                    return Ok(ExactHitScan::Deferred);
                }
                decoded_text = decoded_text
                    .checked_add(id.len())
                    .ok_or_else(|| corrupt_seed_candidate("candidate text limit exceeded"))?;
                let Some(canonical) = canonical_seed_local_msgid(&id) else {
                    return Err(corrupt_seed_candidate(
                        "candidate contains a non-canonical Message-ID",
                    ));
                };
                if part == 0 {
                    return Err(corrupt_seed_candidate(
                        "candidate contains a zero segment number",
                    ));
                }
                manifest_parts.push((part, canonical.to_string()));
                if let Some(&(file_ord, required)) = wanted.get(canonical) {
                    matched.entry(canonical.to_string()).or_insert(file_ord);
                    if local_data && required {
                        required_matched
                            .entry(canonical.to_string())
                            .or_insert(file_ord);
                        required_file_matched = true;
                    }
                }
            }
            manifest_parts.sort_unstable();
            if manifest_parts.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(corrupt_seed_candidate(
                    "candidate contains duplicate segment numbers",
                ));
            }
            if complete_file {
                local_file_keys.push((
                    seed_file_kind(kind),
                    seed_file_manifest_key(
                        kind,
                        0,
                        manifest_parts.iter().map(|(part, id)| (*part, id.as_str())),
                    ),
                ));
            }
            budget.decoded_text = budget
                .decoded_text
                .checked_add(decoded_text)
                .ok_or_else(|| corrupt_seed_candidate("candidate text limit exceeded"))?;
            if !keep_going() {
                return Ok(ExactHitScan::Deferred);
            }
            matched_local_data_files += usize::from(required_file_matched);
        }
        let covered: BTreeSet<i64> = required_matched.values().copied().collect();
        let mut per_file = BTreeMap::new();
        for file_ord in required_matched.values() {
            *per_file.entry(*file_ord).or_default() += 1;
        }
        let strong_membership_key = (full_manifest_complete && !local_file_keys.is_empty())
            .then(|| strong_seed_membership_key_from_files(local_file_keys));
        Ok(ExactHitScan::Hit(ExactHit {
            release_id,
            ids: matched.into_keys().collect(),
            covered,
            per_file,
            local_data_files,
            matched_local_data_files,
            strong_membership_key,
            settled,
        }))
    }

    fn nzb_seed_hash_candidates(
        &self,
        set_id: i64,
        keep_going: &mut impl FnMut() -> bool,
    ) -> rusqlite::Result<Option<Vec<HashCandidate>>> {
        let hashes = {
            let mut stmt = self.db.prepare_cached(
                "SELECT DISTINCT s.h
               FROM nzb_seed_msgids s
               JOIN nzb_seed_files f
                 ON f.set_id=s.set_id AND f.file_ord=s.file_ord
              WHERE s.set_id=?1 AND f.required=1
              ORDER BY s.h",
            )?;
            let mut rows = stmt.query([set_id])?;
            let mut hashes = Vec::new();
            loop {
                if !keep_going() {
                    return Ok(None);
                }
                let Some(row) = rows.next()? else {
                    break;
                };
                hashes.push(row.get::<_, i64>(0)?);
            }
            hashes
        };
        let mut release_ids = BTreeSet::new();
        let mut by_hash = self.db.prepare_cached(
            "SELECT release_id FROM msgid_map
              WHERE h=?1 ORDER BY release_id LIMIT ?2",
        )?;
        'hashes: for hash in hashes {
            if !keep_going() {
                return Ok(None);
            }
            let mut rows =
                by_hash.query(rusqlite::params![hash, (SEED_CANDIDATE_CAP + 1) as i64])?;
            loop {
                if !keep_going() {
                    return Ok(None);
                }
                let Some(row) = rows.next()? else {
                    break;
                };
                release_ids.insert(row.get::<_, i64>(0)?);
                if release_ids.len() > SEED_CANDIDATE_CAP {
                    break 'hashes;
                }
            }
        }
        if release_ids.len() > SEED_CANDIDATE_CAP {
            return Ok(Some(
                release_ids
                    .into_iter()
                    .map(|release_id| HashCandidate {
                        release_id,
                        probes: Vec::new(),
                    })
                    .collect(),
            ));
        }
        let mut out = Vec::with_capacity(release_ids.len());
        let mut mapped = self.db.prepare_cached(
            "SELECT s.file_ord,s.msgid,f.required
               FROM nzb_seed_msgids s
               JOIN nzb_seed_files f
                 ON f.set_id=s.set_id AND f.file_ord=s.file_ord
               JOIN msgid_map m ON m.h=s.h
              WHERE s.set_id=?1 AND m.release_id=?2
              ORDER BY s.file_ord,s.part_ord",
        )?;
        for release_id in release_ids {
            if !keep_going() {
                return Ok(None);
            }
            let mut rows = mapped.query(rusqlite::params![set_id, release_id])?;
            let mut probes = Vec::new();
            loop {
                if !keep_going() {
                    return Ok(None);
                }
                let Some(row) = rows.next()? else {
                    break;
                };
                probes.push((row.get(0)?, row.get(1)?, row.get(2)?));
            }
            out.push(HashCandidate { release_id, probes });
        }
        Ok(Some(out))
    }

    pub(super) fn nzb_seed_title(&self, set_id: i64) -> rusqlite::Result<SeedTitle> {
        // Collection export can reach a legacy proof DB before the background
        // replay task. Repair the partial trusted-title index here as well, so
        // public assertion history can never force an unbounded filtered scan.
        self.ensure_nzb_seed_capacity_schema()?;
        let rows: Vec<(i64, String, String, String, String)> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT id,name,name_key,source,category FROM nzb_seed_assertions
                  WHERE set_id=?1 AND source<>'posted-nzb' ORDER BY id LIMIT ?2",
            )?;
            stmt.query_map(
                rusqlite::params![set_id, (SEED_ASSERTION_CAP + 1) as i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?
            .collect::<rusqlite::Result<_>>()?
        };
        Ok(choose_seed_title(rows, SEED_ASSERTION_CAP))
    }

    /// Keep the claims supported by this exact manifest in lockstep with its
    /// current complete hits and unambiguous trusted title. A release can grow
    /// another file after an earlier replay, or a later assertion can create a
    /// title conflict. In either case stale top-tier evidence must be removed
    /// and the release re-arbitrated inside the caller's reconcile savepoint.
    fn nzb_seed_prior_claim_keys(&self, set_id: i64) -> rusqlite::Result<BTreeSet<String>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT DISTINCT claim_key FROM nzb_seed_matches
              WHERE set_id=?1 AND claim_key<>'' ORDER BY claim_key LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![set_id, (SEED_MATCH_EDGE_CAP + 1) as i64],
            |row| row.get(0),
        )?;
        rows.collect()
    }

    fn reconcile_nzb_seed_claim_support(
        &mut self,
        set_id: i64,
        claim_key: &str,
        desired_release_ids: &BTreeSet<i64>,
        desired_name: Option<&str>,
        now: i64,
    ) -> rusqlite::Result<()> {
        let desired_name = desired_name.map(|name| crate::release::sanitize_name(name.trim()));
        let mut candidate_release_ids = desired_release_ids.clone();
        {
            let mut stmt = self.db.prepare_cached(
                "SELECT release_id FROM nzb_seed_matches
                  WHERE set_id=?1 ORDER BY release_id LIMIT ?2",
            )?;
            let prior = stmt.query_map(
                rusqlite::params![set_id, (SEED_MATCH_EDGE_CAP + 1) as i64],
                |row| row.get(0),
            )?;
            for release_id in prior {
                candidate_release_ids.insert(release_id?);
            }
        }
        let mut claims = Vec::new();
        let mut select = self.db.prepare_cached(
            "SELECT id,name,source FROM name_claims
              WHERE release_id=?1 AND tier=?2 AND key=?3
                AND source LIKE 'external-nzb:%'",
        )?;
        for release_id in candidate_release_ids {
            claims.extend(
                select
                    .query_map(
                        rusqlite::params![release_id, NameEvidence::MsgidSet.tag(), claim_key],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                release_id,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                            ))
                        },
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?,
            );
        }
        drop(select);
        let stale: Vec<(i64, i64, String, String)> = claims
            .into_iter()
            .filter_map(|(id, release_id, name, source)| {
                let supported = desired_release_ids.contains(&release_id)
                    && desired_name.as_ref().is_some_and(|wanted| wanted == &name);
                (!supported).then_some((id, release_id, name, source))
            })
            .collect();
        if stale.is_empty() {
            return Ok(());
        }
        let mut removed_support: BTreeMap<i64, Vec<(String, String)>> = BTreeMap::new();
        for (_, release_id, name, source) in &stale {
            removed_support.entry(*release_id).or_default().push((
                name.clone(),
                super::claims::proven_label(NameEvidence::MsgidSet, source),
            ));
        }
        let mut delete = self
            .db
            .prepare_cached("DELETE FROM name_claims WHERE id=?1")?;
        for (id, _, _, _) in stale {
            delete.execute([id])?;
        }
        drop(delete);

        for (release_id, removed) in removed_support {
            let applied: Option<(String, String)> = self
                .db
                .query_row(
                    "SELECT pre_title,pre_source FROM releases WHERE id=?1",
                    [release_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let remaining = self.name_claims(release_id)?;
            let removed_current = applied.as_ref().is_some_and(|(title, source)| {
                removed
                    .iter()
                    .any(|(name, label)| name == title && label == source)
            });
            let surviving_equivalent = applied.as_ref().is_some_and(|(title, source)| {
                remaining.iter().any(|(name, tier, _, claim_source, _)| {
                    name == title
                        && NameEvidence::parse(tier).is_some_and(|evidence| {
                            super::claims::proven_label(evidence, claim_source) == *source
                        })
                })
            });
            if !removed_current || surviving_equivalent {
                continue;
            }
            self.revoke_pre_name(release_id)?;
            let next = remaining
                .into_iter()
                .find_map(|(name, tier, key, source, _)| {
                    NameEvidence::parse(&tier).map(|evidence| NameClaim {
                        name,
                        evidence,
                        key,
                        source,
                    })
                });
            if let Some(next) = next {
                let _ = self.apply_proven_name(release_id, &next, now)?;
            }
        }
        Ok(())
    }

    fn withdraw_all_nzb_seed_claim_support(
        &mut self,
        set_id: i64,
        now: i64,
    ) -> rusqlite::Result<()> {
        let no_releases = BTreeSet::new();
        for claim_key in self.nzb_seed_prior_claim_keys(set_id)? {
            self.reconcile_nzb_seed_claim_support(set_id, &claim_key, &no_releases, None, now)?;
        }
        Ok(())
    }

    fn write_nzb_seed_match(
        &self,
        set_id: i64,
        hit: &ExactHit,
        required_files: &BTreeMap<i64, usize>,
        state: &str,
        claim_key: &str,
        now: i64,
    ) -> rusqlite::Result<()> {
        let covered_data_files = required_files
            .keys()
            .filter(|file_ord| hit.covered.contains(file_ord))
            .count();
        self.db.execute(
            "INSERT INTO nzb_seed_matches(
                set_id,release_id,exact_ids,covered_data_files,state,claim_key,at)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(set_id,release_id) DO UPDATE SET
                exact_ids=excluded.exact_ids,
                covered_data_files=excluded.covered_data_files,
                state=excluded.state,
                claim_key=excluded.claim_key,
                at=excluded.at",
            rusqlite::params![
                set_id,
                hit.release_id,
                hit.ids.len() as i64,
                covered_data_files as i64,
                state,
                claim_key,
                now,
            ],
        )?;
        Ok(())
    }

    fn finish_nzb_seed(&self, set_id: i64, state: &str, now: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE nzb_seed_sets
                SET state=?2,last_reconciled=?3,reconcile_count=reconcile_count+1
              WHERE id=?1",
            rusqlite::params![set_id, state, now],
        )?;
        Ok(())
    }

    fn quarantine_nzb_seed(&mut self, set_id: i64, now: i64) -> Result<(), NzbSeedError> {
        self.db.execute_batch("SAVEPOINT nzb_seed_quarantine")?;
        let out = (|| -> rusqlite::Result<()> {
            self.withdraw_all_nzb_seed_claim_support(set_id, now)?;
            self.db
                .execute("DELETE FROM nzb_seed_matches WHERE set_id=?1", [set_id])?;
            self.finish_nzb_seed(set_id, "error", now)
        })();
        match out {
            Ok(()) => {
                self.db.execute_batch("RELEASE nzb_seed_quarantine")?;
                Ok(())
            }
            Err(e) => {
                let _ = self
                    .db
                    .execute_batch("ROLLBACK TO nzb_seed_quarantine; RELEASE nzb_seed_quarantine");
                Err(e.into())
            }
        }
    }

    fn reconcile_one_nzb_seed_guarded(
        &mut self,
        set_id: i64,
        now: i64,
        stats: &mut NzbSeedReplayStats,
        keep_going: &mut impl FnMut() -> bool,
    ) -> Result<bool, NzbSeedError> {
        self.db.execute_batch("SAVEPOINT nzb_seed_reconcile_one")?;
        let out = self.reconcile_one_nzb_seed_locked(set_id, now, stats, keep_going);
        match out {
            Ok(true) => {
                self.db.execute_batch("RELEASE nzb_seed_reconcile_one")?;
                Ok(true)
            }
            Ok(false) => {
                self.db.execute_batch(
                    "ROLLBACK TO nzb_seed_reconcile_one; RELEASE nzb_seed_reconcile_one",
                )?;
                Ok(false)
            }
            Err(e) => {
                let _ = self.db.execute_batch(
                    "ROLLBACK TO nzb_seed_reconcile_one; RELEASE nzb_seed_reconcile_one",
                );
                Err(e)
            }
        }
    }

    fn reconcile_one_nzb_seed_locked(
        &mut self,
        set_id: i64,
        now: i64,
        stats: &mut NzbSeedReplayStats,
        keep_going: &mut impl FnMut() -> bool,
    ) -> Result<bool, NzbSeedError> {
        if !keep_going() {
            return Ok(false);
        }
        let Some(seed) = self.load_nzb_seed(set_id)? else {
            return Ok(true);
        };
        stats.sets_examined += 1;
        let Some(candidates) = self.nzb_seed_hash_candidates(seed.id, keep_going)? else {
            return Ok(false);
        };
        stats.hash_candidates += candidates.len();
        if !keep_going() {
            return Ok(false);
        }
        if candidates.len() > SEED_CANDIDATE_CAP {
            self.withdraw_all_nzb_seed_claim_support(seed.id, now)?;
            self.db
                .execute("DELETE FROM nzb_seed_matches WHERE set_id=?1", [seed.id])?;
            stats.sets_saturated += 1;
            self.finish_nzb_seed(set_id, "saturated", now)?;
            return Ok(true);
        }
        let mut hits = Vec::new();
        let mut corrupt_candidates = 0usize;
        let mut scan_budget = SeedReplayScanBudget::default();
        for candidate in candidates {
            if !keep_going() {
                return Ok(false);
            }
            match self.exact_nzb_seed_hit(
                candidate.release_id,
                &candidate.probes,
                now,
                &mut scan_budget,
                keep_going,
            ) {
                Ok(ExactHitScan::Deferred) => return Ok(false),
                Ok(ExactHitScan::Hit(hit)) if hit.ids.is_empty() => {
                    stats.hash_candidates_rejected += 1;
                }
                Ok(ExactHitScan::Hit(hit)) => {
                    hits.push(hit);
                    if hits.len() > SEED_MATCH_EDGE_CAP {
                        break;
                    }
                }
                Err(rusqlite::Error::FromSqlConversionFailure(..)) => {
                    corrupt_candidates += 1;
                    stats.hash_candidates_rejected += 1;
                    // The candidate set is now incomplete. Stop so one
                    // hostile edge cannot multiply bounded decode work, and
                    // never let a later hit rescue a partially scanned set.
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }
        if corrupt_candidates > 0 {
            if !keep_going() {
                return Ok(false);
            }
            self.withdraw_all_nzb_seed_claim_support(seed.id, now)?;
            self.db
                .execute("DELETE FROM nzb_seed_matches WHERE set_id=?1", [seed.id])?;
            stats.sets_errored += 1;
            self.finish_nzb_seed(set_id, "error", now)?;
            return Ok(true);
        }
        if hits.len() > SEED_MATCH_EDGE_CAP {
            if !keep_going() {
                return Ok(false);
            }
            self.withdraw_all_nzb_seed_claim_support(seed.id, now)?;
            self.db
                .execute("DELETE FROM nzb_seed_matches WHERE set_id=?1", [seed.id])?;
            stats.sets_saturated += 1;
            self.finish_nzb_seed(set_id, "saturated", now)?;
            return Ok(true);
        }
        let complete: Vec<usize> = hits
            .iter()
            .enumerate()
            .filter_map(|(i, hit)| (seed.probe_complete && hit.qualifies(&seed)).then_some(i))
            .collect();
        // The savepoint above deliberately remains read-only through all
        // candidate scans. This first write either upgrades the same
        // snapshot atomically or returns BUSY_SNAPSHOT for a later retry;
        // it never holds the daemon's writer lock while decoding 2,048
        // candidate releases.
        let title = if complete.is_empty() {
            None
        } else {
            Some(self.nzb_seed_title(set_id)?)
        };
        let desired_release_ids: BTreeSet<i64> = complete
            .iter()
            .map(|index| hits[*index].release_id)
            .collect();
        let desired_name = match title.as_ref() {
            Some(SeedTitle::One { name, .. }) => Some(name.as_str()),
            Some(SeedTitle::Missing | SeedTitle::Conflict) | None => None,
        };
        if !keep_going() {
            return Ok(false);
        }
        let current_claim_key = seed.strong_membership_key.as_deref();
        let mut support_keys = self.nzb_seed_prior_claim_keys(seed.id)?;
        if let Some(claim_key) = current_claim_key {
            support_keys.insert(claim_key.to_string());
        }
        let no_releases = BTreeSet::new();
        for claim_key in support_keys {
            let currently_supported = current_claim_key == Some(claim_key.as_str());
            self.reconcile_nzb_seed_claim_support(
                seed.id,
                &claim_key,
                if currently_supported {
                    &desired_release_ids
                } else {
                    &no_releases
                },
                if currently_supported {
                    desired_name
                } else {
                    None
                },
                now,
            )?;
        }
        self.db
            .execute("DELETE FROM nzb_seed_matches WHERE set_id=?1", [seed.id])?;
        for hit in &hits {
            if !keep_going() {
                return Ok(false);
            }
            let state = if hit.qualifies(&seed) {
                if seed.probe_complete {
                    "complete"
                } else {
                    "unsafe"
                }
            } else if hit.manifest_qualifies(&seed) && !hit.settled {
                "unsettled"
            } else {
                "partial"
            };
            self.write_nzb_seed_match(set_id, hit, &seed.required_files, state, "", now)?;
        }

        if complete.is_empty() {
            let mut union_files = BTreeSet::new();
            let mut union_ids = HashSet::new();
            for hit in &hits {
                if !keep_going() {
                    return Ok(false);
                }
                union_files.extend(hit.covered.iter().copied());
                union_ids.extend(hit.ids.iter().cloned());
            }
            let state = if corrupt_candidates > 0 {
                stats.sets_errored += 1;
                "error"
            } else if !seed.probe_complete || seed.strong_membership_key.is_none() {
                stats.sets_unsafe += 1;
                "unsafe"
            } else if hits
                .iter()
                .any(|hit| hit.manifest_qualifies(&seed) && !hit.settled)
            {
                stats.sets_unsettled += 1;
                "unsettled"
            } else if hits.len() >= 2
                && seed.required_files.keys().all(|f| union_files.contains(f))
                && union_ids.len() >= crate::nzbimport::MIN_MSGID_QUORUM
            {
                stats.sets_fragmented += 1;
                "fragmented"
            } else if hits.is_empty() {
                stats.sets_unmatched += 1;
                "unmatched"
            } else {
                stats.sets_partial += 1;
                "partial"
            };
            self.finish_nzb_seed(set_id, state, now)?;
            return Ok(true);
        }

        match title.expect("complete candidates always load a title verdict") {
            SeedTitle::Missing => {
                stats.sets_invalid_title += 1;
                for &i in &complete {
                    if !keep_going() {
                        return Ok(false);
                    }
                    self.write_nzb_seed_match(
                        set_id,
                        &hits[i],
                        &seed.required_files,
                        "invalid-title",
                        "",
                        now,
                    )?;
                }
                self.finish_nzb_seed(set_id, "invalid-title", now)?;
            }
            SeedTitle::Conflict => {
                // The support pass above removed any earlier claim attributed
                // to this exact set key before these audit edges are written.
                // A later conflicting source therefore retracts the old seed
                // name while leaving unrelated stronger evidence untouched.
                stats.sets_title_conflict += 1;
                for &i in &complete {
                    if !keep_going() {
                        return Ok(false);
                    }
                    self.write_nzb_seed_match(
                        set_id,
                        &hits[i],
                        &seed.required_files,
                        "title-conflict",
                        "",
                        now,
                    )?;
                }
                self.finish_nzb_seed(set_id, "title-conflict", now)?;
            }
            SeedTitle::One { name, source, .. } => {
                stats.sets_matched += 1;
                stats.exact_release_matches += complete.len();
                for i in complete {
                    if !keep_going() {
                        return Ok(false);
                    }
                    let hit = &hits[i];
                    // The candidate index retains only a bounded raw-ID
                    // sample. The claim key instead commits to every file and
                    // part that was re-read above, so later reverse-map growth
                    // cannot mint a second or weaker proof identity.
                    let key = seed
                        .strong_membership_key
                        .clone()
                        .expect("a complete hit has a strong membership key");
                    let claim = NameClaim {
                        name: name.clone(),
                        evidence: NameEvidence::MsgidSet,
                        key: key.clone(),
                        source: format!("external-nzb:{source}"),
                    };
                    let outcome = self.apply_proven_name(hit.release_id, &claim, now)?;
                    let state = match outcome {
                        ProvenOutcome::Applied => {
                            stats.claims_applied += 1;
                            "applied"
                        }
                        ProvenOutcome::Replaced => {
                            stats.claims_replaced += 1;
                            "replaced"
                        }
                        ProvenOutcome::Confirmed => {
                            stats.claims_confirmed += 1;
                            "confirmed"
                        }
                        ProvenOutcome::Recorded => {
                            stats.claims_recorded += 1;
                            "recorded"
                        }
                        ProvenOutcome::Conflict => {
                            stats.claims_conflicted += 1;
                            "conflict"
                        }
                        ProvenOutcome::Rejected => {
                            stats.claims_rejected += 1;
                            "rejected"
                        }
                    };
                    self.write_nzb_seed_match(set_id, hit, &seed.required_files, state, &key, now)?;
                }
                self.finish_nzb_seed(set_id, "matched", now)?;
            }
        }
        Ok(true)
    }

    /// Reconcile one known set immediately without moving the durable sweep
    /// cursor. Acquisition lanes use this after storing a newly fetched NZB so
    /// a safe exact hit can apply now while split packs still stop at a
    /// collection edge.
    pub fn nzb_seed_reconcile_set(
        &mut self,
        set_id: i64,
        now: i64,
    ) -> Result<NzbSeedReplayStats, NzbSeedError> {
        Ok(self
            .nzb_seed_reconcile_set_guarded(set_id, now, || true)?
            .expect("the unconditional replay guard always succeeds"))
    }

    /// Reconcile one set while an owning daemon remains idle. `None` means
    /// the guard asked the scan to yield; every match and naming write for
    /// this attempt is rolled back so a later pass can retry cleanly.
    pub fn nzb_seed_reconcile_set_guarded(
        &mut self,
        set_id: i64,
        now: i64,
        mut keep_going: impl FnMut() -> bool,
    ) -> Result<Option<NzbSeedReplayStats>, NzbSeedError> {
        self.ensure_nzb_seed_schema()?;
        self.ensure_nzb_seed_file_key_schema()?;
        self.ensure_nzb_seed_capacity_schema()?;
        let mut stats = NzbSeedReplayStats::default();
        match self.reconcile_one_nzb_seed_guarded(set_id, now, &mut stats, &mut keep_going) {
            Ok(true) => {}
            Ok(false) => return Ok(None),
            Err(error) if is_seed_value_error(&error) => {
                self.quarantine_nzb_seed(set_id, now)?;
                stats.sets_errored += 1;
            }
            Err(error) => return Err(error),
        }
        Ok(Some(stats))
    }

    /// Replay a bounded, durable cursor over every saved seed. Resolved
    /// seeds remain in the walk so a later crosspost can inherit the same
    /// exact name without reacquiring the external NZB.
    pub fn nzb_seed_reconcile(
        &mut self,
        now: i64,
        limit: usize,
    ) -> Result<NzbSeedReplayStats, NzbSeedError> {
        Ok(self
            .nzb_seed_reconcile_guarded(now, limit, || true)?
            .expect("the unconditional replay guard always succeeds"))
    }

    /// Guarded form of the durable cursor replay. `None` leaves the current
    /// set at the cursor so an idle pass can retry it without partial writes.
    pub fn nzb_seed_reconcile_guarded(
        &mut self,
        now: i64,
        limit: usize,
        mut keep_going: impl FnMut() -> bool,
    ) -> Result<Option<NzbSeedReplayStats>, NzbSeedError> {
        let mut stats = NzbSeedReplayStats::default();
        if limit == 0 {
            return Ok(Some(stats));
        }
        self.ensure_nzb_seed_schema()?;
        self.ensure_nzb_seed_file_key_schema()?;
        self.ensure_nzb_seed_capacity_schema()?;
        if !keep_going() {
            return Ok(None);
        }
        let cursor = self
            .kv_get(SEED_REPLAY_CURSOR)
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        let select = |from: i64| -> rusqlite::Result<Vec<i64>> {
            let mut stmt = self
                .db
                .prepare_cached("SELECT id FROM nzb_seed_sets WHERE id>?1 ORDER BY id LIMIT ?2")?;
            stmt.query_map(rusqlite::params![from, limit as i64], |r| r.get(0))?
                .collect()
        };
        let mut ids = select(cursor)?;
        if ids.is_empty() && cursor > 0 {
            stats.cycle_wrapped = true;
            ids = select(0)?;
        }
        if ids.is_empty() {
            stats.cycle_wrapped = true;
            self.kv_set(SEED_REPLAY_CURSOR, "0")?;
            return Ok(Some(stats));
        }
        for id in ids {
            match self.reconcile_one_nzb_seed_guarded(id, now, &mut stats, &mut keep_going) {
                Ok(true) => {}
                Ok(false) => return Ok(None),
                Err(error) if is_seed_value_error(&error) => {
                    self.quarantine_nzb_seed(id, now)?;
                    stats.sets_errored += 1;
                }
                Err(error) => return Err(error),
            }
            // Persist each completed verdict. A later bad row or transient
            // writer conflict retries only that row instead of replaying the
            // successful prefix forever.
            self.kv_set(SEED_REPLAY_CURSOR, &id.to_string())?;
        }
        Ok(Some(stats))
    }

    /// Current shadow-mode counts. Safe on an index where the prototype
    /// has never been armed: it returns an empty inventory without DDL.
    pub fn nzb_seed_inventory(&self) -> Result<NzbSeedInventory, NzbSeedError> {
        if !self.nzb_seed_schema_present()? {
            return Ok(NzbSeedInventory::default());
        }
        let count = |sql: &str| -> rusqlite::Result<usize> {
            self.db
                .query_row(sql, [], |r| r.get::<_, i64>(0))
                .map(|n| n.max(0) as usize)
        };
        Ok(NzbSeedInventory {
            sets: count("SELECT COUNT(*) FROM nzb_seed_sets")?,
            assertions: count("SELECT COUNT(*) FROM nzb_seed_assertions")?,
            files: count("SELECT COUNT(*) FROM nzb_seed_files")?,
            probe_ids: count("SELECT COUNT(*) FROM nzb_seed_msgids")?,
            match_edges: count("SELECT COUNT(*) FROM nzb_seed_matches")?,
            matched_sets: count("SELECT COUNT(*) FROM nzb_seed_sets WHERE state='matched'")?,
            fragmented_sets: count("SELECT COUNT(*) FROM nzb_seed_sets WHERE state='fragmented'")?,
            title_conflict_sets: count(
                "SELECT COUNT(*) FROM nzb_seed_sets WHERE state='title-conflict'",
            )?,
            named_release_edges: count(
                "SELECT COUNT(*) FROM nzb_seed_matches
                  WHERE state IN ('applied','replaced','confirmed')",
            )?,
        })
    }

    pub fn nzb_seed_matches(&self, set_id: i64) -> Result<Vec<NzbSeedMatch>, NzbSeedError> {
        if !self.nzb_seed_schema_present()? {
            return Ok(Vec::new());
        }
        let mut stmt = self.db.prepare_cached(
            "SELECT release_id,exact_ids,covered_data_files,state,claim_key,at
               FROM nzb_seed_matches WHERE set_id=?1 ORDER BY release_id",
        )?;
        Ok(stmt
            .query_map([set_id], |r| {
                Ok(NzbSeedMatch {
                    release_id: r.get(0)?,
                    exact_ids: r.get::<_, i64>(1)?.max(0) as usize,
                    covered_data_files: r.get::<_, i64>(2)?.max(0) as usize,
                    state: r.get(3)?,
                    claim_key: r.get(4)?,
                    at: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?)
    }
}

#[cfg(test)]
mod seed_input_validation_tests {
    use super::*;

    #[test]
    fn cumulative_programmatic_text_is_bounded_before_shape_cloning() {
        let nzb = crate::nzb::Nzb {
            files: vec![crate::nzb::NzbFile {
                subject: "abcd".to_string(),
                segments: vec![crate::nzb::Segment {
                    number: 1,
                    bytes: 1,
                    message_id: "one@x".to_string(),
                }],
                ..Default::default()
            }],
            meta: Vec::new(),
        };
        assert!(validate_seed_input(&nzb, 9).is_ok());
        assert!(matches!(
            validate_seed_input(&nzb, 8),
            Err(NzbSeedError::Invalid("NZB text exceeds limit"))
        ));
    }

    #[test]
    fn assertion_saturation_is_never_collapsed_to_one_readable_title() {
        let row = |id| {
            (
                id,
                "Show.S01E01.1080p.WEB-GRP".to_string(),
                "show s01e01 1080p web grp".to_string(),
                format!("source-{id}"),
                "tv".to_string(),
            )
        };
        assert!(matches!(
            choose_seed_title(vec![row(1), row(2), row(3)], 2),
            SeedTitle::Conflict
        ));
    }
}
