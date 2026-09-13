//! The PURE layer between an NZB and the seed tables: the membership and
//! file keys, the storage charges each row costs against the caps, the
//! title choice, and `seed_shape`, which reduces a parsed NZB to the
//! record everything downstream is written in terms of.
//!
//! Everything here is a function of its arguments - no `Connection`, no
//! `Index`, no clock - which is what makes it the seam. `seed.rs` keeps
//! the caps, the SQL and the `impl Index` that spends them.
//!
//! Cut out of `seed.rs` on 7 Sep 2026 (claim `debt-split-hot-files-7sep`)
//! at 3,314 of the size gate's 4,000-line file ceiling. Verbatim move.

use super::*;

pub(in crate::index) fn is_seed_value_error(error: &NzbSeedError) -> bool {
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

pub(in crate::index) fn sqlite_u64(n: u64) -> i64 {
    n.min(i64::MAX as u64) as i64
}

pub(in crate::index) fn add_seed_charge(
    total: &mut u64,
    bytes: usize,
    copies: u64,
) -> Result<(), NzbSeedError> {
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
pub(in crate::index) const SEED_SET_LOGICAL_CHARGE_SQL: &str = "?1 * (1
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

pub(in crate::index) fn seed_set_charge(
    shape: &SeedShape,
    membership_key: &str,
) -> Result<i64, NzbSeedError> {
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

pub(in crate::index) fn seed_assertion_charge(
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

pub(in crate::index) fn seed_file_kind(kind: crate::nzb::FileKind) -> i64 {
    match kind {
        crate::nzb::FileKind::Data => 0,
        crate::nzb::FileKind::Par2Main => 1,
        crate::nzb::FileKind::Par2Volume => 2,
    }
}

pub(in crate::index) fn canonical_seed_local_msgid(value: &str) -> Option<&str> {
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

pub(in crate::index) fn corrupt_seed_candidate(message: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        2,
        rusqlite::types::Type::Blob,
        Box::new(NzbSeedError::Corrupt(message)),
    )
}

pub(in crate::index) fn choose_seed_title(
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
pub(in crate::index) fn seed_file_manifest_key<'a>(
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

pub(in crate::index) fn strong_seed_membership_key_from_files(
    mut file_keys: Vec<(i64, String)>,
) -> String {
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

pub(in crate::index) fn is_strong_seed_file_key(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(in crate::index) fn strong_membership_key(nzb: &crate::nzb::Nzb) -> String {
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

pub(in crate::index) fn membership_key(nzb: &crate::nzb::Nzb) -> String {
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

pub(in crate::index) fn validate_seed_input(
    nzb: &crate::nzb::Nzb,
    text_limit: usize,
) -> Result<(), NzbSeedError> {
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

pub(in crate::index) fn seed_shape(nzb: &crate::nzb::Nzb) -> Result<SeedShape, NzbSeedError> {
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
