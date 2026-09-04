//! Exact named collections assembled from verified local shards.
//!
//! A source NZB can describe one logical collection whose files were split
//! across many local release rows. The seed replay layer records those rows as
//! `fragmented` but deliberately does not copy a pack title onto each shard.
//! This module instead revalidates each complete per-file Message-ID manifest
//! and emits one virtual NZB containing only the proven files.

use super::*;
use rusqlite::OptionalExtension;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const COLLECTION_FILE_SCAN_CAP: usize = 32_768;
/// Two hostile maximum-size source manifests, or 12.6x the largest NZB in
/// the measured field corpus. Candidate crossposts beyond this are safer to
/// refuse than to hash synchronously on a request path.
const COLLECTION_SEGMENT_SCAN_CAP: usize = 2_000_000;
/// Candidate storage may include legacy JSON overhead, so allow 128 MiB total
/// encoded input while still bounding malformed values that declare few parts.
const COLLECTION_SEGMENT_BYTES_SCAN_CAP: usize = 128 << 20;
/// Match the source parser's cumulative retained-text ceiling while decoding
/// compact rows, whose shared prefix can expand far beyond stored bytes.
const COLLECTION_DECODED_TEXT_SCAN_CAP: usize = crate::nzb::limits::MAX_TEXT_BYTES;

/// A named virtual NZB assembled from exact local file identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NzbSeedCollection {
    pub set_id: i64,
    pub name: String,
    pub category: String,
    pub bytes: u64,
    pub data_files: usize,
    pub optional_files: usize,
    pub release_ids: Vec<i64>,
    pub xml: String,
}

#[derive(Debug)]
struct ExpectedFile {
    ord: i64,
    subject: String,
    segments: usize,
    required: bool,
    kind: i64,
    manifest_key: String,
    probes: Vec<(u32, String)>,
}

#[derive(Debug, Clone)]
struct LocalFile {
    release_id: i64,
    filename: String,
    poster: String,
    group: String,
    posted: i64,
    segments: Vec<(u32, String, u64)>,
}

fn xml_escape(value: &str) -> String {
    let clean: String = value
        .chars()
        .filter(|&character| {
            matches!(character, '\t' | '\n' | '\r')
                || (character >= ' ' && character != '\u{FFFE}' && character != '\u{FFFF}')
        })
        .collect();
    clean
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn files_have_same_identity(left: &LocalFile, right: &LocalFile) -> bool {
    left.segments.len() == right.segments.len()
        && left
            .segments
            .iter()
            .zip(&right.segments)
            .all(|(left, right)| left.0 == right.0 && left.1 == right.1)
}

fn retain_candidate(slot: &mut Option<LocalFile>, conflicted: &mut bool, candidate: LocalFile) {
    if *conflicted {
        return;
    }
    let Some(held) = slot else {
        *slot = Some(candidate);
        return;
    };
    if !files_have_same_identity(held, &candidate) {
        *conflicted = true;
        *slot = None;
        return;
    }
    if (candidate.release_id, candidate.filename.as_str())
        < (held.release_id, held.filename.as_str())
    {
        *held = candidate;
    }
}

impl Index {
    /// Build a virtual NZB for a safely fragmented seed collection.
    ///
    /// This is intentionally an on-demand proof. Stored 64-bit hashes and
    /// prior match rows are only candidate indexes; every selected local file
    /// must still match the seed's strong full-manifest key and its retained
    /// raw probes at the same part numbers. `None` means the set is not a safe
    /// export now, including legacy seeds which predate full file keys.
    pub fn make_nzb_seed_collection(
        &self,
        set_id: i64,
    ) -> Result<Option<NzbSeedCollection>, NzbSeedError> {
        if !self.nzb_seed_schema_present()? || !self.nzb_seed_file_key_schema_present()? {
            return Ok(None);
        }
        let seed: Option<(bool, usize, String)> = self
            .db
            .query_row(
                "SELECT probe_complete,file_count,membership_key
                   FROM nzb_seed_sets WHERE id=?1",
                [set_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get::<_, i64>(1)?.max(0) as usize,
                        row.get(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((probe_complete, file_count, stored_membership_key)) = seed else {
            return Ok(None);
        };
        if !probe_complete || file_count == 0 {
            return Ok(None);
        }
        let (assertion_id, name, category) = match self.nzb_seed_title(set_id)? {
            SeedTitle::One {
                assertion_id,
                name,
                category,
                ..
            } => (assertion_id, name, category),
            SeedTitle::Missing | SeedTitle::Conflict => return Ok(None),
        };
        let assertion_still_matches: bool = self.db.query_row(
            "SELECT set_id=?2 AND name=?3 AND category=?4
               FROM nzb_seed_assertions WHERE id=?1",
            rusqlite::params![assertion_id, set_id, name, category],
            |row| row.get(0),
        )?;
        if !assertion_still_matches {
            return Ok(None);
        }

        let mut expected: Vec<ExpectedFile> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT f.file_ord,f.subject,f.segments,f.required,
                        k.kind,k.manifest_key
                   FROM nzb_seed_files f JOIN nzb_seed_file_keys k
                     ON k.set_id=f.set_id AND k.file_ord=f.file_ord
                  WHERE f.set_id=?1 ORDER BY f.file_ord",
            )?;
            stmt.query_map([set_id], |row| {
                Ok(ExpectedFile {
                    ord: row.get(0)?,
                    subject: row.get(1)?,
                    segments: row.get::<_, i64>(2)?.max(0) as usize,
                    required: row.get(3)?,
                    kind: row.get(4)?,
                    manifest_key: row.get(5)?,
                    probes: Vec::new(),
                })
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        if expected.len() != file_count
            || expected.iter().any(|file| {
                file.segments == 0
                    || file.manifest_key.len() != 64
                    || file.required != (file.kind == seed_file_kind(crate::nzb::FileKind::Data))
                    || !matches!(file.kind, 0..=2)
            })
        {
            return Ok(None);
        }
        let ord_index: HashMap<i64, usize> = expected
            .iter()
            .enumerate()
            .map(|(index, file)| (file.ord, index))
            .collect();
        {
            let mut stmt = self.db.prepare_cached(
                "SELECT file_ord,part_ord,msgid FROM nzb_seed_msgids
                  WHERE set_id=?1 ORDER BY file_ord,part_ord,msgid",
            )?;
            let probes = stmt.query_map([set_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            for probe in probes {
                let (ord, part, msgid) = probe?;
                let Some(&index) = ord_index.get(&ord) else {
                    return Ok(None);
                };
                let Some(msgid) = canonical_seed_local_msgid(&msgid) else {
                    return Ok(None);
                };
                if part == 0 {
                    return Ok(None);
                }
                expected[index].probes.push((part, msgid.to_string()));
            }
        }
        if expected
            .iter()
            .any(|file| file.required && file.probes.is_empty())
        {
            return Ok(None);
        }

        let release_ids: Vec<i64> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT DISTINCT m.release_id
                   FROM nzb_seed_msgids s JOIN msgid_map m ON m.h=s.h
                  WHERE s.set_id=?1
                  ORDER BY m.release_id LIMIT ?2",
            )?;
            stmt.query_map(
                rusqlite::params![set_id, (SEED_CANDIDATE_CAP + 1) as i64],
                |row| row.get(0),
            )?
            .collect::<rusqlite::Result<_>>()?
        };
        if release_ids.len() > SEED_CANDIDATE_CAP {
            return Ok(None);
        }

        let mut expected_by_anchor: HashMap<u32, HashMap<String, Vec<usize>>> = HashMap::new();
        let mut unprobed_by_shape: HashMap<(i64, usize), Vec<usize>> = HashMap::new();
        let mut expected_shapes = HashSet::new();
        for (index, file) in expected.iter().enumerate() {
            expected_shapes.insert((file.kind, file.segments));
            if let Some((part, msgid)) = file.probes.first() {
                expected_by_anchor
                    .entry(*part)
                    .or_default()
                    .entry(msgid.clone())
                    .or_default()
                    .push(index);
            } else {
                unprobed_by_shape
                    .entry((file.kind, file.segments))
                    .or_default()
                    .push(index);
            }
        }
        let mut candidates: Vec<Option<LocalFile>> = vec![None; expected.len()];
        let mut conflicts = vec![false; expected.len()];
        let mut scanned_files = 0usize;
        let mut scanned_segments = 0usize;
        let mut scanned_segment_bytes = 0usize;
        let mut scanned_decoded_text = 0usize;
        for release_id in release_ids {
            let metadata: Option<(String, String, i64)> = self
                .db
                .query_row(
                    "SELECT grp,poster,first_posted FROM releases
                      WHERE id=?1
                        AND typeof(grp)='text'
                        AND length(CAST(grp AS BLOB)) BETWEEN 1 AND ?2
                        AND typeof(poster)='text'
                        AND length(CAST(poster AS BLOB))<=?3",
                    rusqlite::params![
                        release_id,
                        crate::nzb::limits::MAX_WIRE_TOKEN as i64,
                        crate::nzb::limits::MAX_FIELD as i64
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((group, poster, posted)) = metadata else {
                continue;
            };
            if !crate::nzb::is_wire_safe(&group)
                || poster.chars().any(|character| {
                    character.is_control() || matches!(character, '\u{FFFE}' | '\u{FFFF}')
                })
            {
                return Ok(None);
            }
            let mut stmt = self.db.prepare_cached(
                "SELECT filename,total_parts,segments FROM files
                  WHERE release_id=?1",
            )?;
            let mut rows = stmt.query([release_id])?;
            while let Some(row) = rows.next()? {
                scanned_files += 1;
                if scanned_files > COLLECTION_FILE_SCAN_CAP {
                    return Ok(None);
                }
                let filename = match row.get_ref(0)? {
                    rusqlite::types::ValueRef::Text(raw) => match std::str::from_utf8(raw) {
                        Ok(filename) if filename.len() <= crate::nzb::limits::MAX_FIELD => filename,
                        _ => return Ok(None),
                    },
                    _ => return Ok(None),
                };
                let Ok(total_parts) = usize::try_from(row.get::<_, i64>(1)?) else {
                    continue;
                };
                if total_parts == 0 {
                    continue;
                }
                let kind = crate::nzb::classify_subject(filename);
                let kind_code = seed_file_kind(kind);
                if !expected_shapes.contains(&(kind_code, total_parts)) {
                    continue;
                }
                scanned_segments = scanned_segments.saturating_add(total_parts);
                if scanned_segments > COLLECTION_SEGMENT_SCAN_CAP {
                    return Ok(None);
                }
                let raw = match row.get_ref(2)? {
                    rusqlite::types::ValueRef::Text(raw) | rusqlite::types::ValueRef::Blob(raw) => {
                        raw
                    }
                    rusqlite::types::ValueRef::Null => continue,
                    _ => return Ok(None),
                };
                scanned_segment_bytes = scanned_segment_bytes.saturating_add(raw.len());
                if scanned_segment_bytes > COLLECTION_SEGMENT_BYTES_SCAN_CAP {
                    return Ok(None);
                }
                let remaining_text =
                    COLLECTION_DECODED_TEXT_SCAN_CAP.saturating_sub(scanned_decoded_text);
                let Some(mut raw_segments) =
                    crate::index::segcodec::parse_capped_bytes(raw, total_parts, remaining_text)
                else {
                    continue;
                };
                if raw_segments.len() != total_parts {
                    continue;
                }
                let Some(decoded_text) = raw_segments
                    .iter()
                    .try_fold(0usize, |total, (_, msgid, _)| {
                        total.checked_add(msgid.len())
                    })
                else {
                    return Ok(None);
                };
                scanned_decoded_text = scanned_decoded_text.saturating_add(decoded_text);
                let mut canonical_ids = true;
                for (_, msgid, _) in &mut raw_segments {
                    let Some(canonical) = canonical_seed_local_msgid(msgid) else {
                        canonical_ids = false;
                        break;
                    };
                    if canonical.len() != msgid.len() {
                        let canonical = canonical.to_owned();
                        *msgid = canonical;
                    }
                }
                if !canonical_ids {
                    continue;
                }
                raw_segments.sort_unstable_by(|left, right| {
                    (left.0, left.1.as_str()).cmp(&(right.0, right.1.as_str()))
                });
                if raw_segments.iter().any(|(part, msgid, _)| {
                    *part == 0
                        || msgid.is_empty()
                        || msgid.len() > crate::nzb::limits::MAX_WIRE_TOKEN
                        || !crate::nzb::is_wire_safe(msgid)
                }) || raw_segments.windows(2).any(|pair| pair[0].0 == pair[1].0)
                {
                    continue;
                }
                // Raw `(part, Message-ID)` probes are the cheap collision
                // check. Most `msgid_map` candidates are stale or association
                // edges; reject them before hashing or retaining every ID.
                let mut plausible = Vec::new();
                for (part, msgid, _) in &raw_segments {
                    if let Some(indices) = expected_by_anchor
                        .get(part)
                        .and_then(|by_id| by_id.get(msgid.as_str()))
                    {
                        plausible.extend(indices.iter().copied().filter(|&index| {
                            expected[index].kind == kind_code
                                && expected[index].segments == total_parts
                        }));
                    }
                }
                if let Some(indices) = unprobed_by_shape.get(&(kind_code, total_parts)) {
                    plausible.extend(indices.iter().copied());
                }
                plausible.sort_unstable();
                plausible.dedup();
                plausible.retain(|&index| {
                    expected[index].probes.iter().all(|(part, msgid)| {
                        raw_segments
                            .binary_search_by(|segment| {
                                (segment.0, segment.1.as_str()).cmp(&(*part, msgid.as_str()))
                            })
                            .is_ok()
                    })
                });
                if plausible.is_empty() {
                    continue;
                }
                let manifest_key = seed_file_manifest_key(
                    kind,
                    0,
                    raw_segments
                        .iter()
                        .map(|(part, msgid, _)| (*part, msgid.as_str())),
                );
                for index in plausible {
                    if expected[index].manifest_key != manifest_key {
                        continue;
                    }
                    let candidate = LocalFile {
                        release_id,
                        filename: filename.to_owned(),
                        poster: spots::base_poster(&poster).to_string(),
                        group: group.clone(),
                        posted,
                        segments: raw_segments.clone(),
                    };
                    retain_candidate(&mut candidates[index], &mut conflicts[index], candidate);
                }
            }
        }

        let mut selected: BTreeMap<i64, LocalFile> = BTreeMap::new();
        for (index, file) in expected.iter().enumerate() {
            if conflicts[index] {
                return Ok(None);
            }
            if file.required || candidates[index].is_some() {
                let Some(candidate) = candidates[index].take() else {
                    return Ok(None);
                };
                selected.insert(file.ord, candidate);
            }
        }

        let mut output_ids = HashSet::new();
        for file in selected.values() {
            for (_, msgid, _) in &file.segments {
                if !output_ids.insert(msgid.as_str()) {
                    return Ok(None);
                }
            }
        }
        let data_files = selected
            .keys()
            .filter(|ord| {
                ord_index
                    .get(ord)
                    .is_some_and(|index| expected[*index].required)
            })
            .count();
        let required_count = expected.iter().filter(|file| file.required).count();
        if data_files != required_count {
            return Ok(None);
        }
        let optional_files = selected.len() - data_files;
        let mut source_releases: BTreeSet<i64> = BTreeSet::new();
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <head>\n",
        );
        xml.push_str(&format!(
            "    <meta type=\"title\">{}</meta>\n",
            xml_escape(&name)
        ));
        if !category.is_empty() {
            xml.push_str(&format!(
                "    <meta type=\"category\">{}</meta>\n",
                xml_escape(&category)
            ));
        }
        xml.push_str("  </head>\n");
        for (ord, local) in &selected {
            let Some(&index) = ord_index.get(ord) else {
                return Ok(None);
            };
            source_releases.insert(local.release_id);
            xml.push_str(&format!(
                "  <file poster=\"{}\" date=\"{}\" subject=\"{}\">\n    <groups><group>{}</group></groups>\n    <segments>\n",
                xml_escape(&local.poster),
                local.posted,
                xml_escape(&expected[index].subject),
                xml_escape(&local.group),
            ));
            for (part, msgid, segment_bytes) in &local.segments {
                xml.push_str(&format!(
                    "      <segment bytes=\"{segment_bytes}\" number=\"{part}\">{}</segment>\n",
                    xml_escape(msgid)
                ));
            }
            xml.push_str("    </segments>\n  </file>\n");
        }
        xml.push_str("</nzb>\n");
        let parsed = crate::nzb::Nzb::parse(xml.as_bytes())?;
        let parsed_files_match =
            parsed
                .files
                .iter()
                .zip(selected.iter())
                .all(|(parsed_file, (ord, local))| {
                    let Some(&index) = ord_index.get(ord) else {
                        return false;
                    };
                    let mut identity: Vec<(u32, String)> = parsed_file
                        .segments
                        .iter()
                        .map(|segment| {
                            (
                                segment.number,
                                claims::norm_msgid(&segment.message_id).to_string(),
                            )
                        })
                        .collect();
                    identity.sort_unstable();
                    seed_file_kind(parsed_file.kind()) == expected[index].kind
                        && identity.len() == local.segments.len()
                        && identity.iter().zip(&local.segments).all(
                            |((part, msgid), (local_part, local_msgid, _))| {
                                part == local_part && msgid == local_msgid
                            },
                        )
                });
        let full_membership_matches = selected.len() != expected.len()
            || if stored_membership_key.starts_with("sha256:") {
                strong_membership_key(&parsed) == stored_membership_key
            } else {
                membership_key(&parsed) == stored_membership_key
            };
        if parsed.files.len() != selected.len()
            || parsed.files.iter().any(|file| file.dropped_segments != 0)
            || !parsed_files_match
            || !parsed
                .meta
                .iter()
                .any(|(kind, value)| kind == "title" && value == &name)
            || (!category.is_empty()
                && !parsed
                    .meta
                    .iter()
                    .any(|(kind, value)| kind == "category" && value == &category))
            || !full_membership_matches
        {
            return Ok(None);
        }

        let title_still_unique = matches!(
            self.nzb_seed_title(set_id)?,
            SeedTitle::One {
                assertion_id: final_assertion_id,
                name: ref final_name,
                category: ref final_category,
                ..
            } if final_assertion_id == assertion_id
                && final_name == &name
                && final_category == &category
        );
        if !title_still_unique {
            return Ok(None);
        }

        Ok(Some(NzbSeedCollection {
            set_id,
            name,
            category,
            bytes: parsed.total_bytes(),
            data_files,
            optional_files,
            release_ids: source_releases.into_iter().collect(),
            xml,
        }))
    }
}
