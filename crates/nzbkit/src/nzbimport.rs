//! Posted-NZB ingestion (research: REDTEAM-indexer-competitive 5c,
//! Codex handoff section 4; build-order item #6).
//!
//! Uploaders sometimes post the `.nzb` beside the content it describes.
//! Our scanner already indexes those posts as one-file releases named
//! `*.nzb`. Fetching that one object (usually a single article), parsing
//! it, and joining its payload message-ids against `files.segments`
//! names the referenced dark rows EXACTLY - no payload download, no
//! third party, no terms friction: the "feed" is Usenet itself.
//!
//! SECURITY: a posted NZB is attacker-controlled input. The parse path
//! is the same hardened `Nzb::parse` every user-supplied NZB goes
//! through (wire-safe message-ids, fuzzed), and an imported title is
//! only trusted when MULTIPLE payload message-ids match the target row
//! ([`quorum`]) - a single-msgid match can be seeded to mislabel a row.
//! Names produced here are CLAIMS with provenance (`nzb-import`), fed
//! to the identity layer's `apply_proven_name`; they never overwrite
//! the posted stem (same rule as `pre_title`).

use crate::nntp::{Connection, NntpError};
use crate::nzb::Nzb;

/// Decoded-size ceiling for a posted NZB object. The largest observed
/// on the 2026-08-09 snapshot was 18.8 MB (a big release listing);
/// 32 MiB clears that with headroom while keeping a hostile
/// thousand-segment "nzb" from buffering gigabytes.
pub const MAX_POSTED_NZB: u64 = 32 << 20;

/// Minimum matching payload message-ids before an imported title may
/// claim a row. Two is the floor that defeats accidental collisions;
/// three also prices out lazy seeding (an attacker must know - i.e.
/// have scanned - the victim row's real message-ids to fake this, at
/// which point they hold the same evidence we do).
pub const MIN_MSGID_QUORUM: usize = 3;

/// Leading segment ids probed per file against the substrate's reverse
/// map, and the whole-NZB probe ceiling that keeps a 100k-segment NZB
/// from turning one probe pass into 100k index lookups. Per-file
/// because the map keys each file's LEADING ids
/// ([`crate::index::MSGID_KEYS_PER_FILE`]) - and more than the map's
/// three, because a row scanned mid-post keys later parts first and
/// keeps them (append-only). Shared by every lane that probes an NZB
/// (enqueue pairing, the posted-NZB rung) so their quorums mean the
/// same thing.
pub const PROBES_PER_FILE: usize = 8;
pub const PROBE_CAP: usize = 512;

/// Strip ONE `.nzb` suffix, any case: the stem an NZB was posted under
/// is the name it carries for the content. One, not repeat-greedy - a
/// posted "Show.nzb.nzb" is the NZB *of* "Show.nzb" - and case-blind,
/// or "Great.Show.NZb" keeps its suffix and the name ladder judges a
/// suffixed stem (the `bare_stem` class of trap).
pub fn strip_nzb_suffix(stem: &str) -> &str {
    match stem.len().checked_sub(4) {
        Some(cut) if stem.is_char_boundary(cut) && stem[cut..].eq_ignore_ascii_case(".nzb") => {
            &stem[..cut]
        }
        _ => stem,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NzbImportError {
    #[error("NNTP: {0}")]
    Nntp(#[from] NntpError),
    #[error("article {0} missing on this server")]
    Missing(String),
    #[error("yEnc: {0}")]
    Yenc(#[from] crate::yenc::YencError),
    #[error("posted NZB exceeds the {MAX_POSTED_NZB} byte cap")]
    TooBig,
    #[error("assembled object has holes (parts missing or overlapping)")]
    Holes,
    #[error("gzip: {0}")]
    Gzip(std::io::Error),
}

/// Fetch and assemble one posted `.nzb` object. `segs` is the indexed
/// file's segment list - `(part_no, message_id)` with the message-id in
/// stored (bracketed) form - complete per the index. Multi-part objects
/// are placed by their yEnc offsets; a gzip-wrapped payload (posters do
/// ship `.nzb` names holding gzipped XML) is inflated under the same
/// cap. Returns the raw XML bytes, ready for [`Nzb::parse`].
pub async fn fetch_posted_nzb(
    conn: &mut Connection,
    segs: &[(u32, String)],
) -> Result<Vec<u8>, NzbImportError> {
    let mut out: Vec<u8> = Vec::new();
    // (offset, len) of every placed part, for the hole check.
    let mut placed: Vec<(u64, u64)> = Vec::with_capacity(segs.len());
    for (_, mid) in segs {
        let body = conn
            .body(mid)
            .await?
            .ok_or_else(|| NzbImportError::Missing(mid.clone()))?;
        let dec = crate::yenc::decode(&body)?;
        // Both the declared file size and the part offset are
        // poster-controlled: cap BEFORE any allocation grows to match.
        if dec.file_size > MAX_POSTED_NZB
            || dec.offset().saturating_add(dec.data.len() as u64) > MAX_POSTED_NZB
        {
            return Err(NzbImportError::TooBig);
        }
        let off = dec.offset() as usize;
        let end = off + dec.data.len();
        if out.len() < end {
            out.resize(end, 0);
        }
        out[off..end].copy_from_slice(&dec.data);
        placed.push((off as u64, dec.data.len() as u64));
    }
    // Coverage must be exactly [0, len) with no gaps: a hole would
    // otherwise silently parse as truncated XML and read as a parse
    // failure (or worse, parse cleanly minus some files).
    placed.sort_unstable();
    let mut cursor = 0u64;
    for (off, len) in &placed {
        // A gap is a hole; an overlap (off < cursor) means two parts
        // both claimed a byte range and one silently overwrote the
        // other - either way the reassembly is not the posted object.
        if *off != cursor {
            return Err(NzbImportError::Holes);
        }
        cursor = off + len;
    }
    if cursor != out.len() as u64 {
        return Err(NzbImportError::Holes);
    }
    // Gzip sniff: 0x1f 0x8b. Inflate under the same ceiling -
    // `take(cap + 1)` then a length check, so a zip bomb stops at the
    // cap instead of filling RAM.
    if out.len() >= 2 && out[0] == 0x1f && out[1] == 0x8b {
        use std::io::Read;
        let mut inflated = Vec::new();
        flate2::read::GzDecoder::new(&out[..])
            .take(MAX_POSTED_NZB + 1)
            .read_to_end(&mut inflated)
            .map_err(NzbImportError::Gzip)?;
        if inflated.len() as u64 > MAX_POSTED_NZB {
            return Err(NzbImportError::TooBig);
        }
        return Ok(inflated);
    }
    Ok(out)
}

/// What a parsed posted NZB contributes to the identity join.
#[derive(Debug, Default, Clone)]
pub struct NzbIdentity {
    /// Payload message-ids in stored (bracketed) form, deduped. These
    /// are the join keys against `files.segments`.
    pub msgids: Vec<String>,
    /// Files the NZB declares.
    pub files: usize,
    /// Declared segments across all files, dropped ones included -
    /// the denominator for "how much of this NZB did we match".
    pub segments: usize,
    /// Most common `release_stem` across the inner filename hints
    /// (subject-quoted names). Usually the real release name even when
    /// the referenced articles are obfuscated - but it is a hint, not
    /// an identity.
    pub inner_stem: Option<String>,
    /// `<meta type="title"|"name">`, when present.
    pub meta_title: Option<String>,
    /// The bounded reverse-map probe set: the first
    /// [`PROBES_PER_FILE`] ids of each file, capped at [`PROBE_CAP`]
    /// overall, deduped, stored (bracketed) form. What
    /// `find_releases_by_msgids` should be fed - `msgids` is the full
    /// set for the exact-count instrument, this is the cheap sample
    /// the persistent map can actually answer.
    pub lead_ids: Vec<String>,
}

/// Parse a posted NZB and extract the identity-join material. Parse
/// errors are the caller's signal that the object was not really an
/// NZB (the measured parse-success rate is part of the deliverable).
pub fn nzb_identity(xml: &[u8]) -> Result<NzbIdentity, crate::nzb::NzbError> {
    let nzb = Nzb::parse(xml)?;
    let mut ids: Vec<String> = Vec::new();
    let mut lead_ids: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = Default::default();
    let mut segments = 0usize;
    let mut stems: std::collections::HashMap<String, usize> = Default::default();
    for f in &nzb.files {
        segments += f.segments.len() + f.dropped_segments;
        for (i, s) in f.segments.iter().enumerate() {
            // Stored form is bracketed (OVER keeps the brackets); the
            // NZB schema strips them. Bracket to match.
            let mid = format!("<{}>", s.message_id);
            if seen.insert(mid.clone()) {
                if i < PROBES_PER_FILE && lead_ids.len() < PROBE_CAP {
                    lead_ids.push(mid.clone());
                }
                ids.push(mid);
            }
        }
        if let Some(name) = f.filename_hint() {
            let stem = crate::names::release_stem(name);
            if !stem.is_empty() {
                *stems.entry(stem).or_default() += 1;
            }
        }
    }
    let inner_stem = stems
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map(|(stem, _)| stem);
    let meta_title = nzb
        .meta
        .iter()
        .find(|(t, v)| (t == "title" || t == "name") && !v.is_empty())
        .map(|(_, v)| v.clone());
    Ok(NzbIdentity {
        msgids: ids,
        files: nzb.files.len(),
        segments,
        inner_stem,
        meta_title,
        lead_ids,
    })
}

// The MsgidSet `NameClaim.key` digest is CANONICAL in the claims layer
// (`crate::index::msgid_set_key`) - one definition so every lane
// derives the same key for the same id set. This module deliberately
// does not carry its own.

/// Group one NZB's reverse-lookup rows into per-release join summaries.
/// `ids` is that NZB's own (deduped) message-id set; `rows` may be the
/// result of a BATCHED lookup covering many NZBs - rows for ids this
/// NZB does not contain are ignored, so per-NZB match counts never
/// conflate across NZBs that hit the same release.
#[cfg(feature = "indexer")]
pub fn group_hits(ids: &[String], rows: &[crate::index::MsgidRow]) -> Vec<crate::index::MsgidHit> {
    use std::collections::{HashMap, HashSet};
    let mine: HashSet<&str> = ids.iter().map(String::as_str).collect();
    let mut per: HashMap<i64, crate::index::MsgidHit> = HashMap::new();
    // A message-id may map to several rows (crossposts) and appears
    // once per (id, release) pair; ids are already deduped upstream,
    // but count distinct ids per release anyway so a hostile lookup
    // result cannot inflate a match count.
    let mut counted: HashSet<(i64, &str)> = HashSet::new();
    for row in rows {
        if !mine.contains(row.msgid.as_str()) {
            continue;
        }
        if !counted.insert((row.release_id, row.msgid.as_str())) {
            continue;
        }
        let h = per
            .entry(row.release_id)
            .or_insert_with(|| crate::index::MsgidHit {
                release_id: row.release_id,
                stem: row.stem.clone(),
                matched: 0,
                row_nsegs: row.row_nsegs,
                ids: Vec::new(),
            });
        h.matched += 1;
        h.row_nsegs = h.row_nsegs.max(row.row_nsegs);
        h.ids.push(row.msgid.clone());
    }
    let mut out: Vec<_> = per.into_values().collect();
    out.sort_by_key(|h| std::cmp::Reverse(h.matched));
    out
}

/// The multi-msgid agreement rule. `matched` is how many of the NZB's
/// payload message-ids landed in the candidate row; `row_nsegs` is how
/// many segments that row holds. Both sides must agree substantially:
/// an absolute floor (see [`MIN_MSGID_QUORUM`]) plus majority coverage
/// of the row, so three stray ids in a thousand-segment row cannot
/// rename it.
pub fn quorum(matched: usize, row_nsegs: u32) -> bool {
    matched >= MIN_MSGID_QUORUM && matched.saturating_mul(2) >= row_nsegs as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nzb_xml(files: &[(&str, &[&str])]) -> Vec<u8> {
        let mut s = String::from(r#"<?xml version="1.0"?><nzb>"#);
        for (subject, ids) in files {
            s.push_str(&format!(r#"<file subject="{subject}" poster="p@x" date="1"><groups><group>a.b.test</group></groups><segments>"#));
            for (i, id) in ids.iter().enumerate() {
                s.push_str(&format!(
                    r#"<segment bytes="100" number="{}">{id}</segment>"#,
                    i + 1
                ));
            }
            s.push_str("</segments></file>");
        }
        s.push_str("</nzb>");
        s.into_bytes()
    }

    #[test]
    fn identity_brackets_msgids_and_finds_dominant_stem() {
        let xml = nzb_xml(&[
            (
                r#"&quot;Show.S01E01.1080p-GRP.part1.rar&quot; yEnc (1/2)"#,
                &["a@x", "b@x"],
            ),
            (
                r#"&quot;Show.S01E01.1080p-GRP.part2.rar&quot; yEnc (1/1)"#,
                &["c@x"],
            ),
        ]);
        let id = nzb_identity(&xml).unwrap();
        assert_eq!(id.files, 2);
        assert_eq!(id.segments, 3);
        assert_eq!(id.msgids, vec!["<a@x>", "<b@x>", "<c@x>"]);
        assert_eq!(id.inner_stem.as_deref(), Some("Show.S01E01.1080p-GRP"));
    }

    #[test]
    fn identity_dedupes_repeated_msgids() {
        // A hostile NZB repeating one message-id thousands of times
        // must count as ONE join key, or repetition alone would beat
        // the quorum floor.
        let xml = nzb_xml(&[(r#"x yEnc (1/3)"#, &["a@x", "a@x", "a@x"])]);
        let id = nzb_identity(&xml).unwrap();
        assert_eq!(id.msgids, vec!["<a@x>"]);
        assert_eq!(id.segments, 3);
    }

    #[test]
    fn identity_meta_title() {
        let xml = br#"<nzb><head><meta type="title">Real.Name.2026</meta></head>
            <file subject="s" poster="p" date="1"><groups><group>g</group></groups>
            <segments><segment bytes="1" number="1">m@x</segment></segments></file></nzb>"#;
        let id = nzb_identity(xml).unwrap();
        assert_eq!(id.meta_title.as_deref(), Some("Real.Name.2026"));
    }

    #[test]
    fn lead_ids_take_leading_per_file_under_the_cap() {
        // One file with more segments than the per-file quota, plus a
        // second file: the probe set holds each file's LEADING ids
        // only, while `msgids` keeps everything.
        let many: Vec<String> = (0..PROBES_PER_FILE + 4)
            .map(|i| format!("f1s{i}@x"))
            .collect();
        let many_refs: Vec<&str> = many.iter().map(String::as_str).collect();
        let xml = nzb_xml(&[
            (r#"a yEnc (1/12)"#, &many_refs),
            (r#"b yEnc (1/1)"#, &["f2s0@x"]),
        ]);
        let id = nzb_identity(&xml).unwrap();
        assert_eq!(id.msgids.len(), many.len() + 1);
        assert_eq!(id.lead_ids.len(), PROBES_PER_FILE + 1);
        assert_eq!(id.lead_ids[0], "<f1s0@x>");
        assert_eq!(id.lead_ids[PROBES_PER_FILE], "<f2s0@x>");
        assert!(id.lead_ids.iter().all(|m| id.msgids.contains(m)));
    }

    #[test]
    fn quorum_needs_floor_and_majority() {
        assert!(!quorum(0, 0));
        assert!(!quorum(2, 2)); // below the absolute floor
        assert!(quorum(3, 3)); // exact full match
        assert!(quorum(3, 6)); // exactly half
        assert!(!quorum(3, 7)); // under half of the row
        assert!(!quorum(3, 1000)); // seeded ids in a big row
        assert!(quorum(600, 1000));
    }

    #[test]
    fn gzip_payload_inflates_under_cap() {
        use std::io::Write;
        let xml = nzb_xml(&[(r#"x yEnc (1/1)"#, &["a@x"])]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&xml).unwrap();
        let packed = gz.finish().unwrap();
        // Round-trip the sniff+inflate arm via a fake "assembled" body.
        assert_eq!(packed[0], 0x1f);
        use std::io::Read;
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&packed[..])
            .take(MAX_POSTED_NZB + 1)
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, xml);
        assert!(nzb_identity(&out).is_ok());
    }
}
