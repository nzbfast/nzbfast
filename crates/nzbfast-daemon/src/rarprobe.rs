//! The on-demand RAR byte-probe: given an open connection and an article
//! budget, read a release's RAR volume headers and say what is inside.
//!
//! **On demand only**, which is why it is here and not in the scan lane.
//! `tasks::indexer::probe7z` runs it from the naming worker and
//! `api::index::pull` runs it from the PULL surface, for a row somebody
//! is looking at right now - so leaving it in the lane made an API
//! handler depend on the background-task layer, which is the one edge
//! `tools/modgraph.py --serve` had left when this moved.
//!
//! It fits a layer below both because it needs neither: an open
//! `nzbkit::nntp::Connection`, a `&[ProbeFile]` and an out-param budget
//! go in, a `RarNameRun` comes out, and no `Daemon` is touched. The
//! LANE - the rotation, the cooldowns, the stand-down while anything
//! downloads, the daily tallies - stays where it was, and so does the
//! whole single-7z recipe, which nothing outside the lane runs.
//!
//! `probe_fetch` comes with it because it is the bounded fetch both
//! probes are built on; `run_sevenz_probe` still calls it, reaching
//! down.
//!
//! Verbatim from `probe7z.rs`, visibility widened from `pub(super)` on
//! the two helpers because `super` is a different module now.

use super::*;

/// One bounded BODY fetch, decoded. `Ok(None)` = the article is gone
/// (430) or does not decode as yEnc - both "this bytes path is closed",
/// distinct from a connection error which aborts the whole probe run.
#[cfg(feature = "indexer")]
pub async fn probe_fetch(
    conn: &mut nzbkit::nntp::Connection,
    msgid: &str,
    spent: &mut (u64, u64),
) -> Result<Option<nzbkit::yenc::Decoded>, nzbkit::nntp::NntpError> {
    let fetch = conn.body(msgid);
    let body = match tokio::time::timeout(std::time::Duration::from_secs(20), fetch).await {
        Ok(r) => r?,
        Err(_) => {
            return Err(nzbkit::nntp::NntpError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "probe article timeout",
            )));
        }
    };
    spent.0 += 1;
    let Some(raw) = body else { return Ok(None) };
    spent.1 += raw.len() as u64;
    Ok(nzbkit::yenc_simd::decode(&raw).ok())
}

/// The volumes worth reading a head out of: first, middle and last of
/// the set's RAR members, deduplicated.
#[cfg(feature = "indexer")]
pub fn rar_probe_volumes(files: &[nzbkit::index::ProbeFile]) -> Vec<nzbkit::index::ProbeFile> {
    let mut vols: Vec<&nzbkit::index::ProbeFile> = files
        .iter()
        .filter(|f| {
            let n = f.filename.to_lowercase();
            // `.partNN.rar` ends in `.rar` like any other; `.rNN` is the
            // old-style continuation naming (29 sets on the measured
            // index - negligible, but free to accept).
            !f.segments.is_empty()
                && (n.ends_with(".rar")
                    || n.rsplit_once(".r").is_some_and(|(head, ext)| {
                        !head.is_empty()
                            && ext.len() == 2
                            && ext.chars().all(|c| c.is_ascii_digit())
                    }))
        })
        .collect();
    if vols.is_empty() {
        return Vec::new();
    }
    vols.sort_by(|a, b| a.filename.cmp(&b.filename));
    let mut order = vec![vols.len() / 2, 0, vols.len() - 1];
    order.dedup();
    let mut seen = std::collections::BTreeSet::new();
    order
        .into_iter()
        .filter(|i| seen.insert(*i))
        .map(|i| vols[i].clone())
        .collect()
}

/// What one on-demand RAR probe concluded.
#[cfg(feature = "indexer")]
pub struct RarNameRun {
    /// One of: named, junkname, encrypted, nohead, parsefail, noshape,
    /// positional (the stored part-1 segment decodes mid-archive - the
    /// index numbered this family positionally, so no head is reachable).
    pub outcome: &'static str,
    pub name: Option<String>,
    /// `{unpacked_size}:{crc32}` from the header, when it carried one.
    pub key: Option<String>,
    /// Which dialect earned an `encrypted` outcome, for the terminal
    /// classification's evidence field.
    pub enc_kind: Option<nzbkit::index::EncKind>,
    pub articles: u64,
    pub bytes: u64,
}

/// Read one release's RAR volume headers for the inner filename.
///
/// **On demand only.** The pilot's verdict on a scan-time RAR lane is
/// NO-GO and stands: 24 of 26 sampled RAR5 sets are `-hp`, 98% of the
/// band by bytes, and half the readable remainder carries an inner
/// filename as obfuscated as the outer post - ~1.2% real-name yield by
/// bytes, the worst evidence-per-byte in the build order. What survives
/// is this: one to three articles, on a row a human or a grab is
/// already looking at, reusing `rar::VolumeMapper` verbatim.
#[cfg(feature = "indexer")]
pub async fn run_rar_probe(
    conn: &mut nzbkit::nntp::Connection,
    files: &[nzbkit::index::ProbeFile],
    spent: &mut (u64, u64),
) -> Result<RarNameRun, nzbkit::nntp::NntpError> {
    // Out-param for the same reason as `run_sevenz_probe`: spend paid
    // before a connection error must reach the caller's tallies.
    use nzbkit::nameprobe;
    let vols = rar_probe_volumes(files);
    if vols.is_empty() {
        return Ok(RarNameRun {
            outcome: "noshape",
            name: None,
            key: None,
            enc_kind: None,
            articles: 0,
            bytes: 0,
        });
    }
    let mut last: &'static str = "nohead";
    for vol in &vols {
        // The part-1 TUPLE, not segments[0] and not the filename: this
        // band's segment order is scrambled against volume order, and
        // the tuple ordinal is the key that survives it.
        let Some((_, msgid, _)) = vol
            .segments
            .iter()
            .find(|(part, _, _)| *part == 1)
            .or_else(|| vol.segments.first())
        else {
            continue;
        };
        let Some(dec) = probe_fetch(conn, msgid, spent).await? else {
            continue;
        };
        if dec.offset() != 0 {
            // The stored part-1 tuple decoded mid-archive: this
            // family's stored part numbers are POSITIONAL (the scan
            // held a slice of the post and numbered what it had), so
            // the volume head is not reachable from any segment this
            // row holds, in this volume or its siblings. Measured
            // live on beta 8 (1 Sep 2026): a stored part 1 of
            // `5tF1OW5LURuyB8tC.part01.rar` was wire part=14 at
            // begin=10223617, and every such row cost three fetches
            // as `nohead` before rotating out. Terminal, one fetch.
            // (Version C's handoff, finding 7, saw the same thing
            // from the wire side.)
            last = "positional";
            break;
        }
        match nameprobe::rar_head(&dec.data, vol.bytes.max(0) as u64) {
            Ok(head) => {
                let Some((name, key)) = nameprobe::pick_rar_media_name(&head) else {
                    last = "junkname";
                    continue;
                };
                return Ok(RarNameRun {
                    outcome: "named",
                    name: Some(name),
                    key,
                    enc_kind: None,
                    articles: spent.0,
                    bytes: spent.1,
                });
            }
            // The wall. A property of the SET, not of this volume, so
            // there is nothing to gain from the other candidates - and
            // the classification that follows means nothing ever pays
            // these articles again.
            Err(nameprobe::ProbeError::EncryptedHeader) => {
                return Ok(RarNameRun {
                    outcome: "encrypted",
                    name: None,
                    key: None,
                    enc_kind: Some(if head_is_rar5(&dec.data) {
                        nzbkit::index::EncKind::Rar5HeadCrypt
                    } else {
                        nzbkit::index::EncKind::Rar4MhdPassword
                    }),
                    articles: spent.0,
                    bytes: spent.1,
                });
            }
            Err(nameprobe::ProbeError::BadStart) => last = "nohead",
            Err(_) => last = "parsefail",
        }
    }
    Ok(RarNameRun {
        outcome: last,
        name: None,
        key: None,
        enc_kind: None,
        articles: spent.0,
        bytes: spent.1,
    })
}

/// Which RAR dialect these leading bytes are, for the classification's
/// evidence field only. The signatures share their first five bytes;
/// RAR5's is two longer and ends `\x01\x00`.
#[cfg(feature = "indexer")]
fn head_is_rar5(head: &[u8]) -> bool {
    head.starts_with(b"Rar!\x1a\x07\x01\x00")
}
