//! Re-fetch of volumes the one-pass RAR trim DROPPED and a demote then
//! materialized with holes.
//!
//! Measured 21 Aug 2026 (research/MEASURED-HOLDS-LADDER-2026-08-21.md):
//! a compressed set 2-5x over the holds cap stayed one-pass at 1.478x
//! payload on a 110 MB/s line, and the whole 0.48x was the drop-behind
//! trim spilling consumed input into each volume's file so that a
//! later demote could materialize byte-exact - bytes a clean job never
//! read back. The trim now DROPS that prefix on a healthy top-level
//! chase (`nzbkit::extract`, `rar_trim_set`), and this module is the
//! other half of that bargain: if a demote comes after all, the
//! materialized file is missing exactly the dropped ranges, and they
//! come back off the wire here, through the same side-fetch driver the
//! repair ladder uses for recovery volumes, BEFORE anything reads the
//! file back. The refetch is whole-volume: a drop is volume-granular
//! in practice (`min_release` is half the cap, larger than a volume on
//! every set measured), and the side-fetch consumer writes articles at
//! their own offsets, so the bytes already on disk are simply
//! rewritten with themselves.
//!
//! Two call sites, because a demote fires at two times: a budget breach
//! mid-download (the slot is materialized by the time settle runs, so
//! the refetch precedes settle's read-back) and an engine failure at
//! `finish()` (after settle, so the refetch precedes the disk unpack).

use crate::repair::{
    SideCancel, VolumeOpen, fetch_volume_articles_with, volume_prealloc_cap, volume_reqs,
};
use crate::*;
use nzbkit::disk::{join_out_name, sanitize_out_name};
use std::path::Path;
use tracing::{info, warn};

/// Re-fetch every demoted volume whose file carries dropped ranges.
/// Never fails the job itself: a volume the fetch could not complete
/// keeps its holes, and the read-back or unpack that follows reports
/// them exactly as it reports any damaged volume. Returns the number
/// of volumes re-fetched in full.
pub(super) async fn refetch_dropped_volumes(
    extractor: &Arc<nzbkit::extract::Extractor>,
    slot_file: &[usize],
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Arc<Nzb>,
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    cancel: Option<&SideCancel>,
) -> Result<usize> {
    let dropped = extractor.dropped_volumes();
    if dropped.is_empty() {
        return Ok(0);
    }
    let mut ids: Vec<nzbkit::pool::ArticleReq> = Vec::new();
    let mut id_to_file = std::collections::HashMap::new();
    // Each entry carries its NZB file index: that is the key the
    // side-fetch attributes article failures to, and without it a
    // volume can only be judged by the fetch-wide total.
    // The third field is the count of this file's declared segments
    // `volume_reqs` did not request because an earlier file already
    // owned the message id (Codex F-02): never asked for, so never
    // reported missing, so invisible to `failures` below.
    let mut wanted: Vec<(usize, &nzbkit::extract::DroppedVolume, u32)> = Vec::new();
    let mut hole_bytes = 0u64;
    for d in &dropped {
        let Some(&fi) = slot_file.get(d.slot) else {
            // A slot with no NZB file behind it (a resume seed of a file
            // the NZB no longer lists) cannot be re-fetched; its holes
            // stay and the disk pass says so.
            continue;
        };
        hole_bytes += d.ranges.iter().map(|(_, l)| *l).sum::<u64>();
        let omitted = volume_reqs(nzb, fi, &mut ids, &mut id_to_file);
        wanted.push((fi, d, omitted));
    }
    if wanted.is_empty() {
        return Ok(0);
    }
    info!(
        target: "par2",
        "♻ re-fetching {} volume(s) the one-pass trim dropped ({:.1} MB of holes) - the set demoted to disk after all",
        wanted.len(),
        hole_bytes as f64 / 1e6
    );
    // Additive: the demote materialized this volume minus its dropped
    // ranges, and those bytes are correct. A truncating open would make
    // one failed article a fresh hole over them, with no retry behind
    // it (the claim is cleared below whatever happens).
    let (failures, paths) = fetch_volume_articles_with(
        servers,
        ids,
        id_to_file,
        out_dir,
        buf_pool,
        volume_prealloc_cap(nzb),
        cancel,
        VolumeOpen::Additive,
    )
    .await?;
    // The side-fetch names the file from the article's yEnc header -
    // the slot's posted name. The slot may have moved since (a PAR2
    // rename before a materialize-for-repair, a deobfuscation): then
    // the fetched file, complete, replaces the holed one at the slot's
    // own path. A volume dropped whole never had a writer and so has
    // no path; it takes the slot's current name.
    let mut done = 0;
    for (fi, d, omitted) in wanted {
        // THIS volume's own article failures, plus any the fetch could
        // not attribute to a file at all, plus the segments that were
        // never requested at all because an earlier file owned the id.
        let short = failures.for_file(fi).saturating_add(omitted);
        // One attempt, whatever the outcome: a short volume is now a
        // damaged volume like any other, and the ladder below says so.
        // Leaving the claim would only make the next hook fetch the
        // same articles from the same servers again.
        extractor.note_dropped_refetched(d.slot);
        let fetched = join_out_name(out_dir, &sanitize_out_name(&d.posted));
        let own = extractor
            .slot_path(d.slot)
            .unwrap_or_else(|| join_out_name(out_dir, &sanitize_out_name(&d.current)));
        match install_for(short, paths.contains(&fetched), own != fetched) {
            Install::Absent => warn!(
                target: "par2",
                "dropped volume {} did not come back under its posted name - its holes stay",
                d.posted
            ),
            Install::Discard => {
                let _ = std::fs::remove_file(&fetched);
                warn!(
                    target: "par2",
                    "dropped volume {} came back short ({short} article failure(s)) - keeping the demoted copy, its holes stay",
                    d.posted
                );
            }
            Install::Rename => {
                std::fs::rename(&fetched, &own)?;
                done += 1;
            }
            Install::InPlace { whole } => {
                if whole {
                    done += 1;
                }
            }
        }
    }
    let failed = failures.total();
    if failed > 0 {
        warn!(
            target: "par2",
            "{failed} article(s) of the dropped volumes did not come back - the disk pass will report them"
        );
    }
    Ok(done)
}

/// What to do with one dropped volume's refetched file.
///
/// Split out of the loop above so the rule the Codex F-05 fix turns on
/// can be stated in a table, without a pool or an extractor. The table
/// stays because it is the cheap statement of the rule; since 23 Aug
/// 2026 (TODO 230) every cell of it is ALSO reached by a run of the
/// real driver against a mock provider, over three rigs below:
/// `a_renamed_pair_installs_the_whole_volume_and_discards_the_short_one`
/// takes `Rename` and `Discard`,
/// `an_unrenamed_refetch_writes_in_place_and_keeps_what_the_demote_had`
/// takes both arms of `InPlace`, and
/// `a_volume_that_never_comes_back_leaves_its_demoted_copy_alone`
/// takes `Absent`.
#[derive(Debug, PartialEq, Eq)]
enum Install {
    /// Nothing came back under the posted name at all.
    Absent,
    /// The fetch wrote straight over the slot's own file (the names
    /// agree). The open is Additive, so whatever arrived is already in
    /// place over the bytes the demote kept, and there is nothing to
    /// install; `whole` only says whether to count it as re-fetched.
    InPlace { whole: bool },
    /// The names differ and this volume came back whole: the fetched
    /// file replaces the holed one at the slot's own path.
    Rename,
    /// The names differ and THIS volume lost articles, so the fetched
    /// file is a fresh sparse one holding only what arrived, while the
    /// slot's own file holds every byte the demote kept. Renaming would
    /// turn one failed article into a hole over good data, with no
    /// retry behind it (Codex F-05, 22 Aug 2026). Discard the fetch.
    Discard,
}

/// `short` is THIS volume's own failure count - not the fetch-wide
/// total, which condemns every whole volume that shares a fetch with a
/// short one.
fn install_for(short: u32, fetched_present: bool, names_differ: bool) -> Install {
    if !fetched_present {
        return Install::Absent;
    }
    match (names_differ, short == 0) {
        (false, whole) => Install::InPlace { whole },
        (true, true) => Install::Rename,
        (true, false) => Install::Discard,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nzbkit::mock::{Chaos, MockServer};

    /// The whole driver, end to end, on exactly the shape the F-05
    /// stopgap got wrong: TWO dropped volumes in ONE re-fetch, both
    /// slots RENAMED since the drop (so each fetched file lands beside
    /// the demoted copy instead of over it), one volume losing an
    /// article and the other coming back whole. The whole one must be
    /// installed and counted; the short one's fetch must be thrown away
    /// with the demoted copy's bytes untouched.
    ///
    /// `install_for` above states that rule and is tested on its own,
    /// but nothing checked that the driver ASKS it the right question:
    /// the stopgap handed it the fetch-wide total, which is a value
    /// this test's volume 0 can only survive if the per-file map is
    /// what reaches it.
    #[tokio::test]
    async fn a_renamed_pair_installs_the_whole_volume_and_discards_the_short_one() {
        use nzbkit::nzb::{NzbFile, Segment};
        // Two articles per volume, the first of which is exactly the
        // range the trim dropped - so a lost first article leaves the
        // fetched file holding nothing the demoted copy does not
        // already have, which is why renaming it over would destroy
        // good bytes.
        const HALF: usize = 2048;
        let dir = std::env::temp_dir().join(format!("nzbfast-dropped-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let posted = ["set.part01.rar", "set.part02.rar"];
        // Where a PAR2 rename moved each slot after the drop.
        let renamed = ["Movie.part01.rar", "Movie.part02.rar"];
        let vols: Vec<Vec<u8>> = (0..2u8)
            .map(|v| {
                (0..HALF * 2)
                    .map(|i| (i as u8).wrapping_mul(3).wrapping_add(v * 17))
                    .collect()
            })
            .collect();

        // The extractor as a demote-after-drop leaves it: each slot's
        // file materialized minus its dropped prefix, then renamed.
        let ex = Arc::new(nzbkit::extract::Extractor::new(&dir, 2, false));
        for (slot, vol) in vols.iter().enumerate() {
            ex.write(
                slot,
                posted[slot],
                vol.len() as u64,
                HALF as u64,
                &vol[HALF..],
            )
            .unwrap();
            let own = dir.join(renamed[slot]);
            std::fs::rename(dir.join(posted[slot]), &own).unwrap();
            ex.note_slot_renamed(slot, own);
            ex.seed_dropped_volume(slot, posted[slot], vec![(0, HALF as u64)]);
        }

        // The wire: both articles of volume 0, and only the second of
        // volume 1. A 430 that echoes the id is terminal on the first
        // ask, so the fetch charges volume 1 exactly one failure.
        let mut arts = std::collections::HashMap::new();
        let mut files = Vec::new();
        for (slot, vol) in vols.iter().enumerate() {
            let mut segments = Vec::new();
            for part in 0..2u32 {
                let at = part as usize * HALF;
                let id = format!("v{slot}p{part}");
                if (slot, part) != (1, 0) {
                    arts.insert(
                        format!("<{id}>"),
                        nzbkit::yenc::encode(
                            posted[slot],
                            vol.len() as u64,
                            Some((part + 1, 2)),
                            at as u64 + 1,
                            &vol[at..at + HALF],
                        ),
                    );
                }
                segments.push(Segment {
                    number: part + 1,
                    bytes: HALF as u64 * 2,
                    message_id: id,
                });
            }
            files.push(NzbFile {
                subject: posted[slot].to_string(),
                segments,
                ..Default::default()
            });
        }
        let nzb = Arc::new(Nzb {
            files,
            meta: Vec::new(),
        });
        let chaos = Chaos {
            missing: ["<v1p0>".to_string()].into_iter().collect(),
            echo_missing_id: true,
            ..Default::default()
        };
        let srv = MockServer::start(arts, chaos).await;
        let mut sc = srv.server_config();
        sc.connections = 2;
        let pc = nzbkit::pool::PoolConfig {
            connections: 2,
            ..Default::default()
        };

        let done = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            refetch_dropped_volumes(
                &ex,
                &[0, 1],
                &[(sc, pc)],
                &nzb,
                &dir,
                &nzbkit::pool::BufPool::new(8),
                None,
            ),
        )
        .await
        .expect("the re-fetch must return, not park")
        .expect("a re-fetch never fails the job");

        assert_eq!(done, 1, "only the whole volume counts as re-fetched");
        // Volume 0 came back whole under its posted name and replaced
        // the holed copy at the slot's own path.
        assert_eq!(
            std::fs::read(dir.join(renamed[0])).unwrap(),
            vols[0],
            "the whole volume was not installed at the slot's own name"
        );
        assert!(
            !dir.join(posted[0]).exists(),
            "the installed volume left a copy under its posted name"
        );
        // Volume 1 came back short: its fetch is gone and the demoted
        // copy still holds every byte the demote kept.
        assert!(
            !dir.join(posted[1]).exists(),
            "the short volume's partial fetch was not discarded"
        );
        let mut kept = vec![0u8; HALF];
        kept.extend_from_slice(&vols[1][HALF..]);
        assert_eq!(
            std::fs::read(dir.join(renamed[1])).unwrap(),
            kept,
            "the short volume's demoted copy lost bytes to the refetch"
        );
        // One attempt per volume, whatever the outcome.
        assert!(
            ex.dropped_volumes().is_empty(),
            "the claims must be cleared even for the volume that stayed short"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Codex F-02 (23 Aug 2026): the same shape as the pair above, but
    /// the later volume loses an article to a DUPLICATE message id
    /// rather than to the wire. `volume_reqs` gives a repeated id to its
    /// first owner and simply does not request it for the second, so no
    /// `Missing` outcome ever comes back and `failures.for_file(1)` is
    /// 0. That zero used to read as "volume 1 came back whole", which
    /// took `Install::Rename` and put a file with a hole where the
    /// duplicate should have been over the demoted copy that held those
    /// bytes. The omitted segment is now counted and charged, so the
    /// later volume takes `Discard` and keeps what the demote left.
    #[tokio::test]
    async fn a_duplicate_id_in_a_renamed_volume_keeps_the_demoted_copy() {
        use nzbkit::nzb::{NzbFile, Segment};
        const HALF: usize = 2048;
        let dir = std::env::temp_dir().join(format!("nzbfast-dropdup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let posted = ["set.part01.rar", "set.part02.rar"];
        let renamed = ["Movie.part01.rar", "Movie.part02.rar"];
        let vols: Vec<Vec<u8>> = (0..2u8)
            .map(|v| {
                (0..HALF * 2)
                    .map(|i| (i as u8).wrapping_mul(3).wrapping_add(v * 17))
                    .collect()
            })
            .collect();

        // Both slots demoted minus their FIRST article's range, then
        // renamed by a PAR2 pass - so each fetched file lands beside the
        // demoted copy rather than over it.
        let ex = Arc::new(nzbkit::extract::Extractor::new(&dir, 2, false));
        for (slot, vol) in vols.iter().enumerate() {
            ex.write(
                slot,
                posted[slot],
                vol.len() as u64,
                HALF as u64,
                &vol[HALF..],
            )
            .unwrap();
            let own = dir.join(renamed[slot]);
            std::fs::rename(dir.join(posted[slot]), &own).unwrap();
            ex.note_slot_renamed(slot, own);
            ex.seed_dropped_volume(slot, posted[slot], vec![(0, HALF as u64)]);
        }

        // The malformed set: volume 0's SECOND segment and volume 1's
        // second segment carry one message id between them. Every
        // article the NZB names is on the wire and healthy - the later
        // volume comes back short purely by the ownership rule.
        let ids = [["v0p0", "shared"], ["v1p0", "shared"]];
        let mut arts = std::collections::HashMap::new();
        let mut files = Vec::new();
        for (slot, vol) in vols.iter().enumerate() {
            let mut segments = Vec::new();
            for part in 0..2u32 {
                let at = part as usize * HALF;
                let id = ids[slot][part as usize];
                // The shared body belongs to volume 0, its first owner,
                // and so carries volume 0's posted name.
                if (slot, part) != (1, 1) {
                    arts.insert(
                        format!("<{id}>"),
                        nzbkit::yenc::encode(
                            posted[slot],
                            vol.len() as u64,
                            Some((part + 1, 2)),
                            at as u64 + 1,
                            &vol[at..at + HALF],
                        ),
                    );
                }
                segments.push(Segment {
                    number: part + 1,
                    bytes: HALF as u64 * 2,
                    message_id: id.to_string(),
                });
            }
            files.push(NzbFile {
                subject: posted[slot].to_string(),
                segments,
                ..Default::default()
            });
        }
        let nzb = Arc::new(Nzb {
            files,
            meta: Vec::new(),
        });
        let srv = MockServer::start(arts, Chaos::default()).await;
        let mut sc = srv.server_config();
        sc.connections = 2;
        let pc = nzbkit::pool::PoolConfig {
            connections: 2,
            ..Default::default()
        };

        let done = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            refetch_dropped_volumes(
                &ex,
                &[0, 1],
                &[(sc, pc)],
                &nzb,
                &dir,
                &nzbkit::pool::BufPool::new(8),
                None,
            ),
        )
        .await
        .expect("the re-fetch must return, not park")
        .expect("a re-fetch never fails the job");

        assert_eq!(done, 1, "only the whole volume counts as re-fetched");
        assert_eq!(
            std::fs::read(dir.join(renamed[0])).unwrap(),
            vols[0],
            "the volume that owned the duplicate came back whole and must install"
        );
        assert!(
            !dir.join(posted[1]).exists(),
            "the volume short by an unrequested duplicate kept its partial fetch"
        );
        let mut kept = vec![0u8; HALF];
        kept.extend_from_slice(&vols[1][HALF..]);
        assert_eq!(
            std::fs::read(dir.join(renamed[1])).unwrap(),
            kept,
            "the demoted copy lost the bytes the duplicate's owner never gave back"
        );
        assert!(
            ex.dropped_volumes().is_empty(),
            "the claims must be cleared even for the volume that stayed short"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Bytes per article, and articles per volume, for the un-renamed
    /// rigs below. Three is the smallest count that puts a KEPT article
    /// behind the dropped prefix, and that is the whole rig: the
    /// re-fetch's own article failure has to land on bytes the demote
    /// materialized CORRECTLY, or a truncating open and an additive one
    /// leave the same file behind and neither test can tell them apart.
    const PART: u64 = 2048;
    const PARTS: u32 = 3;

    fn posted_name(slot: usize) -> String {
        format!("set.part{:02}.rar", slot + 1)
    }

    /// Byte-exact against the cold-run oracle, reporting the first
    /// offset that differs instead of dumping two 6 KB vectors.
    fn assert_same(got: &[u8], want: &[u8], what: &str) {
        assert_eq!(got.len(), want.len(), "{what}: wrong length");
        if let Some(at) = got.iter().zip(want).position(|(a, b)| a != b) {
            panic!(
                "{what}: first differs at byte {at} (got {:#04x}, want {:#04x})",
                got[at], want[at]
            );
        }
    }

    /// The world a demote-after-drop leaves when NOTHING renamed the
    /// slots: `n` volumes of [`PARTS`] articles each, every one
    /// materialized minus its first article's range and claiming that
    /// range as dropped, with the slot's own name still equal to the
    /// posted one. That equality is the point - it is what sends
    /// `install_for` down the `InPlace` arm, where the side-fetch
    /// writes straight into the file the demote left.
    ///
    /// Returns the out dir, the extractor, the NZB, the article map
    /// with every `missing` (slot, zero-based part) left out of it, and
    /// the full volume bytes - which are what a COLD run puts on disk,
    /// and so the oracle the assertions below compare against.
    fn unrenamed_demote(
        tag: &str,
        n: usize,
        missing: &[(usize, u32)],
    ) -> (
        std::path::PathBuf,
        Arc<nzbkit::extract::Extractor>,
        Arc<Nzb>,
        std::collections::HashMap<String, Vec<u8>>,
        Vec<Vec<u8>>,
    ) {
        use nzbkit::nzb::{NzbFile, Segment};
        let dir =
            std::env::temp_dir().join(format!("nzbfast-dropped-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let size = PART * PARTS as u64;
        let vols: Vec<Vec<u8>> = (0..n)
            .map(|v| {
                (0..size as usize)
                    .map(|i| (i as u8).wrapping_mul(3).wrapping_add(v as u8 * 17))
                    .collect()
            })
            .collect();
        let ex = Arc::new(nzbkit::extract::Extractor::new(&dir, n, false));
        let mut arts = std::collections::HashMap::new();
        let mut files = Vec::new();
        for (slot, vol) in vols.iter().enumerate() {
            let posted = posted_name(slot);
            // Materialized minus the dropped first article, and never
            // renamed, so `slot_path` still answers with this name.
            ex.write(slot, &posted, size, PART, &vol[PART as usize..])
                .unwrap();
            ex.seed_dropped_volume(slot, &posted, vec![(0, PART)]);
            let mut segments = Vec::new();
            for part in 0..PARTS {
                let at = (part as u64 * PART) as usize;
                let id = format!("v{slot}p{part}");
                if !missing.contains(&(slot, part)) {
                    arts.insert(
                        format!("<{id}>"),
                        nzbkit::yenc::encode(
                            &posted,
                            size,
                            Some((part + 1, PARTS)),
                            at as u64 + 1,
                            &vol[at..at + PART as usize],
                        ),
                    );
                }
                segments.push(Segment {
                    number: part + 1,
                    bytes: PART,
                    message_id: id,
                });
            }
            files.push(NzbFile {
                subject: posted,
                segments,
                ..Default::default()
            });
        }
        let nzb = Arc::new(Nzb {
            files,
            meta: Vec::new(),
        });
        (dir, ex, nzb, arts, vols)
    }

    /// A mock refusing every id in `arts`' complement, with the 430
    /// echoing the id so a refusal is terminal on the first ask - which
    /// is what makes the request ledger below a fixed number.
    async fn refusing_server(
        arts: std::collections::HashMap<String, Vec<u8>>,
        missing: &[&str],
    ) -> MockServer {
        let chaos = Chaos {
            missing: missing.iter().map(|s| s.to_string()).collect(),
            echo_missing_id: true,
            ..Default::default()
        };
        MockServer::start(arts, chaos).await
    }

    /// Drive the real re-fetch against `srv`, over the identity
    /// slot-to-file map this rig builds.
    async fn drive_refetch(
        ex: &Arc<nzbkit::extract::Extractor>,
        nzb: &Arc<Nzb>,
        dir: &Path,
        srv: &MockServer,
        n: usize,
    ) -> usize {
        let mut sc = srv.server_config();
        sc.connections = 2;
        let pc = nzbkit::pool::PoolConfig {
            connections: 2,
            // TODO 315's late re-ask is OFF for this rig, because
            // `assert_wire` below is built on every id being asked
            // EXACTLY ONCE and the re-ask deliberately asks a refused
            // article a second time. That is a real cost and a real
            // feature; it is just not the cost this rig measures, which
            // is whether the drop-and-refetch path over-fetches. The
            // re-ask has its own end-to-end pair in
            // `nzbkit::pool::unit_tests::recheck_tests`.
            recheck_430: false,
            ..Default::default()
        };
        let slot_file: Vec<usize> = (0..n).collect();
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            refetch_dropped_volumes(
                ex,
                &slot_file,
                &[(sc, pc)],
                nzb,
                dir,
                &nzbkit::pool::BufPool::new(8),
                None,
            ),
        )
        .await
        .expect("the re-fetch must return, not park")
        .expect("a re-fetch never fails the job")
    }

    /// What the retry PAID, on the wire, from the server's own ledger:
    /// every id asked for exactly once, and body bytes accounting for
    /// the articles that existed and no more. Wall time is not the
    /// measure here - a re-ask of one 2 KB article is invisible in a
    /// timing and obvious in this.
    fn assert_wire(srv: &MockServer, asks: usize, bodies: u64) {
        use std::sync::atomic::Ordering;
        let counts = srv.serve_counts();
        assert_eq!(
            counts.len(),
            asks,
            "the re-fetch asked for {} distinct article(s), not {asks}",
            counts.len()
        );
        assert!(
            srv.refetched().is_empty(),
            "an id was asked for twice: {:?}",
            srv.refetched()
        );
        let paid = srv.bytes_out.load(Ordering::Relaxed);
        // Body bytes plus dot-stuffing and each body's ".\r\n" - well
        // inside 1.5%, and far under one more article of slack.
        assert!(
            (bodies..bodies + bodies / 64 + 64).contains(&paid),
            "the retry put {paid} B on the wire for {bodies} B of article bodies"
        );
    }

    /// A subscriber that keeps every rendered line, for the one
    /// question the file system cannot answer. `Absent` and a short
    /// `InPlace` both leave the demoted copy exactly as it stood -
    /// correct either way, and so indistinguishable on disk - which
    /// makes the warning the only witness that a volume was judged
    /// ABSENT rather than merely incomplete.
    #[derive(Clone, Default)]
    struct Lines(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Lines {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Lines {
        type Writer = Lines;
        fn make_writer(&'a self) -> Lines {
            self.clone()
        }
    }

    impl Lines {
        /// Everything the driver has said so far, rendered.
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).expect("utf-8")
        }

        /// Capture this thread's tracing for as long as the guard
        /// lives. The re-fetch runs on the test thread (a
        /// `#[tokio::test]` is a current-thread runtime), so a
        /// thread-local default reaches it and every task it spawns.
        fn capture(&self) -> tracing::subscriber::DefaultGuard {
            use tracing_subscriber::layer::SubscriberExt as _;
            tracing::subscriber::set_default(
                tracing_subscriber::registry().with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .without_time()
                        .with_writer(self.clone()),
                ),
            )
        }
    }

    /// The COMMON dropped-volume shape, and the only end-to-end guard
    /// there is on the `VolumeOpen::Additive` argument at the call
    /// site: two volumes with NO rename behind them, so the side-fetch
    /// writes straight into the file the demote materialized.
    ///
    /// Volume 0 comes back whole. Volume 1 loses its LAST article -
    /// bytes OUTSIDE the dropped range, which the demote had already
    /// put on disk correctly - and that is what makes the open mode
    /// visible at all: additively those bytes stay and the volume ends
    /// byte-exact anyway (short, so uncounted), while a truncating open
    /// replaces them with a hole no retry stands behind. Flip that one
    /// constant to `Fresh` and this is the test that goes red.
    #[tokio::test]
    async fn an_unrenamed_refetch_writes_in_place_and_keeps_what_the_demote_had() {
        let (dir, ex, nzb, arts, vols) = unrenamed_demote("inplace", 2, &[(1, PARTS - 1)]);
        let bodies: u64 = arts.values().map(|a| a.len() as u64).sum();
        let srv = refusing_server(arts, &["<v1p2>"]).await;

        let done = drive_refetch(&ex, &nzb, &dir, &srv, 2).await;

        assert_eq!(done, 1, "only the whole volume counts as re-fetched");
        assert_same(
            &std::fs::read(dir.join(posted_name(0))).unwrap(),
            &vols[0],
            "the whole volume did not land in place under its own name",
        );
        assert_same(
            &std::fs::read(dir.join(posted_name(1))).unwrap(),
            &vols[1],
            "a lost article cost the short volume bytes the demote had \
             materialized - the call site's open is not Additive",
        );
        // In place means IN PLACE: no second copy under any name.
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![posted_name(0), posted_name(1)],
            "the in-place re-fetch left files behind"
        );
        assert_wire(&srv, 6, bodies);
        // One attempt per volume, whatever the outcome.
        assert!(
            ex.dropped_volumes().is_empty(),
            "the claims must be cleared even for the volume that stayed short"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `Absent`: a volume none of whose articles come back, so the
    /// side-fetch never opens a writer and nothing exists under the
    /// posted name for the driver to install. The demoted copy is the
    /// only copy there has ever been and must be handed on exactly as
    /// it stood - the branch does no file work at all, and this is what
    /// says so. Its neighbour, whole, still lands and is still counted:
    /// a dead volume must not condemn the fetch it shared.
    #[tokio::test]
    async fn a_volume_that_never_comes_back_leaves_its_demoted_copy_alone() {
        let (dir, ex, nzb, arts, vols) = unrenamed_demote("absent", 2, &[(1, 0), (1, 1), (1, 2)]);
        let bodies: u64 = arts.values().map(|a| a.len() as u64).sum();
        let before = std::fs::read(dir.join(posted_name(1))).unwrap();
        let srv = refusing_server(arts, &["<v1p0>", "<v1p1>", "<v1p2>"]).await;

        let log = Lines::default();
        let done = {
            let _capturing = log.capture();
            drive_refetch(&ex, &nzb, &dir, &srv, 2).await
        };

        assert_eq!(done, 1, "the dead volume must not condemn its neighbour");
        assert_same(
            &std::fs::read(dir.join(posted_name(0))).unwrap(),
            &vols[0],
            "the whole volume did not land in place under its own name",
        );
        assert_same(
            &before,
            &{
                let mut kept = vec![0u8; PART as usize];
                kept.extend_from_slice(&vols[1][PART as usize..]);
                kept
            },
            "the rig's own demoted copy is not the shape this test assumes",
        );
        assert_same(
            &std::fs::read(dir.join(posted_name(1))).unwrap(),
            &before,
            "the Absent branch touched the demoted copy",
        );
        // Which branch, not just which bytes - see [`Lines`].
        assert!(
            log.text()
                .contains("did not come back under its posted name"),
            "the dead volume was not judged Absent; the driver said: {}",
            log.text()
        );
        assert_wire(&srv, 6, bodies);
        assert!(
            ex.dropped_volumes().is_empty(),
            "the claims must be cleared even for the volume that never arrived"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The F-05 stopgap keyed this on the FETCH-WIDE failure count, so
    /// one lost article in volume A discarded a complete volume B that
    /// happened to share the fetch. Per volume: A is kept out, B lands.
    #[test]
    fn a_short_volume_does_not_condemn_a_whole_one() {
        assert_eq!(install_for(1, true, true), Install::Discard);
        assert_eq!(install_for(0, true, true), Install::Rename);
    }

    /// With the names equal the Additive open already wrote over the
    /// slot's own file, so there is nothing to install and nothing to
    /// throw away - a short volume simply keeps its remaining holes and
    /// is not counted as re-fetched.
    #[test]
    fn a_same_name_refetch_is_never_discarded() {
        assert_eq!(
            install_for(0, true, false),
            Install::InPlace { whole: true }
        );
        assert_eq!(
            install_for(3, true, false),
            Install::InPlace { whole: false }
        );
    }

    /// No file under the posted name beats every other consideration:
    /// nothing was written, so there is nothing to rename or remove.
    #[test]
    fn a_volume_that_never_arrived_is_absent_whatever_its_count() {
        assert_eq!(install_for(0, false, true), Install::Absent);
        assert_eq!(install_for(9, false, false), Install::Absent);
    }
}
