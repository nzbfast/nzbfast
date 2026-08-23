//! The held-article journal join (`get/workers.rs`): what
//! [`flush_pending_r`] may and may not complete a parked
//! `Persist::Held` article from.
//!
//! A child of `workers`, out here for the size gate (TODO 106) like its
//! par-race and spec-ladder siblings: these rigs drive whole extractor
//! fixtures through a demote, and that is not text a production file
//! should carry. The module is named for its file so size-gate.py's
//! CFG_TEST_MOD resolver still reads it as test code; `super` is still
//! `workers`, so `use super::*` reaches exactly what the inline module
//! reached.

use super::*;

/// TODO 100 follow-up: articles that arrive before the offset-0
/// sniff establishes the store mapper park as `Persist::Held`; once
/// the sniff lands and the extractor drains them into the inner
/// file, `flush_pending_r` must complete their journal records -
/// and the records must be RESTORABLE, not merely written. Without
/// the join, the first run's journal nondeterministically lacked
/// `R` records for early/mid payload articles of a mapped store
/// set, and every crash/ENOSPC resume refetched them for no
/// reason.
#[test]
fn held_articles_journal_after_their_holds_drain() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pending-r-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let data: Vec<u8> = (0..600_000u32)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
        .collect();
    let vol = nzbkit::rar::fixtures::rar5_volume(&[("movie.mkv", 600_000, &data, false, false)]);
    let (journal, _) = nzbkit::journal::Journal::open(&dir, b"nzb-held").unwrap();
    let ex = nzbkit::extract::Extractor::new(&dir, 1, true);
    let pending_r = std::sync::Mutex::new(PendingR::default());
    let art = 100_000usize;
    let n = vol.len().div_ceil(art);
    // Every article except offset-0, in reverse: all park.
    for i in (1..n).rev() {
        let s = i * art;
        let e = ((i + 1) * art).min(vol.len());
        match ex
            .write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
            .unwrap()
        {
            nzbkit::extract::Persist::Held(frags) => {
                pending_r.lock_ok().parked.push(ParkedR {
                    sidx: 0,
                    id: format!("<er-{i}@t>").into(),
                    name: "v.rar".into(),
                    size: vol.len() as u64,
                    off: s as u64,
                    len: (e - s) as u64,
                    frags,
                    par2_main: false,
                });
            }
            _ => panic!("article {i} arrived pre-sniff and must park as Held"),
        }
        flush_pending_r(&pending_r, &ex, &journal);
    }
    assert_eq!(
        pending_r.lock_ok().parked.len(),
        n - 1,
        "nothing may journal before its bytes drain"
    );
    // The offset-0 sniff maps the volume and the drain writes every
    // held payload byte; the next flush completes their records.
    ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..art])
        .unwrap();
    flush_pending_r(&pending_r, &ex, &journal);
    let left: Vec<u64> = pending_r.lock_ok().parked.iter().map(|p| p.off).collect();
    // Only the final article may stay parked (it carries the
    // end-of-archive block, which never lands in an output file).
    assert!(
        left.iter().all(|&o| o as usize + art >= vol.len()),
        "payload articles still parked at offsets {left:?}"
    );
    // The records restore on a resume: reopen the journal cold and
    // rebuild - every journaled article's fragments must read back.
    drop(journal);
    drop(ex);
    let (_j2, resume) = nzbkit::journal::Journal::open(&dir, b"nzb-held").unwrap();
    let restored = nzbkit::journal::restore(&dir, &resume, None);
    for i in 1..n - 1 {
        assert!(
            restored.ids.contains(&format!("<er-{i}@t>")),
            "er-{i} journaled but did not restore"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 252 (23 Aug 2026): the OTHER way a parked article's bytes reach
/// disk. A demote raises `refeed_active` so its whole reconstruction
/// surfaces late placements - but the post-write re-route in
/// `Extractor::write` and the forward-delivery re-check land their bytes
/// with the flag DOWN and report nothing, and the read-back skips any
/// range whose pwrite has not landed yet, which is the window those two
/// exist to close. Joining on placements alone, such an article stayed
/// parked for the life of the job and the next run refetched it - ~8% of
/// runs of the e2e resume rig standalone on this box, ~40% under a
/// loaded suite, always exactly one article of the post.
///
/// The gap is reproduced by DISCARDING the placements the demote
/// surfaced, which is precisely what those routes leave behind and does
/// not depend on winning a race with a deferred pwrite. The property
/// pinned is that the volume's own coverage completes the records
/// anyway, and that they RESTORE - the claim being made is that these
/// bytes sit at their final offsets in the volume file, and a wrong one
/// hands the next run zeros out of a sparse hole.
#[test]
fn parked_articles_journal_off_a_materialized_volume_with_no_placements() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pending-mat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let inner: Vec<u8> = (0..600_000u32)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
        .collect();
    let half = inner.len() / 2;
    let vols: Vec<Vec<u8>> = (0..2)
        .map(|i| {
            let part = if i == 0 {
                &inner[..half]
            } else {
                &inner[half..]
            };
            nzbkit::rar::fixtures::rar5_volume_n(
                &[("movie.mkv", inner.len() as u64, part, i > 0, i == 0)],
                i as u64,
            )
        })
        .collect();
    let (journal, _) = nzbkit::journal::Journal::open(&dir, b"nzb-mat").unwrap();
    let ex = nzbkit::extract::Extractor::new(&dir, 2, true);
    let pending_r = std::sync::Mutex::new(PendingR::default());
    let art = 25_000usize;
    let n = vols[0].len().div_ceil(art);
    // Volume 1, every article but its first, in reverse: all park.
    for i in (1..n).rev() {
        let (s, e) = (i * art, ((i + 1) * art).min(vols[0].len()));
        match ex
            .write(
                0,
                "r.part1.rar",
                vols[0].len() as u64,
                s as u64,
                &vols[0][s..e],
            )
            .unwrap()
        {
            nzbkit::extract::Persist::Held(frags) => {
                pending_r.lock_ok().parked.push(ParkedR {
                    sidx: 0,
                    id: format!("<mat-{i}@t>").into(),
                    name: "r.part1.rar".into(),
                    size: vols[0].len() as u64,
                    off: s as u64,
                    len: (e - s) as u64,
                    frags,
                    par2_main: false,
                });
            }
            _ => panic!("article {i} arrived pre-sniff and must park as Held"),
        }
    }
    // Its offset-0 article maps the volume and drains the holds.
    ex.write(0, "r.part1.rar", vols[0].len() as u64, 0, &vols[0][..art])
        .unwrap();
    // Volume 2 never gets ITS header article, so nothing of it can be
    // placed and the whole group demotes to volumes on disk at finish -
    // the advG shape the e2e resume rig runs.
    for i in 1..vols[1].len().div_ceil(art) {
        let (s, e) = (i * art, ((i + 1) * art).min(vols[1].len()));
        ex.write(
            1,
            "r.part2.rar",
            vols[1].len() as u64,
            s as u64,
            &vols[1][s..e],
        )
        .unwrap();
    }
    ex.finish().unwrap();
    assert!(ex.slot_materialized(0), "volume 1 must materialize");
    // The reporting gap: every placement the reconstruction surfaced is
    // thrown away, exactly as the unreported write routes leave it.
    // Nothing but the volume file itself can vouch for these articles.
    ex.drain_late_placements();
    flush_pending_r(&pending_r, &ex, &journal);
    let left: Vec<u64> = pending_r.lock_ok().parked.iter().map(|p| p.off).collect();
    assert!(
        left.is_empty(),
        "articles still parked over a materialized volume at offsets {left:?}"
    );
    // Written is not restored: reopen the journal cold and rebuild.
    drop(journal);
    drop(ex);
    let (_j2, resume) = nzbkit::journal::Journal::open(&dir, b"nzb-mat").unwrap();
    let restored = nzbkit::journal::restore(&dir, &resume, None);
    for i in 1..n {
        assert!(
            restored.ids.contains(&format!("<mat-{i}@t>")),
            "mat-{i} journaled but did not restore"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
